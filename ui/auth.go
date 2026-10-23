package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tlsmask/proxy"
)

const cookieName = "tlsmask_auth_token"

func (h *handler) requireSignIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := h.srv.Auth
		if auth == nil {
			next(w, r)
			return
		}
		if !auth.Configured() {
			writeError(w, http.StatusUnauthorized, "tlsmask has not been set up yet")
			return
		}

		cookie, err := r.Cookie(cookieName)
		if err != nil || !auth.ValidSession(cookie.Value) {
			writeError(w, http.StatusUnauthorized, "sign in to the web UI")
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "this request came from another origin")
				return
			}
			if !isJSONRequest(r) {
				writeError(w, http.StatusUnsupportedMediaType,
					"send application/json: this endpoint changes state and only answers the UI")
				return
			}
		}
		next(w, r)
	}
}

func isJSONRequest(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json")
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func (h *handler) authState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"configured":    true,
		"authenticated": true,
		"minPassword":   proxy.MinPasswordLen,
	}
	auth := h.srv.Auth
	if auth == nil {
		writeJSON(w, out)
		return
	}

	configured := auth.Configured()
	out["configured"] = configured
	out["authenticated"] = configured && h.signedIn(r)

	if !configured {
		needsToken := !proxy.IsLoopback(r.RemoteAddr)
		out["needsToken"] = needsToken
		user, _ := auth.ProxyCredentials()
		out["hasProxyCredentials"] = user != ""
		if needsToken && h.cfg.DataDir != "" {
			out["tokenPath"] = auth.TokenPath()
		}
		if h.cfg.DataDir == "" {
			out["memoryOnly"] = true
		}
	}
	writeJSON(w, out)
}

func (h *handler) signedIn(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	return err == nil && h.srv.Auth.ValidSession(cookie.Value)
}

func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if h.srv.Auth == nil {
		writeError(w, http.StatusConflict, "this build has no credential store")
		return
	}

	token, err := h.srv.Auth.Setup(body.Password, strings.TrimSpace(body.Token), proxy.IsLoopback(r.RemoteAddr))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	proxy.LogInfo("web UI: password set")
	setCookie(w, token)
	writeJSON(w, map[string]any{"ok": true})
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if h.srv.Auth == nil {
		writeJSON(w, map[string]any{"ok": true})
		return
	}

	token, err := h.srv.Auth.Login(body.Password, r.RemoteAddr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	setCookie(w, token)
	writeJSON(w, map[string]any{"ok": true})
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "this request came from another origin")
		return
	}
	if !isJSONRequest(r) {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}

	if h.srv.Auth != nil {
		if cookie, err := r.Cookie(cookieName); err == nil {
			h.srv.Auth.EndSession(cookie.Value)
		}
	}
	clearCookie(w)
	writeJSON(w, map[string]any{"ok": true})
}

func (h *handler) access(w http.ResponseWriter, r *http.Request) {
	auth := h.srv.Auth
	if auth == nil {
		writeError(w, http.StatusNotFound, "this build has no credential store")
		return
	}

	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if _, err := auth.RotateProxyPassword(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		proxy.LogWarn("proxy password regenerated from the web UI; clients on the old one now get 407")
	default:
		writeError(w, http.StatusMethodNotAllowed, "use GET to read the credentials or POST to regenerate the password")
		return
	}

	user, password := auth.ProxyCredentials()
	host, port, _ := net.SplitHostPort(h.srv.ClientAddr())
	writeJSON(w, map[string]any{
		"username": user,
		"password": password,
		"host":     host,
		"port":     port,
	})
}

func (h *handler) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if h.srv.Auth == nil {
		writeError(w, http.StatusNotFound, "this build has no credential store")
		return
	}

	if err := h.srv.Auth.ChangePassword(body.Current, body.Next); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	proxy.LogInfo("web UI: password changed, all sessions signed out")
	clearCookie(w)
	writeJSON(w, map[string]any{"ok": true})
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "this request came from another origin")
		return false
	}
	if !isJSONRequest(r) {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(proxy.SignInTTL / time.Second),
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
