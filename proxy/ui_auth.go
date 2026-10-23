package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) requireSignIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			next(w, r)
			return
		}
		if !s.Auth.Configured() {
			writeUIError(w, http.StatusUnauthorized, "tlsmask has not been set up yet")
			return
		}

		cookie, err := r.Cookie(uiCookieName)
		if err != nil || !s.Auth.ValidSession(cookie.Value) {
			writeUIError(w, http.StatusUnauthorized, "sign in to the web UI")
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				writeUIError(w, http.StatusForbidden, "this request came from another origin")
				return
			}
			if !isJSONRequest(r) {
				writeUIError(w, http.StatusUnsupportedMediaType,
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

func (s *Server) uiAuthState(cfg UIConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{
			"configured":    true,
			"authenticated": true,
			"minPassword":   MinPasswordLen,
		}
		if s.Auth == nil {
			writeUIJSON(w, out)
			return
		}

		configured := s.Auth.Configured()
		out["configured"] = configured
		out["authenticated"] = configured && s.signedIn(r)

		if !configured {
			needsToken := !isLoopback(r.RemoteAddr)
			out["needsToken"] = needsToken
			user, _ := s.Auth.ProxyCredentials()
			out["hasProxyCredentials"] = user != ""
			if needsToken && cfg.DataDir != "" {
				out["tokenPath"] = filepath.Join(cfg.DataDir, setupTokenFile)
			}
			if cfg.DataDir == "" {
				out["memoryOnly"] = true
			}
		}
		writeUIJSON(w, out)
	}
}

func (s *Server) signedIn(r *http.Request) bool {
	cookie, err := r.Cookie(uiCookieName)
	return err == nil && s.Auth.ValidSession(cookie.Value)
}

func (s *Server) uiSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !readUIJSON(w, r, &body) {
		return
	}
	if s.Auth == nil {
		writeUIError(w, http.StatusConflict, "this build has no credential store")
		return
	}

	token, err := s.Auth.Setup(body.Password, strings.TrimSpace(body.Token), isLoopback(r.RemoteAddr))
	if err != nil {
		writeUIError(w, http.StatusForbidden, err.Error())
		return
	}

	logInfo("web UI: password set")
	setUICookie(w, token)
	writeUIJSON(w, map[string]any{"ok": true})
}

func (s *Server) uiLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !readUIJSON(w, r, &body) {
		return
	}
	if s.Auth == nil {
		writeUIJSON(w, map[string]any{"ok": true})
		return
	}

	token, err := s.Auth.Login(body.Password, r.RemoteAddr)
	if err != nil {
		writeUIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	setUICookie(w, token)
	writeUIJSON(w, map[string]any{"ok": true})
}

func (s *Server) uiLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeUIError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !sameOrigin(r) {
		writeUIError(w, http.StatusForbidden, "this request came from another origin")
		return
	}
	if !isJSONRequest(r) {
		writeUIError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}

	if s.Auth != nil {
		if cookie, err := r.Cookie(uiCookieName); err == nil {
			s.Auth.EndSession(cookie.Value)
		}
	}
	clearUICookie(w)
	writeUIJSON(w, map[string]any{"ok": true})
}

func (s *Server) uiAccess(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeUIError(w, http.StatusNotFound, "this build has no credential store")
		return
	}

	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if _, err := s.Auth.RotateProxyPassword(); err != nil {
			writeUIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		logWarn("proxy password regenerated from the web UI; clients on the old one now get 407")
	default:
		writeUIError(w, http.StatusMethodNotAllowed, "use GET to read the credentials or POST to regenerate the password")
		return
	}

	user, password := s.Auth.ProxyCredentials()
	host, port, _ := net.SplitHostPort(s.clientAddr())
	writeUIJSON(w, map[string]any{
		"username": user,
		"password": password,
		"host":     host,
		"port":     port,
	})
}

func (s *Server) uiChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeUIError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !readUIJSON(w, r, &body) {
		return
	}
	if s.Auth == nil {
		writeUIError(w, http.StatusNotFound, "this build has no credential store")
		return
	}

	if err := s.Auth.ChangePassword(body.Current, body.Next); err != nil {
		writeUIError(w, http.StatusForbidden, err.Error())
		return
	}

	logInfo("web UI: password changed, all sessions signed out")
	clearUICookie(w)
	writeUIJSON(w, map[string]any{"ok": true})
}

func readUIJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeUIError(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	if !sameOrigin(r) {
		writeUIError(w, http.StatusForbidden, "this request came from another origin")
		return false
	}
	if !isJSONRequest(r) {
		writeUIError(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(into); err != nil {
		writeUIError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func setUICookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(uiSessionTTL / time.Second),
	})
}

func clearUICookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
