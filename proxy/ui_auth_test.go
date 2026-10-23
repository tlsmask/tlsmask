package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tlsmask/cert"
)

var uiRoutes = []string{
	"/",
	"/ca.crt",
	"/healthz",
	"/api/auth",
	"/api/setup",
	"/api/login",
	"/api/logout",
	"/app.css",
	"/app.js",
	"/logo.png",
	"/mark.png",
	"/api/config",
	"/api/settings",
	"/api/fingerprint/hex",
	"/api/test",
	"/api/stats",
	"/api/requests",
	"/api/stream",
	"/api/sessions",
	"/api/access",
	"/api/ca",
	"/api/password",
}

func TestUIRoutesNeedTheCookie(t *testing.T) {
	srv, _ := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	for _, path := range uiRoutes {
		if uiPublicPaths[path] {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method+" "+path, func(t *testing.T) {
				for _, cookie := range []string{"", "not-a-real-session"} {
					req := httptest.NewRequest(method, path, strings.NewReader("{}"))
					req.Header.Set("Content-Type", "application/json")
					if cookie != "" {
						req.AddCookie(&http.Cookie{Name: uiCookieName, Value: cookie})
					}

					rec := httptest.NewRecorder()
					mux.ServeHTTP(rec, req)
					if rec.Code != http.StatusUnauthorized {
						t.Errorf("cookie %q got %d, want 401", cookie, rec.Code)
					}
				}
			})
		}
	}
}

func TestEveryUIRouteIsListed(t *testing.T) {
	srv, _ := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	listed := make(map[string]bool, len(uiRoutes))
	for _, path := range uiRoutes {
		listed[path] = true
	}

	for _, probe := range []string{"/api/", "/api/x", "/debug", "/metrics", "/api/users"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, probe, nil))
		if rec.Code != http.StatusNotFound && !listed[probe] {
			t.Errorf("%s answered %d, so it is a route that uiRoutes does not list", probe, rec.Code)
		}
	}

	for _, path := range uiRoutes {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusNotFound && path != "/" {
			t.Errorf("%s is listed but not registered", path)
		}
	}
}

func TestSignedInBrowserGetsThrough(t *testing.T) {
	srv, token := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	req := httptest.NewRequest(http.MethodGet, "/api/access", nil)
	req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a signed-in browser got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	user, password := srv.Auth.ProxyCredentials()
	if body := rec.Body.String(); !strings.Contains(body, user) || !strings.Contains(body, password) {
		t.Error("the access panel did not return the proxy credentials")
	}
}

func TestMutationsRefuseAnotherOrigin(t *testing.T) {
	srv, token := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	for _, tc := range []struct {
		origin string
		want   int
	}{
		{origin: "http://localhost:3000", want: http.StatusForbidden},
		{origin: "http://127.0.0.1:2256", want: http.StatusUnprocessableEntity},
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"preset":""}`))
		req.Host = "127.0.0.1:2256"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", tc.origin)
		req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("Origin %s got %d, want %d: %s", tc.origin, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestFormPostIsRefused(t *testing.T) {
	srv, token := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	req := httptest.NewRequest(http.MethodPost, "/api/access", strings.NewReader("rotate=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form post got %d, want 415", rec.Code)
	}
}

func signedInServer(t *testing.T) (*Server, string) {
	t.Helper()
	cheapHashing(t)

	auth := newTestAuth(t)
	token, err := auth.Setup("hunter2hunter2", "", true)
	if err != nil {
		t.Fatalf("Setup(): %v", err)
	}

	ca, _, err := cert.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA(): %v", err)
	}

	srv := &Server{
		Addr:     "0.0.0.0:2255",
		CA:       ca,
		Auth:     auth,
		Store:    &SettingsStore{cur: DefaultSettings()},
		Records:  NewRecorder(0, 0),
		Sessions: NewSessionStore(0, 0, 0),
	}
	t.Cleanup(srv.Sessions.Close)

	if err := srv.Apply(DefaultSettings()); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	return srv, token
}

func TestSignOutEndsTheSession(t *testing.T) {
	srv, token := signedInServer(t)
	mux := srv.uiHandler(UIConfig{})

	call := func(method, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/logout", strings.NewReader("{}"))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(http.MethodGet, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/logout got %d, want 405", rec.Code)
	}
	if !srv.Auth.ValidSession(token) {
		t.Fatal("a refused sign-out ended the session anyway")
	}

	rec := call(http.MethodPost, "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-out got %d: %s", rec.Code, rec.Body.String())
	}
	if srv.Auth.ValidSession(token) {
		t.Error("the session survived signing out")
	}
	if c := rec.Result().Cookies(); len(c) == 0 || c[0].MaxAge >= 0 {
		t.Error("the response did not clear the cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})
	after := httptest.NewRecorder()
	mux.ServeHTTP(after, req)
	if after.Code != http.StatusUnauthorized {
		t.Errorf("after signing out, /api/config got %d, want 401", after.Code)
	}
}

func TestRegenerateCA(t *testing.T) {
	srv, token := signedInServer(t)
	dir := t.TempDir()
	if _, _, err := cert.LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	mux := srv.uiHandler(UIConfig{DataDir: dir})
	before := srv.currentCA().Fingerprint()

	req := httptest.NewRequest(http.MethodPost, "/api/ca", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: uiCookieName, Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("regenerate got %d: %s", rec.Code, rec.Body.String())
	}

	after := srv.currentCA().Fingerprint()
	if after == before {
		t.Fatal("the CA did not change")
	}

	dl := httptest.NewRecorder()
	mux.ServeHTTP(dl, httptest.NewRequest(http.MethodGet, "/ca.crt", nil))
	if !strings.Contains(dl.Body.String(), string(srv.currentCA().CertPEM())) {
		t.Error("/ca.crt still serves the old certificate")
	}

	reloaded, created, err := cert.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if created || reloaded.Fingerprint() != after {
		t.Errorf("a restart would load %s (created=%v), want the regenerated %s",
			reloaded.Fingerprint(), created, after)
	}
}
