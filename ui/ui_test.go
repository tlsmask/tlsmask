package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEveryFileLoads(t *testing.T) {
	want := map[string]string{
		"index.html": "text/html",
		"app.css":    "text/css",
		"app.js":     "text/javascript",
		"logo.png":   "image/png",
		"mark.png":   "image/png",
	}
	for name, ctype := range want {
		a, err := Load(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(a.Body) == 0 || !strings.HasPrefix(a.ContentType, ctype) || a.ETag == "" {
			t.Errorf("%s: %d bytes, type %q, etag %q", name, len(a.Body), a.ContentType, a.ETag)
		}
	}
}

func TestThePageUsesItsFiles(t *testing.T) {
	page, err := Load("index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{`href="/app.css"`, `src="/app.js"`, `src="/logo.png"`, `href="/mark.png"`} {
		if !strings.Contains(string(page.Body), ref) {
			t.Errorf("index.html does not reference %s", ref)
		}
	}
}

func TestRevalidation(t *testing.T) {
	a, err := Load("app.js")
	if err != nil {
		t.Fatal(err)
	}

	fresh := httptest.NewRecorder()
	a.Serve(fresh, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if fresh.Code != http.StatusOK || fresh.Body.Len() != len(a.Body) {
		t.Fatalf("first load: %d, %d bytes", fresh.Code, fresh.Body.Len())
	}
	if got := fresh.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}

	same := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	same.Header.Set("If-None-Match", a.ETag)
	rec := httptest.NewRecorder()
	a.Serve(rec, same)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("revalidating the current file got %d with %d bytes, want 304", rec.Code, rec.Body.Len())
	}

	old := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	old.Header.Set("If-None-Match", `"0000000000000000"`)
	rec = httptest.NewRecorder()
	a.Serve(rec, old)
	if rec.Code != http.StatusOK {
		t.Errorf("revalidating an older file got %d, want 200", rec.Code)
	}
}
