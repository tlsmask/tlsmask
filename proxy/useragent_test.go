package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"tlsmask/fingerprint"
)

type seenRequest struct {
	proto     string
	userAgent []string
}

func recordingServer() (http.HandlerFunc, func() seenRequest) {
	var mu sync.Mutex
	var last seenRequest
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = seenRequest{proto: r.Proto, userAgent: r.Header.Values("User-Agent")}
		mu.Unlock()
		io.WriteString(w, "ok")
	}
	return handler, func() seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func TestUserAgentIsTheClients(t *testing.T) {
	was := fingerprint.VerifyUpstream()
	fingerprint.SetVerifyUpstream(false)
	t.Cleanup(func() { fingerprint.SetVerifyUpstream(was) })

	h2Handler, h2Seen := recordingServer()
	h2 := httptest.NewUnstartedServer(h2Handler)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	t.Cleanup(h2.Close)

	h1Handler, h1Seen := recordingServer()
	h1 := httptest.NewServer(h1Handler)
	t.Cleanup(h1.Close)

	tmpl := fingerprint.Get("okhttp4")
	if tmpl == nil {
		t.Fatal("the okhttp4 preset is missing")
	}

	for _, target := range []struct {
		name      string
		url       string
		seen      func() seenRequest
		wantProto string
	}{
		{"HTTP/2", h2.URL, h2Seen, "HTTP/2.0"},
		{"HTTP/1.1", h1.URL, h1Seen, "HTTP/1.1"},
	} {
		for _, tc := range []struct {
			name string
			ua   []string
		}{
			{"no User-Agent", nil},
			{"the client's own", []string{"MyAgent/1.0 (tlsmask test)"}},
		} {
			t.Run(target.name+"/"+tc.name, func(t *testing.T) {
				client, err := fingerprint.BuildClient(tmpl, "", fingerprint.Plan{})
				if err != nil {
					t.Fatalf("BuildClient(): %v", err)
				}

				down := httptest.NewRequest(http.MethodGet, target.url+"/ua", nil)
				down.Header.Set("Accept", "*/*")
				if tc.ua != nil {
					down.Header["User-Agent"] = tc.ua
				}

				obs := &exchange{}
				resp, err := relay(context.Background(), 1, client, down, nil, obs)
				if err != nil {
					t.Fatalf("relay(): %v", err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				got := target.seen()
				if got.proto != target.wantProto {
					t.Fatalf("the request went over %s, want %s, so the case is not testing what it says",
						got.proto, target.wantProto)
				}
				if strings.Join(got.userAgent, "|") != strings.Join(tc.ua, "|") {
					t.Errorf("the target received User-Agent %q, want %q", got.userAgent, tc.ua)
				}

				hasLine := strings.Contains(strings.ToLower(obs.RawRequest), "user-agent:")
				if tc.ua == nil && hasLine {
					t.Errorf("the recorded request shows a User-Agent that was not sent:\n%s", obs.RawRequest)
				}
				if tc.ua != nil && !strings.Contains(obs.RawRequest, tc.ua[0]) {
					t.Errorf("the recorded request lost the client's User-Agent:\n%s", obs.RawRequest)
				}
			})
		}
	}
}
