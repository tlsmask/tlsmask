package proxy

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/bandwidth"
	"golang.org/x/net/proxy"
)

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func authRequest(user, pass string) *http.Request {
	req := &http.Request{Header: make(http.Header)}
	if user != "" || pass != "" {
		req.Header.Set("Proxy-Authorization", basic(user, pass))
	}
	return req
}

func TestParseProxyAuth(t *testing.T) {
	const user, password = "3fa2c71b9e04", "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name         string
		header       string
		wantUser     string
		wantPassword string
		wantSession  string
	}{
		{
			name: "no header at all",
		},
		{
			name:     "a proxy URL",
			header:   basic(user, password),
			wantUser: user, wantPassword: password,
		},
		{
			name:     "a session on the username",
			header:   basic(user+"-session-a1b2c3", password),
			wantUser: user, wantPassword: password, wantSession: "a1b2c3",
		},
		{
			name:     "the scheme is case-insensitive",
			header:   "basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
			wantUser: user, wantPassword: password,
		},
		{
			name:     "a colon in the password",
			header:   basic(user, "pa:ss"),
			wantUser: user, wantPassword: "pa:ss",
		},
		{
			name:   "a bare value is not a credential",
			header: password,
		},
		{
			name:   "undecodable credentials are nothing at all",
			header: "Basic not-base64!",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: make(http.Header)}
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}

			got := parseProxyAuth(req)
			if got.user != tc.wantUser || got.password != tc.wantPassword || got.sessionID != tc.wantSession {
				t.Errorf("parseProxyAuth() = {user:%q password:%q session:%q}, want {user:%q password:%q session:%q}",
					got.user, got.password, got.sessionID, tc.wantUser, tc.wantPassword, tc.wantSession)
			}
		})
	}
}

func TestSessionIDPrefersHeader(t *testing.T) {
	req := authRequest("from-auth", "")
	req.Header.Set(SessionHeader, "  from-header  ")

	auth := parseProxyAuth(req)
	if got := sessionID(req, auth); got != "from-header" {
		t.Errorf("sessionID() = %q, want %q", got, "from-header")
	}
}

func TestSessionStoreReusesAndIsolates(t *testing.T) {
	store := NewSessionStore(time.Minute, 10, 0)
	defer store.Close()

	var built int
	factory := func(proxyURL string, idx int) SessionFactory {
		return func() (tls_client.HttpClient, string, int, error) {
			built++
			return &fakeClient{}, proxyURL, idx, nil
		}
	}

	first, fresh, err := store.Get("run-1", factory("http://p1", 0))
	if err != nil || !fresh {
		t.Fatalf("first Get: fresh=%v err=%v", fresh, err)
	}

	again, fresh, err := store.Get("run-1", factory("http://p2", 1))
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if fresh {
		t.Error("second Get reported a fresh session for the same ID")
	}
	if again.Client != first.Client || again.ProxyURL != "http://p1" {
		t.Errorf("session %q did not keep its client and proxy: %+v", again.ID, again)
	}
	if built != 1 {
		t.Errorf("factory ran %d times for one session, want 1", built)
	}

	other, fresh, err := store.Get("run-2", factory("http://p2", 1))
	if err != nil || !fresh {
		t.Fatalf("Get for a new ID: fresh=%v err=%v", fresh, err)
	}
	if other.Client == first.Client {
		t.Error("two sessions share a client, so cookie jars are not isolated")
	}
	if other.ProxyURL != "http://p2" {
		t.Errorf("second session proxy = %q, want http://p2", other.ProxyURL)
	}
}

func TestSessionRouteProxySource(t *testing.T) {
	pool := NewProxyPool([]ProxyEntry{
		{URL: "http://pool-1", Client: &fakeClient{}},
		{URL: "http://pool-2", Client: &fakeClient{}},
	})

	srv := &Server{Sessions: NewSessionStore(time.Minute, 10, 0)}
	defer srv.Sessions.Close()

	srv.cur.Store(&view{
		settings: DefaultSettings(),
		pool:     pool,
		builder:  func(string) (tls_client.HttpClient, error) { return &fakeClient{}, nil },
	})

	first, ok := srv.sessionRoute("a", "", "")
	if !ok || first.proxyURL != "http://pool-1" || first.proxyIdx != 0 {
		t.Fatalf("first session route = %+v, want pool slot 0", first)
	}
	second, ok := srv.sessionRoute("b", "", "")
	if !ok || second.proxyURL != "http://pool-2" {
		t.Fatalf("second session route = %+v, want pool slot 1", second)
	}
	if again, _ := srv.sessionRoute("a", "", ""); again.proxyURL != "http://pool-1" {
		t.Errorf("session a moved to %q, want to keep http://pool-1", again.proxyURL)
	}

	if _, url, _ := pool.Next(); url != "http://pool-1" {
		t.Errorf("next pool slot = %q, want http://pool-1 (cursor advanced too far)", url)
	}
}

func TestSessionStoreExpiresIdle(t *testing.T) {
	store := NewSessionStore(30*time.Millisecond, 10, 0)
	defer store.Close()

	factory := func() (tls_client.HttpClient, string, int, error) {
		return &fakeClient{}, "http://p1", 0, nil
	}

	first, _, _ := store.Get("run-1", factory)

	deadline := time.Now().Add(3 * time.Second)
	for store.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if store.Len() != 0 {
		t.Fatalf("live sessions = %d, want the idle one to have expired", store.Len())
	}

	revived, fresh, _ := store.Get("run-1", factory)
	if !fresh {
		t.Error("expired session was reused instead of rebuilt")
	}
	if revived.Client == first.Client {
		t.Error("rebuilt session kept the expired client")
	}
}

func TestSessionStoreJanitorReapsUntouched(t *testing.T) {
	store := NewSessionStore(200*time.Millisecond, 10, 0)
	defer store.Close()

	store.Get("abandoned", func() (tls_client.HttpClient, string, int, error) {
		return &fakeClient{}, "http://p1", 0, nil
	})
	if store.Len() != 1 {
		t.Fatalf("live sessions = %d right after creation, want 1", store.Len())
	}

	deadline := time.Now().Add(3 * time.Second)
	for store.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}

	if store.Len() != 0 {
		t.Error("idle session survived the janitor without any call to End()")
	}
}

func TestSessionStoreTTLIsIdleNotAge(t *testing.T) {
	store := NewSessionStore(200*time.Millisecond, 10, 0)
	defer store.Close()

	factory := func() (tls_client.HttpClient, string, int, error) {
		return &fakeClient{}, "http://p1", 0, nil
	}

	first, _, _ := store.Get("busy", factory)

	for i := 0; i < 8; i++ {
		time.Sleep(50 * time.Millisecond)
		sess, fresh, err := store.Get("busy", factory)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if fresh || sess.Client != first.Client {
			t.Fatalf("iteration %d: session was rebuilt while still in use", i)
		}
	}
}

func TestSessionStoreReleasesIdleConnections(t *testing.T) {
	store := NewSessionStore(time.Minute, 10, 50*time.Millisecond)
	defer store.Close()

	client := &fakeClient{}
	factory := func() (tls_client.HttpClient, string, int, error) {
		return client, "http://p1", 0, nil
	}

	sess, _, err := store.Get("run-1", factory)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for client.closedIdle() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if client.closedIdle() == 0 {
		t.Fatal("idle connections were never released")
	}
	if store.Len() != 1 {
		t.Fatalf("live sessions = %d, want the session to survive its idle sockets", store.Len())
	}

	again, fresh, err := store.Get("run-1", factory)
	if err != nil || fresh {
		t.Fatalf("reuse after release: fresh=%v err=%v", fresh, err)
	}
	if again.Client != sess.Client || again.ProxyURL != "http://p1" {
		t.Errorf("session lost its client or proxy after the release: %+v", again)
	}

	before := client.closedIdle()
	deadline = time.Now().Add(3 * time.Second)
	for client.closedIdle() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if client.closedIdle() == before {
		t.Error("release did not re-arm after the session was used again")
	}
}

func TestSessionStoreKeepsConnectionsWhenDisabled(t *testing.T) {
	store := NewSessionStore(time.Minute, 10, 0)
	defer store.Close()

	client := &fakeClient{}
	store.Get("run-1", func() (tls_client.HttpClient, string, int, error) {
		return client, "http://p1", 0, nil
	})

	time.Sleep(1500 * time.Millisecond)
	if n := client.closedIdle(); n != 0 {
		t.Errorf("connections were released %d times with idleConns disabled", n)
	}
}

func TestSessionStoreEvictsLeastRecentlyUsed(t *testing.T) {
	store := NewSessionStore(time.Minute, 2, 0)
	defer store.Close()

	factory := func() (tls_client.HttpClient, string, int, error) {
		return &fakeClient{}, "http://p", 0, nil
	}

	store.Get("a", factory)
	time.Sleep(2 * time.Millisecond)
	store.Get("b", factory)
	time.Sleep(2 * time.Millisecond)

	store.Get("a", factory)
	time.Sleep(2 * time.Millisecond)
	store.Get("c", factory)

	if store.Len() != 2 {
		t.Fatalf("live sessions = %d, want 2", store.Len())
	}
	for _, info := range store.Snapshot() {
		if info.ID == "b" {
			t.Error("evicted the wrong session: b was not the least recently used")
		}
	}
}

func TestSessionStoreEnd(t *testing.T) {
	store := NewSessionStore(time.Minute, 10, 0)
	defer store.Close()

	factory := func() (tls_client.HttpClient, string, int, error) {
		return &fakeClient{}, "", -1, nil
	}

	store.Get("run-1", factory)

	if !store.End("run-1") {
		t.Error("End() reported the session was not present")
	}
	if store.End("run-1") {
		t.Error("End() reported success twice for one session")
	}
	if store.Len() != 0 {
		t.Errorf("live sessions = %d after End, want 0", store.Len())
	}
}

func TestSessionStoreConcurrentGetBuildsOnce(t *testing.T) {
	store := NewSessionStore(time.Minute, 10, 0)
	defer store.Close()

	var mu sync.Mutex
	built := 0
	factory := func() (tls_client.HttpClient, string, int, error) {
		mu.Lock()
		built++
		mu.Unlock()
		return &fakeClient{}, "http://p", 0, nil
	}

	var wg sync.WaitGroup
	clients := make([]tls_client.HttpClient, 16)
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess, _, err := store.Get("shared", factory)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			clients[i] = sess.Client
		}(i)
	}
	wg.Wait()

	if built != 1 {
		t.Errorf("factory ran %d times under concurrency, want 1", built)
	}
	for i, c := range clients {
		if c != clients[0] {
			t.Fatalf("goroutine %d got a different client than goroutine 0", i)
		}
	}
}

func TestIsSelfAddressed(t *testing.T) {
	srv := &Server{Addr: "0.0.0.0:2255"}

	tests := []struct {
		rawURL string
		want   bool
	}{
		{"/sessions", true},
		{"http://127.0.0.1:2255/sessions", true},
		{"http://localhost:2255/sessions/abc", true},
		{"http://127.0.0.1:9999/sessions", false},
		{"https://api.x.com/1.1/guest/activate", false},
	}

	for _, tc := range tests {
		t.Run(tc.rawURL, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			req := &http.Request{Method: http.MethodGet, URL: u, Header: make(http.Header)}
			if got := srv.isSelfAddressed(req); got != tc.want {
				t.Errorf("isSelfAddressed(%q) = %v, want %v", tc.rawURL, got, tc.want)
			}
		})
	}
}

type fakeClient struct {
	tls_client.HttpClient
	idleCloses atomic.Int64
}

func (c *fakeClient) CloseIdleConnections() { c.idleCloses.Add(1) }

func (c *fakeClient) closedIdle() int64 { return c.idleCloses.Load() }

func (c *fakeClient) GetCookies(*url.URL) []*fhttp.Cookie             { return nil }
func (c *fakeClient) GetBandwidthTracker() bandwidth.BandwidthTracker { return nil }
func (c *fakeClient) GetDialer() proxy.ContextDialer                  { return nil }
func (c *fakeClient) GetTLSDialer() tls_client.TLSDialerFunc          { return nil }
