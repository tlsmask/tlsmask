package tests

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"tlsmask/cert"
	"tlsmask/proxy"
	"tlsmask/ui"
)

type env struct {
	proxyAddr string
	uiURL     string
	cookie    *http.Cookie
	user      string
	password  string
	caPEM     []byte
	target    *httptest.Server
}

var suite *env

func TestMain(m *testing.M) {
	os.Exit(func() int {
		e, stop, err := start()
		if err != nil {
			fmt.Fprintln(os.Stderr, "starting tlsmask:", err)
			return 1
		}
		defer stop()
		suite = e
		return m.Run()
	}())
}

func start() (*env, func(), error) {
	dir, err := os.MkdirTemp("", "tlsmask-e2e-")
	if err != nil {
		return nil, nil, err
	}

	store, err := proxy.OpenSettings(dir)
	if err != nil {
		return nil, nil, err
	}
	ca, _, err := cert.LoadOrCreateCA(dir)
	if err != nil {
		return nil, nil, err
	}
	auth, err := proxy.OpenAuth(dir)
	if err != nil {
		return nil, nil, err
	}

	proxyAddr, uiAddr := freeAddr(), freeAddr()
	srv := &proxy.Server{
		Addr:           proxyAddr,
		CA:             ca,
		Store:          store,
		Auth:           auth,
		Sessions:       proxy.NewSessionStore(0, 0, 0),
		Records:        proxy.NewRecorder(0, 0),
		HealthInterval: -1,
	}

	settings := proxy.DefaultSettings()
	settings.VerifyUpstream = false
	settings.Verbose = false
	if err := srv.Apply(settings); err != nil {
		return nil, nil, err
	}
	proxy.SetRecording(true)

	go srv.ListenAndServe()
	stopUI, err := ui.Serve(srv, ui.Config{Addr: uiAddr, DataDir: dir, Version: "e2e"})
	if err != nil {
		return nil, nil, err
	}
	if err := waitFor(proxyAddr); err != nil {
		return nil, nil, err
	}

	target := httptest.NewUnstartedServer(http.HandlerFunc(echo))
	target.EnableHTTP2 = true
	target.StartTLS()

	e := &env{proxyAddr: proxyAddr, uiURL: "http://" + uiAddr, target: target}
	if err := e.setup(); err != nil {
		return nil, nil, err
	}

	stop := func() {
		target.Close()
		stopUI()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		os.RemoveAll(dir)
	}
	return e, stop, nil
}

func (e *env) setup() error {
	res, err := e.ui(http.MethodPost, "/api/setup", `{"password":"e2e-password-1"}`, false)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("setup answered %d", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "tlsmask_auth_token" {
			e.cookie = c
		}
	}
	if e.cookie == nil {
		return fmt.Errorf("setup set no session cookie")
	}

	var access struct{ Username, Password string }
	if err := e.uiJSON("/api/access", &access); err != nil {
		return err
	}
	e.user, e.password = access.Username, access.Password

	res, err = http.Get(e.uiURL + "/ca.crt")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	e.caPEM, err = io.ReadAll(res.Body)
	return err
}

func echo(w http.ResponseWriter, r *http.Request) {
	headers := map[string][]string{}
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = v
	}
	json.NewEncoder(w).Encode(map[string]any{"proto": r.Proto, "headers": headers})
}

type echoed struct {
	Proto   string              `json:"proto"`
	Headers map[string][]string `json:"headers"`
}

func (e *env) client(user, password string) *http.Client {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(e.caPEM)
	proxyURL := &url.URL{Scheme: "http", Host: e.proxyAddr}
	if user != "" || password != "" {
		proxyURL.User = url.UserPassword(user, password)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}

func (e *env) fetch(t *testing.T, c *http.Client, userAgent []string) echoed {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.target.URL+"/echo", nil)
	if userAgent != nil {
		req.Header["User-Agent"] = userAgent
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("request through tlsmask: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("request through tlsmask answered %d", res.StatusCode)
	}
	var got echoed
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode the target's answer: %v", err)
	}
	return got
}

func (e *env) connect(t *testing.T, proxyAuth string) (int, http.Header) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	host := strings.TrimPrefix(e.target.URL, "https://")
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", host, host)
	if proxyAuth != "" {
		fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", proxyAuth)
	}
	fmt.Fprint(conn, "\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the CONNECT answer: %v", err)
	}
	res.Body.Close()
	return res.StatusCode, res.Header
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func (e *env) ui(method, path, body string, signedIn bool) (*http.Response, error) {
	req, err := http.NewRequest(method, e.uiURL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if signedIn && e.cookie != nil {
		req.AddCookie(e.cookie)
	}
	return http.DefaultClient.Do(req)
}

func (e *env) uiJSON(path string, into any) error {
	res, err := e.ui(http.MethodGet, path, "", true)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", path, res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(into)
}

func freeAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitFor(addr string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("nothing listening on %s", addr)
}

func TestProxyAsksForCredentials(t *testing.T) {
	status, header := suite.connect(t, "")
	if status != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT without credentials got %d, want 407", status)
	}
	if got := header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic") {
		t.Errorf("Proxy-Authenticate = %q, want a Basic challenge", got)
	}
}

func TestProxyRefusesAWrongPassword(t *testing.T) {
	if status, _ := suite.connect(t, basic(suite.user, "not-the-password")); status != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT with a wrong password got %d, want 407", status)
	}
	if status, _ := suite.connect(t, basic(suite.user, suite.password)); status != http.StatusOK {
		t.Errorf("CONNECT with the right credentials got %d, want 200", status)
	}
}

func TestRequestReachesTheTargetAsSent(t *testing.T) {
	got := suite.fetch(t, suite.client(suite.user, suite.password), []string{"e2e-client/1.0"})

	if ua := got.Headers["user-agent"]; len(ua) != 1 || ua[0] != "e2e-client/1.0" {
		t.Errorf("the target saw User-Agent %q, want the client's own", ua)
	}
	if v, leaked := got.Headers["proxy-authorization"]; leaked {
		t.Errorf("the target received Proxy-Authorization %q", v)
	}
	if got.Proto != "HTTP/2.0" {
		t.Errorf("the upstream request went over %s; the default fingerprint offers h2", got.Proto)
	}
}

func TestNoUserAgentStaysNone(t *testing.T) {
	got := suite.fetch(t, suite.client(suite.user, suite.password), []string{""})
	if ua, sent := got.Headers["user-agent"]; sent {
		t.Errorf("the client sent no User-Agent, the target received %q", ua)
	}
}

func TestIPAddressTargetsVerify(t *testing.T) {
	if !strings.HasPrefix(suite.target.URL, "https://127.0.0.1:") {
		t.Skipf("the target is %s, not an IP address", suite.target.URL)
	}
	suite.fetch(t, suite.client(suite.user, suite.password), []string{"e2e-client/1.0"})
}

func TestSessionOnTheUsername(t *testing.T) {
	suite.fetch(t, suite.client(suite.user+"-session-e2e1", suite.password), []string{"e2e-client/1.0"})

	req, _ := http.NewRequest(http.MethodGet, "http://"+suite.proxyAddr+"/sessions", nil)
	req.SetBasicAuth(suite.user, suite.password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var listing struct {
		Sessions []struct{ ID string } `json:"sessions"`
	}
	if err := json.NewDecoder(res.Body).Decode(&listing); err != nil {
		t.Fatalf("decode /sessions: %v", err)
	}
	for _, s := range listing.Sessions {
		if s.ID == "e2e1" {
			return
		}
	}
	t.Errorf("session e2e1 is not among the live sessions: %+v", listing.Sessions)
}

func TestControlAPIWantsCredentials(t *testing.T) {
	res, err := http.Get("http://" + suite.proxyAddr + "/sessions")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("/sessions without credentials got %d (WWW-Authenticate %q), want 401 with a Basic challenge",
			res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
}

func TestWebUINeedsTheSession(t *testing.T) {
	res, err := suite.ui(http.MethodGet, "/api/config", "", false)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/config without a session got %d, want 401", res.StatusCode)
	}

	var cfg map[string]any
	if err := suite.uiJSON("/api/config", &cfg); err != nil {
		t.Errorf("/api/config with a session: %v", err)
	}
}

func TestWebUIRefusesOtherOrigins(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, suite.uiURL+"/api/settings", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(suite.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a settings change from another origin got %d, want 403", res.StatusCode)
	}
}

func TestRequestsAreRecorded(t *testing.T) {
	suite.fetch(t, suite.client(suite.user, suite.password), []string{"recorded/1.0"})

	var records []struct {
		Host string `json:"host"`
		Path string `json:"path"`
	}
	if err := suite.uiJSON("/api/requests?limit=50", &records); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(suite.target.URL, "https://")
	for _, r := range records {
		if strings.HasPrefix(r.Host, strings.Split(host, ":")[0]) && r.Path == "/echo" {
			return
		}
	}
	t.Errorf("the request is not in the recorded window: %+v", records)
}

func TestPlainAndTLSToTheSameHost(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(echo))
	defer plain.Close()
	secure := httptest.NewUnstartedServer(http.HandlerFunc(echo))
	secure.EnableHTTP2 = true
	secure.StartTLS()
	defer secure.Close()

	suite.setProxies(t, routingProxy(t, map[string]string{
		"site.test:80":  strings.TrimPrefix(plain.URL, "http://"),
		"site.test:443": strings.TrimPrefix(secure.URL, "https://"),
	}))

	for session, order := range map[string][]string{
		"mix1": {"http://site.test/echo", "https://site.test/echo"},
		"mix2": {"https://site.test/echo", "http://site.test/echo"},
	} {
		c := suite.client(suite.user+"-session-"+session, suite.password)
		for _, target := range order {
			res, err := c.Get(target)
			if err != nil {
				t.Errorf("%v: %s: %v", order, target, err)
				continue
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("%v: %s answered %d: %s", order, target, res.StatusCode, body)
			}
		}
		c.CloseIdleConnections()
	}
}

func (e *env) setProxies(t *testing.T, proxies ...string) {
	t.Helper()
	put := func(list []string) {
		body, _ := json.Marshal(map[string]any{"proxies": list})
		res, err := e.ui(http.MethodPut, "/api/settings", string(body), true)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("setting the upstream proxies got %d", res.StatusCode)
		}
	}
	put(proxies)
	t.Cleanup(func() { put([]string{}) })
}

func routingProxy(t *testing.T, routes map[string]string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go route(c, routes)
		}
	}()
	return ln.Addr().String()
}

func route(c net.Conn, routes map[string]string) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host := req.Host
	if req.Method != http.MethodConnect && req.URL.Port() == "" {
		host = net.JoinHostPort(req.URL.Hostname(), "80")
	}
	dst, ok := routes[host]
	if !ok {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", dst)
	if err != nil {
		return
	}
	defer up.Close()
	if req.Method == http.MethodConnect {
		fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else if err := req.Write(up); err != nil {
		return
	}
	go io.Copy(up, br)
	io.Copy(c, up)
}

func TestRegenerateCertificate(t *testing.T) {
	oldClient := suite.client(suite.user, suite.password)

	res, err := suite.ui(http.MethodPost, "/api/ca", `{}`, true)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("regenerate got %d", res.StatusCode)
	}

	oldClient.Transport.(*http.Transport).DisableKeepAlives = true
	if _, err := oldClient.Get(suite.target.URL + "/echo"); err == nil {
		t.Error("a client trusting the replaced CA was still accepted")
	}

	dl, err := http.Get(suite.uiURL + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	suite.caPEM, _ = io.ReadAll(dl.Body)
	dl.Body.Close()
	suite.fetch(t, suite.client(suite.user, suite.password), []string{"e2e-client/1.0"})
}
