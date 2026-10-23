package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tlsmask/cert"
	"tlsmask/fingerprint"

	tls_client "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/http2"
)

type ClientBuilder func(proxyURL string) (tls_client.HttpClient, error)

type fingerprintCacheKey struct{ ja3, ja4r string }

type Server struct {
	Addr string

	CA      *cert.CA
	swapped atomic.Pointer[cert.CA]

	cur     atomic.Pointer[view]
	applyMu applyGuard

	Store *SettingsStore

	Sessions *SessionStore

	Auth *AuthStore

	uiURL atomic.Pointer[string]

	refusals     sync.Map
	refusalHosts atomic.Int64

	health atomic.Pointer[upstreamHealth]

	Records *Recorder

	HealthInterval time.Duration
	outcomes       outcomeCounters

	requestNum atomic.Int64

	openConns atomic.Int64

	listener  atomic.Pointer[net.Listener]
	closeOnce sync.Once

	fingerprintCache sync.Map
}

func (s *Server) CurrentCA() *cert.CA {
	if ca := s.swapped.Load(); ca != nil {
		return ca
	}
	return s.CA
}

func (s *Server) SetUIURL(url string) {
	s.uiURL.Store(&url)
}

func (s *Server) ActiveFingerprint() (ja3, profile string) {
	v := s.current()
	return v.ja3, v.profile
}

func (s *Server) RequestsTotal() int64 {
	return s.requestNum.Load()
}

func (s *Server) OpenConnections() int64 {
	return s.openConns.Load()
}

func (s *Server) ProxiesCooling() int {
	return s.healthGauge().tripped()
}

func (s *Server) ReplaceCA(dataDir string) (*cert.CA, error) {
	ca, err := cert.RegenerateCA(dataDir)
	if err != nil {
		return nil, err
	}
	s.swapped.Store(ca)
	return ca, nil
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Addr, err)
	}
	defer ln.Close()
	s.listener.Store(&ln)

	LogInfo("Proxy listening on " + s.Addr)

	if s.Records == nil {
		s.Records = NewRecorder(0, 0)
	}
	if interval := s.HealthInterval; interval >= 0 {
		if interval == 0 {
			interval = 10 * time.Second
		}
		go s.reportHealth(interval)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Shutdown(ctx context.Context) int64 {
	s.closeOnce.Do(func() {
		if ln := s.listener.Load(); ln != nil {
			(*ln).Close()
		}
	})

	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		open := s.openConns.Load()
		if open == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return open
		case <-tick.C:
		}
	}

	if s.Sessions != nil {
		s.Sessions.Close()
	}
	return 0
}

type route struct {
	client   tls_client.HttpClient
	proxyURL string
	proxyIdx int

	session *Session
	fresh   bool

	conn string
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader

	pipelined int
	sniff     []byte
}

const sniffLimit = 4096

func (c *bufferedConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.sniff != nil && len(c.sniff) < sniffLimit {
		c.sniff = append(c.sniff, p[:min(n, sniffLimit-len(c.sniff))]...)
	}
	return n, err
}

func (c *bufferedConn) stopSniffing() { c.sniff = nil }

func (c *bufferedConn) describe() string {
	head := c.sniff
	if len(head) > 8 {
		head = head[:8]
	}
	return fmt.Sprintf("pipelined=%dB first-bytes=%x read=%dB\n  client-hello: %x",
		c.pipelined, head, len(c.sniff), c.sniff)
}

func (s *Server) relayVia(ctx context.Context, num int64, r route, req *http.Request, headerOrder []string) (*http.Response, error) {
	s.healthGauge()

	gauge := s.healthGauge()
	if !gauge.allow(r.proxyURL) {
		return nil, ErrUpstreamCooling
	}

	r.countRequest()

	var obs *exchange
	if Recording() {
		obs = &exchange{}
	}

	started := time.Now()
	resp, err := relay(ctx, num, r.client, req, headerOrder, obs)
	gauge.record(r.proxyURL, err)
	s.outcomes.record(err)
	s.record(num, started, req, r, resp, err, obs)
	return resp, err
}

func (s *Server) record(num int64, started time.Time, req *http.Request, r route, resp *http.Response, relayErr error, obs *exchange) {
	if s.Records == nil || obs == nil {
		return
	}

	outcome, errText := classify(relayErr)

	proto := obs.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}

	rec := &Record{
		Num: num, At: started, Millis: time.Since(started).Milliseconds(),
		Method: req.Method, Proto: proto,
		Outcome: outcome, Error: errText,
		Session: r.sessionID(), ProxyURL: r.proxyURL, ProxySlot: r.proxyIdx + 1, Conn: r.conn,
	}
	if req.URL != nil {
		rec.Host = req.URL.Host
		rec.Path = req.URL.RequestURI()
	}
	if resp != nil {
		rec.Status = resp.StatusCode
		rec.Bytes = resp.ContentLength
		rec.RawResponse = responseHead(resp, proto)
	}

	rec.RawRequest = obs.RawRequest
	rec.body = obs.Body

	s.Records.Add(rec)
}

func (r route) sessionID() string {
	if r.session == nil {
		return ""
	}
	return r.session.ID
}

func responseHead(resp *http.Response, proto string) string {
	var b strings.Builder
	h2 := strings.HasPrefix(proto, "HTTP/2")
	if h2 {
		fmt.Fprintf(&b, ":status: %d\r\n", resp.StatusCode)
	} else {
		fmt.Fprintf(&b, "%s %d %s\r\n", proto, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	for _, name := range sortedHeaderNames(resp.Header) {
		shown := name
		if h2 {
			shown = strings.ToLower(name)
		}
		for _, v := range resp.Header[name] {
			fmt.Fprintf(&b, "%s: %s\r\n", shown, v)
		}
	}
	return b.String()
}

func sortedHeaderNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r route) countRequest() {
	if r.session != nil {
		r.session.Requests.Add(1)
	}
}

func (s *Server) pickClient(req *http.Request) route {
	v := s.current()
	ja3 := req.Header.Get("X-TLS-JA3")
	ja4r := req.Header.Get("X-TLS-JA4R")

	if id := sessionID(req, parseProxyAuth(req)); id != "" && s.Sessions != nil {
		if r, ok := s.sessionRoute(id, ja3, ja4r); ok {
			return r
		}
	}

	if ja3 != "" && ja4r != "" {
		key := fingerprintCacheKey{ja3: ja3, ja4r: ja4r}
		if cached, ok := s.fingerprintCache.Load(key); ok {
			return route{client: cached.(tls_client.HttpClient), proxyIdx: -1}
		}

		c, _, err := fingerprint.BuildClientFromRaw(ja3, ja4r, "", v.randomizeConfig().Plan(ja3))
		if err != nil {
			log.Printf("failed to build dynamic fingerprint client: %v", err)
		} else {
			s.fingerprintCache.Store(key, c)
			return route{client: c, proxyIdx: -1}
		}
	}

	if v.pool != nil && v.pool.Len() > 0 {
		idx, url, c := v.pool.Next()
		return route{client: c, proxyURL: url, proxyIdx: idx}
	}

	return route{client: v.client, proxyIdx: -1}
}

func (s *Server) routeFor(conn route, req *http.Request) route {
	if s.Sessions == nil {
		return conn
	}
	id := strings.TrimSpace(req.Header.Get(SessionHeader))
	if id == "" || (conn.session != nil && conn.session.ID == id) {
		return conn
	}

	r, ok := s.sessionRoute(id, req.Header.Get("X-TLS-JA3"), req.Header.Get("X-TLS-JA4R"))
	if !ok {
		return conn
	}
	r.conn = conn.conn
	return r
}

func sessionID(req *http.Request, auth proxyAuth) string {
	if id := strings.TrimSpace(req.Header.Get(SessionHeader)); id != "" {
		return id
	}
	return auth.sessionID
}

func (s *Server) sessionRoute(id, ja3, ja4r string) (route, bool) {
	v := s.current()

	sess, fresh, err := s.Sessions.Get(id, func() (tls_client.HttpClient, string, int, error) {
		proxyURL, proxyIdx := "", -1
		if v.pool != nil && v.pool.Len() > 0 {
			proxyIdx, proxyURL, _ = v.pool.Next()
		}

		if ja3 != "" && ja4r != "" {
			c, _, buildErr := fingerprint.BuildClientFromRaw(ja3, ja4r, proxyURL, v.randomizeConfig().Plan(ja3))
			return c, proxyURL, proxyIdx, buildErr
		}
		if v.builder != nil {
			c, buildErr := v.builder(proxyURL)
			return c, proxyURL, proxyIdx, buildErr
		}
		if v.client == nil {
			return nil, "", -1, fmt.Errorf("no client builder configured")
		}
		return v.client, proxyURL, proxyIdx, nil
	})
	if err != nil {
		log.Printf("failed to open session %q: %v", id, err)
		return route{}, false
	}

	return route{
		client:   sess.Client,
		proxyURL: sess.ProxyURL,
		proxyIdx: sess.ProxyIdx,
		session:  sess,
		fresh:    fresh,
	}, true
}

func (s *Server) handleConn(conn net.Conn) {
	s.openConns.Add(1)
	defer s.openConns.Add(-1)

	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered: %v", r)
		}
		conn.Close()
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	conn = &bufferedConn{Conn: conn, r: br, pipelined: br.Buffered(), sniff: []byte{}}

	if req.Method != http.MethodConnect && s.isSelfAddressed(req) {
		if reason, ok := s.checkControlAuth(req); !ok {
			s.refuseUnauthorized(conn, req, reason)
			return
		}
		s.handleControl(conn, req)
		return
	}

	if reason, ok := s.checkProxyAuth(req); !ok {
		s.refuseUnauthorized(conn, req, reason)
		return
	}

	r := s.pickClient(req)

	if s.current().settings.RequireProxy && r.proxyURL == "" {
		host := req.Host
		if host == "" {
			host = req.URL.Host
		}
		LogInfo(fmt.Sprintf("\033[31mrefused %s: no upstream proxy, and Settings refuses direct requests\033[0m", host))
		if req.Method == http.MethodConnect {
			fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		} else {
			writeErrorResponse(conn, 502, "no upstream proxy bound for this request")
		}
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, req, r)
	} else {
		s.handlePlainHTTP(conn, req, r)
	}
}

func (s *Server) handleConnect(conn net.Conn, connectReq *http.Request, r route) {
	r.conn = connLabel(conn)

	hostname, port, err := net.SplitHostPort(connectReq.Host)
	if err != nil {
		hostname, port = strings.Trim(connectReq.Host, "[]"), "443"
	}

	authority := net.JoinHostPort(hostname, port)
	if port == "443" {
		authority = hostname
		if strings.Contains(hostname, ":") {
			authority = "[" + hostname + "]"
		}
	}

	s.logRoute(conn, hostname, r)

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tlsConfig := s.CurrentCA().TLSConfigForHost(hostname)
	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		if !isConnectionClosed(err) {
			detail := ""
			if bc, ok := conn.(*bufferedConn); ok {
				detail = " (" + bc.describe() + ")"
			}
			log.Printf("TLS handshake failed for %s: %v%s", hostname, err, detail)
		}
		return
	}

	if bc, ok := conn.(*bufferedConn); ok {
		bc.stopSniffing()
	}

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if negotiated == "h2" {
		if s.current().settings.Verbose {
			log.Printf("[h2] session started for %s%s", hostname, sessionSuffix(r))
		}
		s.serveH2(tlsConn, authority, r)
		return
	}

	if s.current().settings.Verbose {
		log.Printf("[h1] session started for %s%s", hostname, sessionSuffix(r))
	}
	s.serveH1(tlsConn, authority, r)
}

func (s *Server) logRoute(conn net.Conn, targetHost string, r route) {
	if !s.current().settings.Verbose {
		return
	}

	if r.session != nil {
		poolLen := 0
		if pool := s.current().pool; pool != nil {
			poolLen = pool.Len()
		}
		logSession(r.session.ID, targetHost, r.proxyURL, r.proxyIdx+1, poolLen, r.fresh)
		return
	}

	if r.proxyURL == "" {
		return
	}
	if pool := s.current().pool; pool != nil {
		logProxyAssigned(conn.RemoteAddr().String(), targetHost, r.proxyIdx+1, pool.Len(), r.proxyURL)
	}
}

func connLabel(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return "?"
	}
	s := addr.String()
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func sessionSuffix(r route) string {
	if r.session == nil {
		return ""
	}
	return " [session " + r.session.ID + "]"
}

func (s *Server) serveH1(tlsConn *tls.Conn, authority string, connRoute route) {
	tlsConn.SetReadDeadline(time.Time{})
	br := bufio.NewReader(tlsConn)

	connCtx, closeConn := context.WithCancel(context.Background())
	defer closeConn()

	for {
		tlsConn.SetReadDeadline(time.Now().Add(120 * time.Second))

		parsed, err := readOrderedRequest(br)
		if err != nil {
			if err != io.EOF && !isConnectionClosed(err) {
				log.Printf("read error: %v", err)
			}
			return
		}

		parsed.URL.Scheme = "https"
		parsed.URL.Host = authority
		parsed.RequestURI = ""

		r := s.routeFor(connRoute, parsed.Request)

		num := s.requestNum.Add(1)
		fullURL := parsed.URL.String()
		start := time.Now()

		ctx, cancel := context.WithCancel(connCtx)
		resp, err := s.relayVia(ctx, num, r, parsed.Request, parsed.HeaderOrder)
		if err != nil {
			cancel()
			logRelayError(num, r.conn, "relay", err)
			writeErrorResponse(tlsConn, 502, err.Error())
			continue
		}

		written, writeErr := writeHTTPResponse(tlsConn, resp)
		cancel()
		duration := time.Since(start)

		if s.current().settings.Verbose {
			if r.proxyURL != "" {
				logRequestWithProxy(num, parsed.Method, fullURL, resp.StatusCode, written, duration, r.proxyIdx+1, r.proxyURL)
			} else {
				logRequest(num, parsed.Method, fullURL, resp.StatusCode, written, duration)
			}
		}

		if writeErr != nil {
			logError(num, "write", writeErr)
			return
		}
	}
}

var h2ForbiddenRequestHeaders = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"te":                true,
}

var h2ForbiddenResponseHeaders = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"content-encoding":  true,
}

func (s *Server) serveH2(tlsConn *tls.Conn, authority string, connRoute route) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = authority
		r.RequestURI = ""

		for k := range r.Header {
			if h2ForbiddenRequestHeaders[strings.ToLower(k)] {
				delete(r.Header, k)
			}
		}

		rt := s.routeFor(connRoute, r)

		var reqBodyBytes []byte
		if r.Body != nil {
			reqBodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}

		num := s.requestNum.Add(1)
		fullURL := r.URL.String()
		start := time.Now()

		resp, err := s.relayVia(r.Context(), num, rt, r, stableHeaderOrder(r.Header))
		if err != nil {
			logRelayError(num, rt.conn, "relay h2", err)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "relay error: %v", err)
			return
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			logError(num, "read h2 resp body", readErr)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "read error: %v", readErr)
			return
		}

		for k, vals := range resp.Header {
			lk := strings.ToLower(k)
			if h2ForbiddenResponseHeaders[lk] || lk == "content-length" {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(body)

		duration := time.Since(start)
		written := int64(len(body))

		if s.current().settings.Verbose {
			if rt.proxyURL != "" {
				logRequestWithProxy(num, r.Method, fullURL, resp.StatusCode, written, duration, rt.proxyIdx+1, rt.proxyURL)
			} else {
				logRequest(num, r.Method, fullURL, resp.StatusCode, written, duration)
			}
		}
	})

	h2s := &http2.Server{
		IdleTimeout: 5 * time.Minute,
	}
	h2s.ServeConn(tlsConn, &http2.ServeConnOpts{
		BaseConfig: &http.Server{
			Handler:     handler,
			IdleTimeout: 5 * time.Minute,
			ReadTimeout: 10 * time.Minute,
		},
	})
}

func (s *Server) handlePlainHTTP(conn net.Conn, req *http.Request, r route) {
	defer conn.Close()

	reqHost := req.Host
	if reqHost == "" {
		reqHost = req.URL.Host
	}

	r.conn = connLabel(conn)
	s.logRoute(conn, reqHost, r)

	req.RequestURI = ""
	num := s.requestNum.Add(1)
	fullURL := req.URL.String()
	start := time.Now()

	resp, err := s.relayVia(req.Context(), num, r, req, stableHeaderOrder(req.Header))
	if err != nil {
		logError(num, "relay", err)
		writeErrorResponse(conn, 502, err.Error())
		return
	}

	written, writeErr := writeHTTPResponse(conn, resp)
	duration := time.Since(start)

	if s.current().settings.Verbose {
		if r.proxyURL != "" {
			logRequestWithProxy(num, req.Method, fullURL, resp.StatusCode, written, duration, r.proxyIdx+1, r.proxyURL)
		} else {
			logRequest(num, req.Method, fullURL, resp.StatusCode, written, duration)
		}
	}

	if writeErr != nil {
		logError(num, "write", writeErr)
	}
}

func writeHTTPResponse(w io.Writer, resp *http.Response) (int64, error) {
	defer resp.Body.Close()

	bw := bufio.NewWriterSize(w, 64*1024)

	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	skipHeaders := map[string]bool{
		"Transfer-Encoding": true, "Content-Encoding": true,
		"Content-Length": true, "Connection": true,
	}

	for key, vals := range resp.Header {
		if skipHeaders[key] {
			continue
		}
		for _, val := range vals {
			fmt.Fprintf(bw, "%s: %s\r\n", key, val)
		}
	}

	fmt.Fprintf(bw, "Transfer-Encoding: chunked\r\n")
	fmt.Fprintf(bw, "Connection: keep-alive\r\n")
	fmt.Fprintf(bw, "\r\n")
	bw.Flush()

	written, err := writeChunkedBody(w, resp.Body)
	return written, err
}

func writeChunkedBody(w io.Writer, body io.Reader) (int64, error) {
	bw := bufio.NewWriterSize(w, 64*1024)
	buf := make([]byte, 32*1024)
	var total int64

	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			fmt.Fprintf(bw, "%x\r\n", n)
			bw.Write(buf[:n])
			bw.WriteString("\r\n")
			bw.Flush()
			total += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			bw.WriteString("0\r\n\r\n")
			bw.Flush()
			return total, fmt.Errorf("read body: %w", readErr)
		}
	}

	bw.WriteString("0\r\n\r\n")
	bw.Flush()
	return total, nil
}

func writeErrorResponse(w io.Writer, status int, msg string) {
	body := fmt.Sprintf(`{"error":"%s"}`, msg)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

type parsedRequest struct {
	*http.Request
	HeaderOrder []string
}

func readOrderedRequest(br *bufio.Reader) (*parsedRequest, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(line, []byte("PRI * HTTP/2.0")) {
		return nil, fmt.Errorf("HTTP/2 binary framing not supported over this path")
	}

	line = bytes.Replace(line, []byte(" HTTP/2\r\n"), []byte(" HTTP/1.1\r\n"), 1)
	line = bytes.Replace(line, []byte(" HTTP/2.0\r\n"), []byte(" HTTP/1.1\r\n"), 1)
	line = bytes.Replace(line, []byte(" HTTP/2\n"), []byte(" HTTP/1.1\n"), 1)

	var headerLines []string
	var orderedKeys []string

	for {
		hline, herr := br.ReadBytes('\n')
		if herr != nil {
			return nil, herr
		}
		trimmed := strings.TrimRight(string(hline), "\r\n")
		if trimmed == "" {
			break
		}
		headerLines = append(headerLines, trimmed)

		if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
			lk := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
			if !hopByHopHeaders[lk] && lk != "host" && lk != "content-length" {
				orderedKeys = append(orderedKeys, lk)
			}
		}
	}

	var buf bytes.Buffer
	buf.Write(line)
	for _, h := range headerLines {
		buf.WriteString(h)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")

	combined := io.MultiReader(&buf, br)
	req, err := http.ReadRequest(bufio.NewReader(combined))
	if err != nil {
		return nil, err
	}

	return &parsedRequest{Request: req, HeaderOrder: orderedKeys}, nil
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "user canceled") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "malformed HTTP") ||
		strings.Contains(s, "An established connection was aborted") ||
		strings.Contains(s, "An existing connection was forcibly closed") ||
		strings.Contains(s, "wsarecv") ||
		strings.Contains(s, "wsasend")
}

func (s *Server) healthGauge() *upstreamHealth {
	if h := s.health.Load(); h != nil {
		return h
	}
	fresh := newUpstreamHealth(s.current().settings.ProxyCooldown.Duration())
	if s.health.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return s.health.Load()
}
