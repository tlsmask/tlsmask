package ui

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"

	"tlsmask/fingerprint"
	"tlsmask/proxy"
)

const DefaultAddr = ":2256"

type Config struct {
	Addr string

	DataDir string

	Version string
}

type handler struct {
	srv *proxy.Server
	cfg Config
}

func Serve(srv *proxy.Server, cfg Config) (func(), error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for the UI: %w", cfg.Addr, err)
	}

	server := &http.Server{
		Handler:     newMux(srv, cfg),
		ReadTimeout: 15 * time.Second,
	}

	go server.Serve(ln)

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	link := "http://127.0.0.1:" + port
	srv.SetUIURL(link)

	switch host {
	case "127.0.0.1", "::1", "localhost":
		proxy.LogInfo("Web UI on " + link)
	default:
		proxy.LogInfo("Web UI on " + link + " (listening on all interfaces)")
		proxy.LogWarn("the UI is bound on every interface and speaks plain HTTP, so its password crosses " +
			"any network it is reachable from in clear. Publish it as 127.0.0.1:" + port + ":" + port +
			" in Docker (the shipped compose file does), or pass --ui-addr 127.0.0.1:" + port + " outside it")
	}

	return func() { server.Close() }, nil
}

var publicPaths = map[string]bool{
	"/":           true,
	"/ca.crt":     true,
	"/healthz":    true,
	"/api/auth":   true,
	"/api/setup":  true,
	"/api/login":  true,
	"/api/logout": true,
	"/app.css":    true,
	"/app.js":     true,
	"/logo.png":   true,
	"/mark.png":   true,
}

func newMux(srv *proxy.Server, cfg Config) *http.ServeMux {
	h := &handler{srv: srv, cfg: cfg}
	mux := http.NewServeMux()

	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/app.css", serveAsset("app.css"))
	mux.HandleFunc("/app.js", serveAsset("app.js"))
	mux.HandleFunc("/logo.png", serveAsset("logo.png"))
	mux.HandleFunc("/mark.png", serveAsset("mark.png"))
	mux.HandleFunc("/ca.crt", h.caCert)
	mux.HandleFunc("/api/auth", h.authState)
	mux.HandleFunc("/api/setup", h.setup)
	mux.HandleFunc("/api/login", h.login)
	mux.HandleFunc("/api/logout", h.logout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	signedIn := h.requireSignIn
	mux.HandleFunc("/api/config", signedIn(h.config))
	mux.HandleFunc("/api/settings", signedIn(h.settings))
	mux.HandleFunc("/api/fingerprint/hex", signedIn(h.fingerprintFromHex))
	mux.HandleFunc("/api/test", signedIn(h.selfTest))
	mux.HandleFunc("/api/stats", signedIn(h.stats))
	mux.HandleFunc("/api/requests", signedIn(h.requests))
	mux.HandleFunc("/api/stream", signedIn(h.stream))
	mux.HandleFunc("/api/sessions", signedIn(h.sessions))
	mux.HandleFunc("/api/access", signedIn(h.access))
	mux.HandleFunc("/api/ca", signedIn(h.regenerateCA))
	mux.HandleFunc("/api/password", signedIn(h.changePassword))

	return mux
}

func serveAsset(name string) http.HandlerFunc {
	asset, err := Load(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "ui not built in: "+name, http.StatusInternalServerError)
			return
		}
		asset.Serve(w, r)
	}
}

var indexPage = serveAsset("index.html")

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	indexPage(w, r)
}

func (h *handler) config(w http.ResponseWriter, r *http.Request) {
	s := h.srv
	cur := s.Settings()
	out := map[string]any{
		"listen":    s.Addr,
		"dataDir":   h.cfg.DataDir,
		"version":   h.cfg.Version,
		"bodyLimit": s.Records.BodyLimit(),
		"capacity":  proxy.DefaultRecordCapacity,
		"presets":   fingerprint.Names(),
		"modes":     fingerprint.ModeNames(),
	}
	if h.cfg.DataDir == "" {
		out["settingsPath"] = ""
	} else if s.Store != nil {
		out["settingsPath"] = s.Store.Path()
	}
	if s.Auth != nil {
		out["proxyUser"], out["proxyPassword"] = s.Auth.ProxyCredentials()
	}
	if ca := s.CurrentCA(); ca != nil {
		out["caFingerprint"] = ca.Fingerprint()
		out["caExpires"] = ca.NotAfter()
		out["caPath"] = h.cfg.DataDir
	}

	ja3, profile := s.ActiveFingerprint()
	if ja3 != "" {
		out["activeJA3"] = ja3
		if cur.GREASE {
			out["effectiveJA3"] = fingerprint.GreaseJA3(ja3)
		}
	}
	out["profile"] = profile
	out["randomize"] = cur.Randomize
	out["ja4r"] = cur.JA4R
	writeJSON(w, out)
}

func (h *handler) settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, h.srv.Settings())

	case http.MethodPut, http.MethodPost:
		next := h.srv.Settings()
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&next); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := h.srv.Apply(next); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		proxy.LogInfo("settings updated from the web UI")
		writeJSON(w, h.srv.Settings())

	default:
		writeError(w, http.StatusMethodNotAllowed, "use GET or PUT")
	}
}

func (h *handler) fingerprintFromHex(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hex string `json:"hex"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ja3, ja4r, err := fingerprint.ParseClientHelloHex(body.Hex)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ja3": ja3, "ja4r": ja4r})
}

const testTarget = "https://tls.peet.ws/api/all"

func (h *handler) selfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	_, port, err := net.SplitHostPort(h.srv.Addr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot work out the proxy port: "+err.Error())
		return
	}

	user, password := "", ""
	if h.srv.Auth != nil {
		user, password = h.srv.Auth.ProxyCredentials()
	}
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   "127.0.0.1:" + port,
		User:   url.UserPassword(user+proxy.SessionMarker+"selftest", password),
	}

	roots := x509.NewCertPool()
	if ca := h.srv.CurrentCA(); ca != nil && !roots.AppendCertsFromPEM(ca.CertPEM()) {
		writeError(w, http.StatusInternalServerError, "could not load the proxy CA")
		return
	}

	client := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}

	testReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, testTarget, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ua := r.UserAgent(); ua != "" {
		testReq.Header.Set("User-Agent", ua)
	} else {
		testReq.Header["User-Agent"] = []string{""}
	}

	started := time.Now()
	resp, err := client.Do(testReq)
	if err != nil {
		writeJSON(w, map[string]any{
			"ok":      false,
			"target":  testTarget,
			"error":   err.Error(),
			"millis":  time.Since(started).Milliseconds(),
			"through": "127.0.0.1:" + port,
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, "read response: "+err.Error())
		return
	}

	out := map[string]any{
		"ok":      resp.StatusCode == http.StatusOK,
		"status":  resp.StatusCode,
		"target":  testTarget,
		"millis":  time.Since(started).Milliseconds(),
		"through": "127.0.0.1:" + port,
	}

	var parsed any
	if json.Unmarshal(body, &parsed) == nil {
		out["report"] = parsed
	} else {
		out["raw"] = string(body)
	}
	writeJSON(w, out)
}

func (h *handler) stats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s := h.srv
	open, dialing, opened, failed := fingerprint.UpstreamStats()
	out := map[string]any{
		"goroutines":      runtime.NumGoroutine(),
		"requestsTotal":   s.RequestsTotal(),
		"openConnections": s.OpenConnections(),
		"heapMB":          float64(mem.HeapAlloc) / (1 << 20),
		"tunnelsOpen":     open,
		"tunnelsDialing":  dialing,
		"tunnelsOpened":   opened,
		"tunnelsFailed":   failed,
		"proxiesCooling":  s.ProxiesCooling(),
		"recordsDropped":  s.Records.Dropped(),
	}
	if s.Sessions != nil {
		out["sessions"] = s.Sessions.Len()
		out["sessionsMax"] = s.Sessions.Max()
		out["sessionsCreated"] = s.Sessions.Created()
	}
	writeJSON(w, out)
}

func (h *handler) requests(w http.ResponseWriter, r *http.Request) {
	if num := r.URL.Query().Get("num"); num != "" {
		id, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			http.Error(w, "bad num", http.StatusBadRequest)
			return
		}
		rec := h.srv.Records.Find(id)
		if rec == nil {
			http.Error(w, "no longer in the window", http.StatusNotFound)
			return
		}
		writeJSON(w, rec)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, h.srv.Records.Snapshot(limit))
}

func (h *handler) sessions(w http.ResponseWriter, r *http.Request) {
	if h.srv.Sessions == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, h.srv.Sessions.Snapshot())
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	records, release := h.srv.Records.Subscribe()
	defer release()

	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case rec, open := <-records:
			if !open {
				return
			}
			summary := *rec
			summary.RawRequest, summary.RawResponse = "", ""
			body, err := json.Marshal(&summary)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: request\ndata: %s\n\n", body)
			flusher.Flush()
		case <-beat.C:
			fmt.Fprint(w, ": beat\n\n")
			flusher.Flush()
		}
	}
}

func (h *handler) regenerateCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	ca, err := h.srv.ReplaceCA(h.cfg.DataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	proxy.LogWarn("CA regenerated from the web UI; clients must install the new certificate before they trust the proxy again")
	writeJSON(w, map[string]any{"caFingerprint": ca.Fingerprint(), "caExpires": ca.NotAfter()})
}

func (h *handler) caCert(w http.ResponseWriter, r *http.Request) {
	ca := h.srv.CurrentCA()
	if ca == nil {
		http.Error(w, "no CA", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="tlsmask-ca.crt"`)
	w.Write(ca.CertPEM())
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		return
	}
}
