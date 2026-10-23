package proxy

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
	"tlsmask/ui"
)

const DefaultUIAddr = ":2256"

type UIConfig struct {
	Addr string

	DataDir string

	Version string
}

func (s *Server) ServeUI(cfg UIConfig) (func(), error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultUIAddr
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for the UI: %w", cfg.Addr, err)
	}

	mux := s.uiHandler(cfg)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0,
	}

	go srv.Serve(ln)

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	url := "http://127.0.0.1:" + port
	s.uiURL.Store(&url)

	switch host {
	case "127.0.0.1", "::1", "localhost":
		logInfo("Web UI on " + url)
	default:
		logInfo("Web UI on " + url + " (listening on all interfaces)")
		logWarn("the UI is bound on every interface and speaks plain HTTP, so its password crosses " +
			"any network it is reachable from in clear. Publish it as 127.0.0.1:" + port + ":" + port +
			" in Docker (the shipped compose file does), or pass --ui-addr 127.0.0.1:" + port + " outside it")
	}

	return func() { srv.Close() }, nil
}

var uiPublicPaths = map[string]bool{
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

func (s *Server) uiHandler(cfg UIConfig) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.serveIndex)
	mux.HandleFunc("/app.css", serveAsset("app.css"))
	mux.HandleFunc("/app.js", serveAsset("app.js"))
	mux.HandleFunc("/logo.png", serveAsset("logo.png"))
	mux.HandleFunc("/mark.png", serveAsset("mark.png"))
	mux.HandleFunc("/ca.crt", s.uiCACert)
	mux.HandleFunc("/api/auth", s.uiAuthState(cfg))
	mux.HandleFunc("/api/setup", s.uiSetup)
	mux.HandleFunc("/api/login", s.uiLogin)
	mux.HandleFunc("/api/logout", s.uiLogout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	signedIn := s.requireSignIn
	mux.HandleFunc("/api/config", signedIn(s.uiConfig(cfg)))
	mux.HandleFunc("/api/settings", signedIn(s.uiSettings))
	mux.HandleFunc("/api/fingerprint/hex", signedIn(s.uiFingerprintFromHex))
	mux.HandleFunc("/api/test", signedIn(s.uiSelfTest))
	mux.HandleFunc("/api/stats", signedIn(s.uiStats))
	mux.HandleFunc("/api/requests", signedIn(s.uiRequests))
	mux.HandleFunc("/api/stream", signedIn(s.uiStream))
	mux.HandleFunc("/api/sessions", signedIn(s.uiSessions))
	mux.HandleFunc("/api/access", signedIn(s.uiAccess))
	mux.HandleFunc("/api/ca", signedIn(s.uiRegenerateCA(cfg)))
	mux.HandleFunc("/api/password", signedIn(s.uiChangePassword))

	return mux
}

func serveAsset(name string) http.HandlerFunc {
	asset, err := ui.Load(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "ui not built in: "+name, http.StatusInternalServerError)
			return
		}
		asset.Serve(w, r)
	}
}

var serveIndexPage = serveAsset("index.html")

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	serveIndexPage(w, r)
}

func (s *Server) uiConfig(cfg UIConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cur := s.Settings()
		out := map[string]any{
			"listen":    s.Addr,
			"dataDir":   cfg.DataDir,
			"version":   cfg.Version,
			"bodyLimit": s.Records.BodyLimit(),
			"capacity":  DefaultRecordCapacity,
			"presets":   fingerprint.Names(),
			"modes":     fingerprint.ModeNames(),
		}
		if cfg.DataDir == "" {
			out["settingsPath"] = ""
		} else if s.Store != nil {
			out["settingsPath"] = s.Store.Path()
		}
		if s.Auth != nil {
			out["proxyUser"], out["proxyPassword"] = s.Auth.ProxyCredentials()
		}
		if ca := s.currentCA(); ca != nil {
			out["caFingerprint"] = ca.Fingerprint()
			out["caExpires"] = ca.NotAfter()
			out["caPath"] = cfg.DataDir
		}

		if ja3 := s.current().ja3; ja3 != "" {
			out["activeJA3"] = ja3
			if cur.GREASE {
				out["effectiveJA3"] = fingerprint.GreaseJA3(ja3)
			}
		}
		out["profile"] = s.current().profile
		out["randomize"] = cur.Randomize
		out["ja4r"] = cur.JA4R
		writeUIJSON(w, out)
	}
}

func (s *Server) uiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeUIJSON(w, s.Settings())

	case http.MethodPut, http.MethodPost:
		next := s.Settings()
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&next); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.Apply(next); err != nil {
			writeUIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		logInfo("settings updated from the web UI")
		writeUIJSON(w, s.Settings())

	default:
		writeUIError(w, http.StatusMethodNotAllowed, "use GET or PUT")
	}
}

func (s *Server) uiFingerprintFromHex(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hex string `json:"hex"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeUIError(w, http.StatusBadRequest, err.Error())
		return
	}

	ja3, ja4r, err := fingerprint.ParseClientHelloHex(body.Hex)
	if err != nil {
		writeUIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeUIJSON(w, map[string]string{"ja3": ja3, "ja4r": ja4r})
}

const testTarget = "https://tls.peet.ws/api/all"

func (s *Server) uiSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeUIError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	_, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		writeUIError(w, http.StatusInternalServerError, "cannot work out the proxy port: "+err.Error())
		return
	}

	user, password := "", ""
	if s.Auth != nil {
		user, password = s.Auth.ProxyCredentials()
	}
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   "127.0.0.1:" + port,
		User:   url.UserPassword(user+sessionMarker+"selftest", password),
	}

	roots := x509.NewCertPool()
	if ca := s.currentCA(); ca != nil && !roots.AppendCertsFromPEM(ca.CertPEM()) {
		writeUIError(w, http.StatusInternalServerError, "could not load the proxy CA")
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
		writeUIError(w, http.StatusInternalServerError, err.Error())
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
		writeUIJSON(w, map[string]any{
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
		writeUIError(w, http.StatusBadGateway, "read response: "+err.Error())
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
	writeUIJSON(w, out)
}

func writeUIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) uiStats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	open, dialing, opened, failed := fingerprint.UpstreamStats()
	out := map[string]any{
		"goroutines":      runtime.NumGoroutine(),
		"requestsTotal":   s.requestNum.Load(),
		"openConnections": s.openConns.Load(),
		"heapMB":          float64(mem.HeapAlloc) / (1 << 20),
		"tunnelsOpen":     open,
		"tunnelsDialing":  dialing,
		"tunnelsOpened":   opened,
		"tunnelsFailed":   failed,
		"proxiesCooling":  s.healthGauge().tripped(),
		"recordsDropped":  s.Records.Dropped(),
	}
	if s.Sessions != nil {
		out["sessions"] = s.Sessions.Len()
		out["sessionsMax"] = s.Sessions.Max()
		out["sessionsCreated"] = s.Sessions.Created()
	}
	writeUIJSON(w, out)
}

func (s *Server) uiRequests(w http.ResponseWriter, r *http.Request) {
	if num := r.URL.Query().Get("num"); num != "" {
		id, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			http.Error(w, "bad num", http.StatusBadRequest)
			return
		}
		rec := s.Records.Find(id)
		if rec == nil {
			http.Error(w, "no longer in the window", http.StatusNotFound)
			return
		}
		writeUIJSON(w, rec)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeUIJSON(w, s.Records.Snapshot(limit))
}

func (s *Server) uiSessions(w http.ResponseWriter, r *http.Request) {
	if s.Sessions == nil {
		writeUIJSON(w, []any{})
		return
	}
	writeUIJSON(w, s.Sessions.Snapshot())
}

func (s *Server) uiStream(w http.ResponseWriter, r *http.Request) {
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

	records, release := s.Records.Subscribe()
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

func (s *Server) uiRegenerateCA(cfg UIConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "use POST")
			return
		}
		ca, err := s.ReplaceCA(cfg.DataDir)
		if err != nil {
			writeUIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		logWarn("CA regenerated from the web UI; clients must install the new certificate before they trust the proxy again")
		writeUIJSON(w, map[string]any{"caFingerprint": ca.Fingerprint(), "caExpires": ca.NotAfter()})
	}
}

func (s *Server) uiCACert(w http.ResponseWriter, r *http.Request) {
	ca := s.currentCA()
	if ca == nil {
		http.Error(w, "no CA", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="tlsmask-ca.crt"`)
	w.Write(ca.CertPEM())
}

func writeUIJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		return
	}
}
