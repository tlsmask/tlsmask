package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"

	"tlsmask/fingerprint"
)

func (s *Server) isSelfAddressed(req *http.Request) bool {
	if req.URL.Host == "" {
		return true
	}

	_, listenPort, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return false
	}

	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		return false
	}
	if port != listenPort {
		return false
	}

	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func (s *Server) handleControl(conn net.Conn, req *http.Request) {
	defer conn.Close()

	path := strings.TrimSuffix(req.URL.Path, "/")

	switch {
	case path == "/stats" && req.Method == http.MethodGet:
		s.writeStats(conn)

	case s.Sessions == nil:
		writeJSON(conn, http.StatusNotFound, map[string]any{"error": "sessions are disabled"})

	case path == "/sessions" && req.Method == http.MethodGet:
		sessions := s.Sessions.Snapshot()
		writeJSON(conn, http.StatusOK, map[string]any{
			"count":       len(sessions),
			"max":         s.Sessions.Max(),
			"ttl_seconds": s.Sessions.TTL().Seconds(),
			"sessions":    sessions,
		})

	case path == "/sessions" && req.Method == http.MethodDelete:
		n := s.Sessions.EndAll()
		LogInfo(fmt.Sprintf("ended all %d sessions", n))
		writeJSON(conn, http.StatusOK, map[string]any{"ended": n})

	case strings.HasPrefix(path, "/sessions/") && req.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/sessions/")
		ended := s.Sessions.End(id)
		if ended && s.current().settings.Verbose {
			LogInfo("ended session " + id)
		}
		writeJSON(conn, http.StatusOK, map[string]any{"id": id, "ended": ended})

	default:
		writeJSON(conn, http.StatusNotFound, map[string]any{
			"error": "unknown control endpoint",
			"endpoints": []string{
				"GET /stats",
				"GET /sessions",
				"DELETE /sessions",
				"DELETE /sessions/<id>",
			},
		})
	}
}

func (s *Server) writeStats(conn net.Conn) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := map[string]any{
		"goroutines":       runtime.NumGoroutine(),
		"requests_total":   s.requestNum.Load(),
		"heap_mb":          float64(mem.HeapAlloc) / (1 << 20),
		"open_connections": s.openConns.Load(),
		"proxies_cooling":  s.healthGauge().tripped(),
	}

	open, dialing, opened, failed := fingerprint.UpstreamStats()
	stats["upstream_tunnels_open"] = open
	stats["upstream_tunnels_dialing"] = dialing
	stats["upstream_tunnels_opened"] = opened
	stats["upstream_tunnels_failed"] = failed
	if s.Sessions != nil {
		created := s.Sessions.Created()
		stats["sessions"] = s.Sessions.Len()
		stats["sessions_max"] = s.Sessions.Max()
		stats["sessions_created"] = created

		if created > 0 {
			stats["requests_per_session"] = float64(s.requestNum.Load()) / float64(created)
		}
	}
	if pool := s.current().pool; pool != nil {
		stats["pool_size"] = pool.Len()
	}
	writeJSON(conn, http.StatusOK, stats)
}

func writeJSON(conn net.Conn, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"failed to encode response"}`)
		status = http.StatusInternalServerError
	}

	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status), len(body))
	conn.Write(body)
}
