package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
	"tlsmask/cert"
)

type Server struct {
	Addr    string
	Client  tls_client.HttpClient
	CA      *cert.CA
	Verbose bool

	requestNum atomic.Int64
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Addr, err)
	}
	defer ln.Close()

	logInfo("Proxy listening on " + s.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
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

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, req)
	} else {
		s.handlePlainHTTP(conn, req)
	}
}

func (s *Server) handleConnect(conn net.Conn, connectReq *http.Request) {
	host := connectReq.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	hostname := strings.Split(host, ":")[0]

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tlsConfig := s.CA.TLSConfigForHost(hostname)
	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		if !isConnectionClosed(err) {
			log.Printf("TLS handshake failed for %s: %v", hostname, err)
		}
		return
	}

	tlsConn.SetReadDeadline(time.Time{})
	br := bufio.NewReader(tlsConn)

	for {
		tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))

		req, err := readRequestCompat(br)
		if err != nil {
			if err != io.EOF && !isConnectionClosed(err) {
				log.Printf("read error: %v", err)
			}
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = hostname
		req.RequestURI = ""

		num := s.requestNum.Add(1)
		fullURL := req.URL.String()
		start := time.Now()

		resp, err := relay(s.Client, req)
		if err != nil {
			logError(num, "relay", err)
			writeErrorResponse(tlsConn, 502, err.Error())
			return
		}

		written, writeErr := writeHTTPResponse(tlsConn, resp)
		duration := time.Since(start)

		if s.Verbose {
			logRequest(num, req.Method, fullURL, resp.StatusCode, written, duration)
		}

		if writeErr != nil {
			logError(num, "write", writeErr)
			return
		}
	}
}

func (s *Server) handlePlainHTTP(conn net.Conn, req *http.Request) {
	defer conn.Close()

	req.RequestURI = ""
	num := s.requestNum.Add(1)
	fullURL := req.URL.String()
	start := time.Now()

	resp, err := relay(s.Client, req)
	if err != nil {
		logError(num, "relay", err)
		writeErrorResponse(conn, 502, err.Error())
		return
	}

	written, writeErr := writeHTTPResponse(conn, resp)
	duration := time.Since(start)

	if s.Verbose {
		logRequest(num, req.Method, fullURL, resp.StatusCode, written, duration)
	}

	if writeErr != nil {
		logError(num, "write", writeErr)
	}
}

func writeHTTPResponse(w io.Writer, resp *http.Response) (int, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}

	bw := bufio.NewWriter(w)
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

	fmt.Fprintf(bw, "Content-Length: %d\r\n\r\n", len(body))
	bw.Write(body)

	return len(body), bw.Flush()
}

func writeErrorResponse(w io.Writer, status int, msg string) {
	body := fmt.Sprintf(`{"error":"%s"}`, msg)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

func readRequestCompat(br *bufio.Reader) (*http.Request, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(line, []byte("PRI * HTTP/2.0")) {
		return nil, fmt.Errorf("HTTP/2 binary framing not supported")
	}

	line = bytes.Replace(line, []byte(" HTTP/2\r\n"), []byte(" HTTP/1.1\r\n"), 1)
	line = bytes.Replace(line, []byte(" HTTP/2.0\r\n"), []byte(" HTTP/1.1\r\n"), 1)
	line = bytes.Replace(line, []byte(" HTTP/2\n"), []byte(" HTTP/1.1\n"), 1)

	combined := io.MultiReader(bytes.NewReader(line), br)
	return http.ReadRequest(bufio.NewReader(combined))
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
		strings.Contains(s, "malformed HTTP")
}
