package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"tlsmask/cert"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	ca, err := cert.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	srv := &Server{
		Addr:           "127.0.0.1:0",
		CA:             ca,
		HealthInterval: -1,
		Records:        NewRecorder(8, 1024),
	}

	ready := make(chan string, 1)
	go func() {
		ln, lnErr := net.Listen("tcp", srv.Addr)
		if lnErr != nil {
			ready <- ""
			return
		}
		srv.Addr = ln.Addr().String()
		ln.Close()
		ready <- srv.Addr
		srv.ListenAndServe()
	}()

	addr := <-ready
	if addr == "" {
		t.Fatal("could not reserve a port")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond); dialErr == nil {
			c.Close()
			return srv, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never started accepting")
	return nil, ""
}

func TestShutdownStopsAccepting(t *testing.T) {
	srv, addr := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if left := srv.Shutdown(ctx); left != 0 {
		t.Fatalf("Shutdown reported %d connections still open on an idle server", left)
	}

	if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		c.Close()
		t.Error("the listener still accepts connections after Shutdown")
	}
}

func TestShutdownWaitsForInFlight(t *testing.T) {
	srv, addr := newTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if want := "200"; !contains(line, want) {
		t.Fatalf("CONNECT answered %q, want it to contain %q", line, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if left := srv.Shutdown(ctx); left == 0 {
		t.Error("Shutdown reported a clean exit while a connection was still being served")
	}

	conn.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if left := srv.Shutdown(ctx2); left != 0 {
		t.Errorf("Shutdown still reports %d open after the client disconnected", left)
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	srv, _ := newTestServer(t)

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if left := srv.Shutdown(ctx); left != 0 {
			t.Errorf("call %d reported %d open", i+1, left)
		}
		cancel()
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
