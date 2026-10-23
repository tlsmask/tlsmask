package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tlsmask/cert"
	"tlsmask/proxy"
	"tlsmask/ui"
)

func main() {
	port := flag.Int("port", 2255, "proxy listen port")
	uiAddr := flag.String("ui-addr", envOr("TLSMASK_UI_ADDR", ""),
		"address for the web UI; it serves raw requests and the upstream proxy password, so bind it where only you can reach it (default one port above --port)")
	dataDir := flag.String("data-dir", envOr("TLSMASK_DATA_DIR", cert.DefaultDir()),
		"directory holding the CA and the settings; empty keeps both in memory, so nothing survives a restart")
	showVersion := flag.Bool("version", false, "print the version and exit")

	group("Listening", "port", "ui-addr")
	group("State", "data-dir")
	group("Other", "version")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("tlsmask %s\n", Version)
		return
	}

	switch cmd := flag.Arg(0); cmd {
	case "":
	case "reset-password":
		resetPassword(*dataDir, uiAddress(*uiAddr, *port))
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		flag.Usage()
		os.Exit(2)
	}

	store, err := proxy.OpenSettings(*dataDir)
	if err != nil {
		log.Fatalf("failed to read settings: %v", err)
	}

	ca, created, err := cert.LoadOrCreateCA(*dataDir)
	if err != nil {
		log.Fatalf("failed to prepare CA: %v", err)
	}

	auth, err := proxy.OpenAuth(*dataDir)
	if err != nil {
		log.Fatalf("failed to read credentials: %v", err)
	}

	srv := &proxy.Server{
		Addr:     fmt.Sprintf("0.0.0.0:%d", *port),
		CA:       ca,
		Store:    store,
		Auth:     auth,
		Sessions: proxy.NewSessionStore(0, 0, 0),
		Records:  proxy.NewRecorder(0, 0),
	}
	if err := srv.Apply(store.Get()); err != nil {
		log.Fatalf("the stored settings are not usable: %v\n  fix or delete %s", err, store.Path())
	}

	uiListen := uiAddress(*uiAddr, *port)
	printBanner(srv, *dataDir, uiListen)
	if created {
		logNewCA(cert.CertPath(*dataDir))
	}
	if !auth.Configured() {
		printFirstRun(auth, uiListen)
	}

	proxy.SetRecording(true)
	stopUI, uiErr := ui.Serve(srv, ui.Config{Addr: uiListen, DataDir: *dataDir, Version: Version})
	if uiErr != nil {
		log.Fatalf("failed to start the web UI: %v", uiErr)
	}
	defer stopUI()

	go watchForShutdown(srv, stopUI)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("proxy server error: %v", err)
	}
}

func uiAddress(configured string, port int) string {
	if configured != "" {
		return configured
	}
	return fmt.Sprintf(":%d", port+1)
}

func watchForShutdown(srv *proxy.Server, stopUI func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	sig := <-sigs

	const cyan, yellow, reset = "\033[36m", "\033[33m", "\033[0m"
	fmt.Fprintf(os.Stderr, "\n  %s%s: finishing in-flight requests%s\n", cyan, sig, reset)

	stopUI()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if left := srv.Shutdown(ctx); left > 0 {
		fmt.Fprintf(os.Stderr, "  %s! gave up on %d connection(s) still open%s\n", yellow, left, reset)
	}
	os.Exit(0)
}

func resetPassword(dataDir, uiAddr string) {
	const (
		dim   = "\033[90m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
		white = "\033[97m"
		reset = "\033[0m"
	)

	token, err := proxy.ResetPassword(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset-password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("  %s%sPassword cleared.%s The proxy username and password are unchanged,\n",
		bold, white, reset)
	fmt.Println("  so clients keep working.")
	fmt.Printf("  Set a new one at %shttp://127.0.0.1%s%s with this token:\n", cyan, portOf(uiAddr), reset)
	fmt.Println()
	fmt.Printf("  %-12s%s:%s %s\n", "Setup Token", dim, reset, token)
	fmt.Println()
}

func printFirstRun(auth *proxy.AuthStore, uiAddr string) {
	const (
		dim   = "\033[90m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
		white = "\033[97m"
		reset = "\033[0m"
	)

	fmt.Println()
	fmt.Printf("  %s%sFirst run%s: the proxy refuses every request until a password is set.\n",
		bold, white, reset)
	fmt.Printf("  Set one at %shttp://127.0.0.1%s%s. It also generates the proxy username\n",
		cyan, portOf(uiAddr), reset)
	fmt.Println("  and password clients use.")
	fmt.Println()
	fmt.Printf("  %-12s%s:%s %s\n", "Setup Token", dim, reset, auth.SetupToken())
	fmt.Printf("  %sThe page asks for it unless you open it on this machine.%s\n", dim, reset)
	if path := auth.TokenPath(); path != "" {
		fmt.Printf("  %sAlso written to %s%s\n", dim, path, reset)
	}
	fmt.Println()
}

func logNewCA(path string) {
	const cyan, reset = "\033[36m", "\033[0m"
	fmt.Fprintf(os.Stderr, "  %sGenerated a CA at %s. Install it from the UI so clients can verify instead of skipping it%s\n",
		cyan, path, reset)
}

func printBanner(srv *proxy.Server, dataDir, uiAddr string) {
	const (
		dim   = "\033[90m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
		white = "\033[97m"
		reset = "\033[0m"
	)

	s := srv.Settings()
	bar := dim + strings.Repeat("=", 58) + reset

	fmt.Println()
	fmt.Printf("  %s%sTLSMask%s %s%s - TLS behaviour emulation proxy%s\n", bold, white, reset, dim, Version, reset)
	fmt.Println("  " + bar)
	fmt.Println()

	row := func(label, value string) {
		fmt.Printf("  %-12s%s:%s %s\n", label, dim, reset, value)
	}

	row("Proxy", srv.Addr)
	row("Web UI", "http://127.0.0.1"+portOf(uiAddr))

	state := dataDir
	if state == "" {
		state = "in memory (settings and CA are lost on restart)"
	}
	row("State", state)

	profile := s.Preset
	if s.JA3 != "" {
		profile = "custom JA3 + JA4_r"
	}
	row("Fingerprint", profile)
	row("Randomize", s.Randomize)

	upstream := "none (requests exit from this host)"
	switch n := len(s.Proxies); {
	case n == 1:
		upstream = "1 proxy"
	case n > 1:
		upstream = fmt.Sprintf("%d proxies, round-robin", n)
	}
	row("Upstream", upstream)

	fmt.Println()
	fmt.Printf("  %sConfigure everything at %shttp://127.0.0.1%s%s\n", dim, cyan, portOf(uiAddr), reset)
	fmt.Println("  " + bar)
	fmt.Println()
}

func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ":" + addr
}
