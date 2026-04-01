package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"tlsmask/cert"
	"tlsmask/fingerprint"
	"tlsmask/proxy"

	tls_client "github.com/bogdanfinn/tls-client"
)

type bannerInfo struct {
	addr       string
	upstream   string
	profile    string
	kind       string
	tlsVersion string
	alpn       string
	ciphers    int
	sigAlgs    int
	ja3        string
	ja4r       string
}

func main() {
	port := flag.Int("port", 2255, "proxy listen port")
	fp := flag.String("fingerprint", "", "fingerprint template name (e.g. okhttp4)")
	upstream := flag.String("upstream", "", "upstream proxy URL (e.g. http://127.0.0.1:8888)")
	verbose := flag.Bool("verbose", true, "log requests and response status codes")
	listFP := flag.Bool("list", false, "list available fingerprint templates and exit")
	ja3Flag := flag.String("ja3", "", "JA3 fullstring")
	ja4rFlag := flag.String("ja4r", "", "JA4_r raw string")
	hexFlag := flag.String("hex", "", "raw ClientHello hex stream (auto-extracts JA3+JA4_r)")
	flag.Parse()

	if *listFP {
		printTemplateList()
		os.Exit(0)
	}

	var (
		client tls_client.HttpClient
		info   bannerInfo
		err    error
	)

	info.addr = fmt.Sprintf("0.0.0.0:%d", *port)
	info.upstream = *upstream

	// --hex auto-extracts JA3 and JA4_r from raw ClientHello
	if *hexFlag != "" {
		parsedJA3, parsedJA4R, hexErr := fingerprint.ParseClientHelloHex(*hexFlag)
		if hexErr != nil {
			log.Fatalf("failed to parse ClientHello hex: %v", hexErr)
		}
		*ja3Flag = parsedJA3
		*ja4rFlag = parsedJA4R
		fmt.Printf("  \033[90mParsed from hex →\033[0m\n")
		fmt.Printf("  \033[90m  JA3 :\033[0m %s\n", parsedJA3)
		fmt.Printf("  \033[90m  JA4r:\033[0m %s\n\n", parsedJA4R)
	}

	if *ja3Flag != "" && *ja4rFlag != "" {
		var displayName string
		client, displayName, err = fingerprint.BuildClientFromRaw(*ja3Flag, *ja4rFlag, *upstream)
		if err != nil {
			log.Fatalf("failed to build client from JA3+JA4_r: %v", err)
		}

		ja4r, _ := fingerprint.ParseJA4R(*ja4rFlag)
		info.profile = displayName
		info.kind = "custom"
		info.ja3 = *ja3Flag
		info.ja4r = *ja4rFlag
		if ja4r != nil {
			info.tlsVersion = ja4r.SupportedVersions()[0]
			info.alpn = strings.Join(ja4r.ALPNProtocols(), ", ")
			info.sigAlgs = len(ja4r.SignatureAlgorithmsHex)
		}
		info.ciphers = countCiphers(*ja3Flag)
	} else if *ja3Flag != "" && *ja4rFlag == "" {
		fmt.Fprintln(os.Stderr, "error: --ja3 requires --ja4r")
		os.Exit(1)
	} else if *ja3Flag == "" && *ja4rFlag != "" {
		fmt.Fprintln(os.Stderr, "error: --ja4r requires --ja3")
		os.Exit(1)
	} else {
		templateName := *fp
		if templateName == "" {
			templateName = "okhttp4"
		}
		tmpl := fingerprint.Get(templateName)
		if tmpl == nil {
			fmt.Fprintf(os.Stderr, "error: unknown fingerprint template %q\n", templateName)
			fmt.Fprintf(os.Stderr, "available: %s\n", strings.Join(fingerprint.Names(), ", "))
			os.Exit(1)
		}
		client, err = fingerprint.BuildClient(tmpl, *upstream)
		if err != nil {
			log.Fatalf("failed to build TLS client: %v", err)
		}
		info.profile = tmpl.Name
		info.kind = "preset"
		info.ja3 = tmpl.JA3String
		info.tlsVersion = strings.Join(tmpl.SupportedVersions, ", ")
		info.alpn = strings.Join(tmpl.ALPNProtocols, ", ")
		info.ciphers = countCiphers(tmpl.JA3String)
		info.sigAlgs = len(tmpl.SupportedSignatureAlgorithms)
	}

	ca, err := cert.NewCA()
	if err != nil {
		log.Fatalf("failed to create CA: %v", err)
	}

	printBanner(info)

	srv := &proxy.Server{
		Addr:    info.addr,
		Client:  client,
		CA:      ca,
		Verbose: *verbose,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("proxy server error: %v", err)
	}
}

func printBanner(b bannerInfo) {
	const (
		dim   = "\033[90m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
		white = "\033[97m"
		reset = "\033[0m"
	)

	dbar := dim + strings.Repeat("═", 56) + reset
	sbar := dim + strings.Repeat("─", 56) + reset

	fmt.Println()
	fmt.Printf("  %s%sTLSMask%s %s— TLS Behavior Emulation Proxy%s\n", bold, white, reset, dim, reset)
	fmt.Println("  " + dbar)

	row := func(label, value string) {
		fmt.Printf("  %-12s%s:%s %s\n", label, dim, reset, value)
	}

	fmt.Println()
	row("Listen", b.addr)
	if b.upstream != "" {
		row("Upstream", b.upstream)
	}

	fmt.Println()
	fmt.Printf("  %s%sFingerprint%s\n", bold, white, reset)
	fmt.Println("  " + sbar)
	row("Profile", b.kind)
	if b.kind == "preset" {
		row("Name", fmt.Sprintf("%s%s%s", cyan, b.profile, reset))
	}
	row("TLS", b.tlsVersion)
	row("ALPN", b.alpn)
	row("Ciphers", fmt.Sprintf("%d", b.ciphers))
	row("SigAlgs", fmt.Sprintf("%d", b.sigAlgs))

	fmt.Println()
	fmt.Printf("  %s%sHash%s\n", bold, white, reset)
	fmt.Println("  " + sbar)
	wrapRow("JA3", b.ja3, 68)
	if b.ja4r != "" {
		wrapRow("JA4", b.ja4r, 68)
	}

	fmt.Println()
	fmt.Println("  " + dbar)
	fmt.Println()
}

func wrapRow(label, value string, maxLen int) {
	const (
		dim   = "\033[90m"
		reset = "\033[0m"
	)
	if len(value) <= maxLen {
		fmt.Printf("  %-12s%s:%s %s\n", label, dim, reset, value)
		return
	}
	fmt.Printf("  %-12s%s:%s %s\n", label, dim, reset, value[:maxLen])
	rest := value[maxLen:]
	for len(rest) > maxLen {
		fmt.Printf("  %14s%s\n", "", rest[:maxLen])
		rest = rest[maxLen:]
	}
	if len(rest) > 0 {
		fmt.Printf("  %14s%s\n", "", rest)
	}
}

func printTemplateList() {
	const (
		dim   = "\033[90m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
		reset = "\033[0m"
	)

	fmt.Printf("\n  %s%sAvailable fingerprint templates:%s\n\n", bold, cyan, reset)
	for _, name := range fingerprint.Names() {
		tmpl := fingerprint.Get(name)
		fmt.Printf("  %-24s %sJA3: %s%s\n", name, dim, trunc(tmpl.JA3String, 50), reset)
	}
	fmt.Printf("\n  %sOr use custom:%s --ja3 <value> --ja4r <value>\n\n", dim, reset)
}

func countCiphers(ja3String string) int {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 2 || parts[1] == "" {
		return 0
	}
	return len(strings.Split(parts[1], "-"))
}

func trunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
