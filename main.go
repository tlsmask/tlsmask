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
	verbose := flag.Bool("verbose", false, "log response status codes")
	listFP := flag.Bool("list", false, "list available fingerprint templates and exit")
	ja3Flag := flag.String("ja3", "", "JA3 fullstring")
	ja4rFlag := flag.String("ja4r", "", "JA4_r raw string")
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
		dim    = "\033[90m"
		cyan   = "\033[36m"
		bold   = "\033[1m"
		white  = "\033[97m"
		reset  = "\033[0m"
		green  = "\033[32m"
	)

	w := 60
	bar := dim + strings.Repeat("─", w) + reset

	fmt.Println()
	fmt.Printf("  %s%sTLSMask%s %s— TLS Behavior Emulation Proxy%s\n", bold, white, reset, dim, reset)
	fmt.Println("  " + bar)
	fmt.Println()

	field := func(label, value string) {
		fmt.Printf("  %s%-14s%s%s\n", dim, label, reset, value)
	}

	field("Listen", b.addr)
	if b.upstream != "" {
		field("Upstream", b.upstream)
	}
	fmt.Println()

	field("Profile", fmt.Sprintf("%s%s%s %s(%s)%s", cyan, b.profile, reset, dim, b.kind, reset))
	field("TLS", b.tlsVersion)
	field("ALPN", b.alpn)
	field("Ciphers", fmt.Sprintf("%d", b.ciphers))
	field("Sig Algs", fmt.Sprintf("%d", b.sigAlgs))
	fmt.Println()

	if len(b.ja3) > 72 {
		field("JA3", b.ja3[:72])
		fmt.Printf("  %s%-14s%s%s\n", dim, "", reset, b.ja3[72:])
	} else {
		field("JA3", b.ja3)
	}

	if b.ja4r != "" {
		if len(b.ja4r) > 72 {
			field("JA4_r", b.ja4r[:72])
			fmt.Printf("  %s%-14s%s%s\n", dim, "", reset, b.ja4r[72:])
		} else {
			field("JA4_r", b.ja4r)
		}
	}

	fmt.Println()
	fmt.Println("  " + bar)
	fmt.Printf("  %sProxy listening on %s%s%s\n", dim, green, b.addr, reset)
	fmt.Printf("  %sUpstream config: %s127.0.0.1:%d%s\n", dim, reset, portFromAddr(b.addr), reset)
	fmt.Println()
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

func portFromAddr(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return 0
	}
	var p int
	fmt.Sscanf(parts[len(parts)-1], "%d", &p)
	return p
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
