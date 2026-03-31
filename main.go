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

func main() {
	port := flag.Int("port", 8080, "proxy listen port")
	fp := flag.String("fingerprint", "", "fingerprint template name (e.g. okhttp4)")
	upstream := flag.String("upstream", "", "upstream proxy URL (e.g. http://127.0.0.1:8888)")
	verbose := flag.Bool("verbose", false, "log response status codes")
	listFP := flag.Bool("list", false, "list available fingerprint templates and exit")
	ja3Flag := flag.String("ja3", "", "JA3 fullstring from Wireshark (e.g. 771,4865-4866-...,0-23-...,...,...)")
	ja4rFlag := flag.String("ja4r", "", "JA4_r (raw) string from Wireshark (e.g. t12d1209h2_..._..._0403,0804,...)")
	flag.Parse()

	if *listFP {
		fmt.Println("Available fingerprint templates:")
		for _, name := range fingerprint.Names() {
			tmpl := fingerprint.Get(name)
			fmt.Printf("  %-30s  JA3: %s\n", name, truncate(tmpl.JA3String, 60))
		}
		fmt.Println("\nOr use custom fingerprint from Wireshark:")
		fmt.Println("  --ja3 \"<JA3 fullstring>\" --ja4r \"<JA4_r string>\"")
		os.Exit(0)
	}

	var (
		client      tls_client.HttpClient
		displayName string
		ja3Display  string
		err         error
	)

	if *ja3Flag != "" && *ja4rFlag != "" {
		client, displayName, err = fingerprint.BuildClientFromRaw(*ja3Flag, *ja4rFlag, *upstream)
		if err != nil {
			log.Fatalf("failed to build client from JA3+JA4_r: %v", err)
		}
		ja3Display = *ja3Flag
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
		displayName = tmpl.Name
		ja3Display = tmpl.JA3String
	}

	ca, err := cert.NewCA()
	if err != nil {
		log.Fatalf("failed to create CA: %v", err)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	printBanner(addr, displayName, ja3Display, *upstream)

	srv := &proxy.Server{
		Addr:    addr,
		Client:  client,
		CA:      ca,
		Verbose: *verbose,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("proxy server error: %v", err)
	}
}

func printBanner(addr, fpName, ja3String, upstream string) {
	w := 62
	line := strings.Repeat("═", w)
	fmt.Printf("╔%s╗\n", line)
	fmt.Printf("║  %-*s║\n", w-2, "TLSMask — TLS Fingerprint Proxy")
	fmt.Printf("╠%s╣\n", line)
	fmt.Printf("║  %-*s║\n", w-2, fmt.Sprintf("Listen     : %s", addr))
	fmt.Printf("║  %-*s║\n", w-2, fmt.Sprintf("Fingerprint: %s", fpName))
	fmt.Printf("║  %-*s║\n", w-2, fmt.Sprintf("JA3        : %s", truncate(ja3String, 40)))
	if upstream != "" {
		fmt.Printf("║  %-*s║\n", w-2, fmt.Sprintf("Upstream   : %s", upstream))
	}
	fmt.Printf("║  %-*s║\n", w-2, "")
	fmt.Printf("║  %-*s║\n", w-2, "Set as upstream proxy in your tool:")
	fmt.Printf("║  %-*s║\n", w-2, fmt.Sprintf("  Host: 127.0.0.1  Port: %d", portFromAddr(addr)))
	fmt.Printf("╚%s╝\n\n", line)
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
