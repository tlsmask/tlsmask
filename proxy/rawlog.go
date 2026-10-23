package proxy

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httputil"
	tls_client "github.com/bogdanfinn/tls-client"
)

func dumpUpstreamRequest(client tls_client.HttpClient, req *fhttp.Request, body []byte, pseudoOrder []string, proto string) (string, error) {
	clone := req.Clone(req.Context())

	if ua, set := clone.Header["User-Agent"]; set && (len(ua) == 0 || ua[0] == "") {
		clone.Header["User-Agent"] = []string{}
	}

	if client != nil && req.URL != nil {
		for _, c := range client.GetCookies(req.URL) {
			clone.AddCookie(c)
		}
	}

	if len(body) > 0 {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	} else {
		clone.Body = nil
	}

	raw, err := httputil.DumpRequestOut(clone, len(body) > 0)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(proto, "HTTP/2") {
		return string(raw), nil
	}
	return toH2View(string(raw), clone, pseudoOrder), nil
}

func toH2View(raw string, req *fhttp.Request, pseudoOrder []string) string {
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return raw
	}

	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	path := ""
	if req.URL != nil {
		path = req.URL.RequestURI()
	}
	scheme := ""
	if req.URL != nil {
		scheme = req.URL.Scheme
	}

	if len(pseudoOrder) == 0 {
		pseudoOrder = []string{":method", ":authority", ":scheme", ":path"}
	}

	var out []string
	for _, p := range pseudoOrder {
		switch p {
		case ":method":
			out = append(out, ":method: "+req.Method)
		case ":authority":
			out = append(out, ":authority: "+authority)
		case ":scheme":
			out = append(out, ":scheme: "+scheme)
		case ":path":
			out = append(out, ":path: "+path)
		}
	}

	skip := map[string]bool{
		"host": true, "connection": true, "proxy-connection": true,
		"transfer-encoding": true, "upgrade": true, "keep-alive": true,
	}

	named := make(map[string]bool)
	for _, n := range req.Header[fhttp.HeaderOrderKey] {
		named[strings.ToLower(n)] = true
	}

	var ordered, rest []string
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(name))
		if skip[lower] {
			continue
		}
		if named[lower] {
			ordered = append(ordered, lower+":"+value)
		} else {
			rest = append(rest, lower+":"+value)
		}
	}
	sort.Strings(rest)
	out = append(out, ordered...)
	out = append(out, rest...)

	if body != "" {
		return strings.Join(out, "\r\n") + "\r\n\r\n" + body
	}
	return strings.Join(out, "\r\n") + "\r\n"
}

func logRawRequest(num int64, proto, raw string) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s┌─ [#%03d] upstream request  (%s)%s\n", colorCyan, num, proto, colorReset)
	for _, line := range strings.Split(strings.TrimRight(raw, "\r\n"), "\n") {
		fmt.Fprintf(&b, "  %s│%s %s\n", colorGray, colorReset, strings.TrimRight(line, "\r"))
	}
	fmt.Fprintf(&b, "  %s└─%s\n", colorGray, colorReset)
	fmt.Fprint(os.Stderr, b.String())
}
