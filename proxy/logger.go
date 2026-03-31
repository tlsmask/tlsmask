package proxy

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorWhite  = "\033[97m"
)

func logRequest(num int64, method string, rawURL string, statusCode int, bodySize int, duration time.Duration) {
	ts := time.Now().Format("15:04:05")
	host, path := splitURL(rawURL)
	display := truncateStr(host+path, 52)
	size := humanSize(bodySize)
	dur := formatDuration(duration)
	sc := statusToColor(statusCode)

	fmt.Fprintf(os.Stderr, "  %s%s%s  %s[#%03d]%s  %-6s %s%-52s%s  %s%d%s  %s%6s  %5s%s\n",
		colorGray, ts, colorReset,
		colorGray, num, colorReset,
		method,
		colorWhite, display, colorReset,
		sc, statusCode, colorReset,
		colorGray, size, dur, colorReset,
	)
}

func logError(num int64, context string, err error) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "  %s%s%s  %s[#%03d]%s  %s✗ %s: %v%s\n",
		colorGray, ts, colorReset,
		colorGray, num, colorReset,
		colorRed, context, err, colorReset,
	)
}

func logInfo(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", colorCyan, msg, colorReset)
}

func splitURL(rawURL string) (string, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}

	host := u.Host
	path := u.Path

	if u.RawQuery != "" {
		params := u.Query()
		if len(params) <= 2 {
			keys := make([]string, 0, len(params))
			for k := range params {
				keys = append(keys, k)
			}
			path += "?" + strings.Join(keys, "&")
		} else {
			path += fmt.Sprintf("?(%d params)", len(params))
		}
	}

	return host, path
}

func humanSize(bytes int) string {
	switch {
	case bytes < 0:
		return "  ?"
	case bytes < 1024:
		return fmt.Sprintf("%dB", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%.1fK", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%.1fM", float64(bytes)/(1024*1024))
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dμs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func statusToColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorYellow
	case code >= 400:
		return colorRed
	default:
		return colorReset
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
