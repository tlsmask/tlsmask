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
)

func logRequest(num int64, method string, rawURL string, statusCode int, bodySize int, duration time.Duration) {
	ts := time.Now().Format("15:04:05")
	displayURL := compactURL(rawURL, 60)
	size := humanSize(bodySize)
	dur := formatDuration(duration)
	statusColor := statusToColor(statusCode)

	fmt.Fprintf(os.Stderr, "%s %s#%-4d%s %-4s %-60s %s→ %d%s %s(%s, %s)%s\n",
		colorGray+ts+colorReset,
		colorBold, num, colorReset,
		method, displayURL,
		statusColor, statusCode, colorReset,
		colorGray, size, dur, colorReset,
	)
}

func logError(num int64, context string, err error) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "%s %s#%-4d%s %s✗ %s: %v%s\n",
		colorGray+ts+colorReset,
		colorBold, num, colorReset,
		colorRed, context, err, colorReset,
	)
}

func logInfo(msg string) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "%s %s%s%s\n",
		colorGray+ts+colorReset,
		colorCyan, msg, colorReset,
	)
}

func compactURL(rawURL string, maxLen int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return truncateStr(rawURL, maxLen)
	}

	display := u.Host + u.Path
	if u.RawQuery != "" {
		params := u.Query()
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		if len(keys) <= 3 {
			display += "?" + strings.Join(keys, "&")
		} else {
			display += fmt.Sprintf("?(%d params)", len(keys))
		}
	}

	return truncateStr(display, maxLen)
}

func humanSize(bytes int) string {
	switch {
	case bytes < 0:
		return "?"
	case bytes < 1024:
		return fmt.Sprintf("%d B", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
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
