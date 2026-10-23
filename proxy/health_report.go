package proxy

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"tlsmask/fingerprint"
)

type outcomeCounters struct {
	ok           atomic.Int64
	dialTimeout  atomic.Int64
	proxyRefused atomic.Int64
	clientGone   atomic.Int64
	other        atomic.Int64
}

func (c *outcomeCounters) record(err error) {
	switch {
	case err == nil:
		c.ok.Add(1)
	case isDialFailure(err):
		c.dialTimeout.Add(1)
	case isProxyRefusal(err):
		c.proxyRefused.Add(1)
	case strings.Contains(err.Error(), "client went away"):
		c.clientGone.Add(1)
	default:
		c.other.Add(1)
	}
}

func (c *outcomeCounters) drain() (ok, dial, refused, gone, other int64) {
	return c.ok.Swap(0), c.dialTimeout.Swap(0), c.proxyRefused.Swap(0),
		c.clientGone.Swap(0), c.other.Swap(0)
}

func (s *Server) reportHealth(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	degraded := false
	for range ticker.C {
		ok, dial, refused, gone, other := s.outcomes.drain()
		if ok+dial+refused+gone+other == 0 {
			continue
		}

		open, dialing, _, _ := fingerprint.UpstreamStats()

		var parts []string
		parts = append(parts, fmt.Sprintf("ok=%d", ok))
		if dial > 0 {
			parts = append(parts, fmt.Sprintf("%sproxy-unreachable=%d%s", colorRed, dial, colorReset))
		}
		if refused > 0 {
			parts = append(parts, fmt.Sprintf("%sproxy-refused=%d%s", colorRed, refused, colorReset))
		}
		if gone > 0 {
			parts = append(parts, fmt.Sprintf("%sclient-gave-up=%d%s", colorYellow, gone, colorReset))
		}
		if other > 0 {
			parts = append(parts, fmt.Sprintf("other=%d", other))
		}

		mark := ""
		bad := dial + refused
		switch {
		case !degraded && bad > ok:
			degraded, mark = true, "  "+colorRed+"<- upstream turned here"+colorReset
		case degraded && bad == 0 && ok > 0:
			degraded, mark = false, "  "+colorGreen+"<- recovered"+colorReset
		}

		fmt.Fprintf(os.Stderr, "  %s%s%s  %s[health]%s  %s%s  %stunnels open=%d dialing=%d%s%s\n",
			colorGray, time.Now().Format("15:04:05"), colorReset,
			colorCyan, colorReset,
			strings.Join(parts, " "),
			colorReset,
			colorGray, open, dialing, colorReset,
			mark,
		)
	}
}
