package proxy

import (
	"fmt"
	"sync/atomic"

	tls_client "github.com/bogdanfinn/tls-client"
)

type ProxyEntry struct {
	URL    string
	Client tls_client.HttpClient
}

type ProxyPool struct {
	entries []ProxyEntry
	n       uint64
	counter atomic.Uint64
}

func NewProxyPool(entries []ProxyEntry) *ProxyPool {
	return &ProxyPool{
		entries: entries,
		n:       uint64(len(entries)),
	}
}

func (p *ProxyPool) Len() int {
	return len(p.entries)
}

func (p *ProxyPool) Next() (int, string, tls_client.HttpClient) {
	slot := (p.counter.Add(1) - 1) % p.n
	idx := int(slot)
	e := p.entries[idx]
	return idx, e.URL, e.Client
}

func FormatProxyURL(raw string) (string, error) {
	parts := splitMax(raw, ':', 4)
	switch len(parts) {
	case 2:
		return fmt.Sprintf("http://%s:%s", parts[0], parts[1]), nil
	case 4:
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1]), nil
	default:
		return "", fmt.Errorf("invalid proxy format %q, expected host:port or host:port:username:password", raw)
	}
}

func splitMax(s string, sep byte, n int) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s) && len(parts) < n-1; i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
