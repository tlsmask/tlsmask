package proxy

import (
	gocontext "context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	breakerThreshold = 5

	DefaultProxyCooldown = 15 * time.Second
)

var ErrUpstreamCooling = errors.New("upstream proxy is failing to connect; cooling down")

type upstreamHealth struct {
	cooldown time.Duration

	mu    sync.Mutex
	state map[string]*proxyState
}

type proxyState struct {
	failures  int
	openUntil time.Time
}

func newUpstreamHealth(cooldown time.Duration) *upstreamHealth {
	return &upstreamHealth{cooldown: cooldown, state: make(map[string]*proxyState)}
}

func breakerKeys(proxyURL string) (hostKey, fullKey string) {
	fullKey = proxyURL

	host := proxyURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return "host:" + host, fullKey
}

func (h *upstreamHealth) allow(proxyURL string) bool {
	if h == nil || h.cooldown <= 0 || proxyURL == "" {
		return true
	}

	hostKey, fullKey := breakerKeys(proxyURL)

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, key := range [2]string{hostKey, fullKey} {
		st, ok := h.state[key]
		if !ok || st.openUntil.IsZero() {
			continue
		}
		if time.Now().Before(st.openUntil) {
			return false
		}
		st.openUntil = time.Now().Add(h.cooldown)
	}
	return true
}

func (h *upstreamHealth) record(proxyURL string, err error) {
	if h == nil || h.cooldown <= 0 || proxyURL == "" {
		return
	}

	hostKey, fullKey := breakerKeys(proxyURL)

	h.mu.Lock()
	defer h.mu.Unlock()

	dial, refused := isDialFailure(err), isProxyRefusal(err)

	if !dial && !refused {
		for _, key := range [2]string{hostKey, fullKey} {
			if st, ok := h.state[key]; ok {
				st.failures = 0
				st.openUntil = time.Time{}
			}
		}
		return
	}

	key, label := fullKey, maskProxyCredentials(proxyURL)
	if dial {
		key, label = hostKey, strings.TrimPrefix(hostKey, "host:")
	}

	st, ok := h.state[key]
	if !ok {
		st = &proxyState{}
		h.state[key] = st
	}

	st.failures++
	if st.failures >= breakerThreshold && st.openUntil.IsZero() {
		st.openUntil = time.Now().Add(h.cooldown)
		logInfo(fmt.Sprintf("%supstream %s failed %d times in a row, refusing it for %s%s",
			colorYellow, label, st.failures, h.cooldown, colorReset))
	}
}

func (h *upstreamHealth) tripped() int {
	if h == nil {
		return 0
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	n := 0
	for _, st := range h.state {
		if !st.openUntil.IsZero() && now.Before(st.openUntil) {
			n++
		}
	}
	return n
}

func isDialFailure(err error) bool {
	if err == nil {
		return false
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return strings.Contains(err.Error(), "dial tcp")
}

func isProxyRefusal(err error) bool {
	if err == nil {
		return false
	}

	s := err.Error()
	return strings.Contains(s, "Proxy responded with non 200 code") ||
		strings.Contains(s, "proxyconnect")
}

func isClientGone(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, gocontext.Canceled) ||
		strings.Contains(err.Error(), "client went away")
}
