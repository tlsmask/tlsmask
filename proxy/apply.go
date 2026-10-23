package proxy

import (
	"fmt"
	"strings"
	"sync"

	"tlsmask/fingerprint"

	tls_client "github.com/bogdanfinn/tls-client"
)

type view struct {
	settings Settings

	client  tls_client.HttpClient
	pool    *ProxyPool
	builder ClientBuilder
	plan    fingerprint.Plan

	ja3, ja4r string
	profile   string
}

func (v *view) randomizeConfig() fingerprint.Config {
	mode, err := fingerprint.ParseMode(v.settings.Randomize)
	if err != nil {
		mode = fingerprint.ModeAuto
	}
	return fingerprint.Config{Mode: mode, DisableGREASE: !v.settings.GREASE}
}

func (s *Server) current() *view {
	if v := s.cur.Load(); v != nil {
		return v
	}
	v := &view{settings: DefaultSettings()}
	s.cur.CompareAndSwap(nil, v)
	return s.cur.Load()
}

func (s *Server) Settings() Settings { return s.current().settings }

func (s *Server) Apply(next Settings) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	next.Normalize()
	if err := next.Validate(); err != nil {
		return err
	}

	wasTimeout, wasDial, wasVerify := fingerprint.ClientTimeout(), fingerprint.DialTimeout(), fingerprint.VerifyUpstream()
	fingerprint.SetClientTimeout(next.Timeout.Duration())
	fingerprint.SetDialTimeout(next.DialTimeout.Duration())
	fingerprint.SetVerifyUpstream(next.VerifyUpstream)
	applied := false
	defer func() {
		if !applied {
			fingerprint.SetClientTimeout(wasTimeout)
			fingerprint.SetDialTimeout(wasDial)
			fingerprint.SetVerifyUpstream(wasVerify)
		}
	}()

	v, err := buildView(next)
	if err != nil {
		return err
	}

	prev := s.cur.Load()
	setRawLog(next.LogRaw)

	if v.pool, err = buildPool(next.Proxies, v.builder); err != nil {
		return err
	}

	if s.Store != nil {
		if err := s.Store.Put(next); err != nil {
			return err
		}
	}

	s.cur.Store(v)
	applied = true

	if s.Sessions != nil {
		s.Sessions.Reconfigure(next.SessionTTL.Duration(), next.MaxSessions, next.SessionIdleConns.Duration())

		if prev != nil && identityChanged(prev.settings, next) {
			if n := s.Sessions.EndAll(); n > 0 {
				logInfo(fmt.Sprintf("configuration changed, released %d session(s) built on the previous one", n))
			}
		}
	}

	if prev == nil || prev.settings.ProxyCooldown != next.ProxyCooldown {
		s.health.Store(newUpstreamHealth(next.ProxyCooldown.Duration()))
	}

	s.fingerprintCache.Range(func(k, _ any) bool {
		s.fingerprintCache.Delete(k)
		return true
	})

	return nil
}

func identityChanged(a, b Settings) bool {
	return a.JA3 != b.JA3 ||
		a.JA4R != b.JA4R ||
		a.Preset != b.Preset ||
		a.Randomize != b.Randomize ||
		a.GREASE != b.GREASE ||
		strings.Join(a.Proxies, "\n") != strings.Join(b.Proxies, "\n")
}

func buildView(s Settings) (*view, error) {
	v := &view{settings: s, ja3: s.JA3, ja4r: s.JA4R}

	cfg := fingerprint.Config{DisableGREASE: !s.GREASE}
	mode, err := fingerprint.ParseMode(s.Randomize)
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode

	if s.JA3 != "" && s.JA4R != "" {
		v.plan = cfg.Plan(s.JA3)
		v.builder = func(proxyURL string) (tls_client.HttpClient, error) {
			c, _, buildErr := fingerprint.BuildClientFromRaw(s.JA3, s.JA4R, proxyURL, v.plan)
			return c, buildErr
		}

		client, profile, buildErr := fingerprint.BuildClientFromRaw(s.JA3, s.JA4R, "", v.plan)
		if buildErr != nil {
			return nil, buildErr
		}
		v.client, v.profile = client, profile
		return v, nil
	}

	name := s.Preset
	if name == "" {
		name = "okhttp4"
	}
	tmpl := fingerprint.Get(name)
	if tmpl == nil {
		return nil, fmt.Errorf("unknown preset %q; available: %s", name, strings.Join(fingerprint.Names(), ", "))
	}

	v.plan = cfg.Plan(tmpl.JA3String)
	v.ja3, v.profile = tmpl.JA3String, tmpl.Name
	v.builder = func(proxyURL string) (tls_client.HttpClient, error) {
		return fingerprint.BuildClient(tmpl, proxyURL, v.plan)
	}

	client, buildErr := fingerprint.BuildClient(tmpl, "", v.plan)
	if buildErr != nil {
		return nil, buildErr
	}
	v.client = client
	return v, nil
}

func buildPool(lines []string, build ClientBuilder) (*ProxyPool, error) {
	if len(lines) == 0 || build == nil {
		return nil, nil
	}

	entries := make([]ProxyEntry, 0, len(lines))
	for i, line := range lines {
		url, err := FormatProxyURL(line)
		if err != nil {
			return nil, fmt.Errorf("proxy line %d: %w", i+1, err)
		}
		client, err := build(url)
		if err != nil {
			return nil, fmt.Errorf("proxy line %d: build client: %w", i+1, err)
		}
		entries = append(entries, ProxyEntry{URL: url, Client: client})
	}
	return NewProxyPool(entries), nil
}

type applyGuard = sync.Mutex
