package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tlsmask/fingerprint"
)

type Dur time.Duration

func (d Dur) Duration() time.Duration { return time.Duration(d) }
func (d Dur) String() string          { return time.Duration(d).String() }

func (d Dur) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Dur) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if numErr := json.Unmarshal(b, &n); numErr == nil {
			*d = Dur(time.Duration(n))
			return nil
		}
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%q is not a duration like 30s or 2m", s)
	}
	*d = Dur(parsed)
	return nil
}

type Settings struct {
	JA3       string `json:"ja3"`
	JA4R      string `json:"ja4r"`
	Preset    string `json:"preset"`
	Randomize string `json:"randomize"`
	GREASE    bool   `json:"grease"`

	Proxies       []string `json:"proxies"`
	RequireProxy  bool     `json:"requireProxy"`
	ProxyCooldown Dur      `json:"proxyCooldown"`

	VerifyUpstream bool `json:"verifyUpstream"`

	Timeout     Dur `json:"timeout"`
	DialTimeout Dur `json:"dialTimeout"`

	SessionTTL       Dur `json:"sessionTTL"`
	SessionIdleConns Dur `json:"sessionIdleConns"`
	MaxSessions      int `json:"maxSessions"`

	Verbose bool `json:"verbose"`
	LogRaw  bool `json:"logRaw"`
}

func DefaultSettings() Settings {
	return Settings{
		Preset:           "okhttp4",
		Randomize:        string(fingerprint.ModeAuto),
		GREASE:           true,
		Timeout:          Dur(30 * time.Second),
		DialTimeout:      Dur(10 * time.Second),
		SessionTTL:       Dur(DefaultSessionTTL),
		SessionIdleConns: Dur(DefaultSessionIdleConns),
		MaxSessions:      0,
		VerifyUpstream:   true,
		Verbose:          true,
	}
}

func (s *Settings) Normalize() {
	s.JA3 = strings.TrimSpace(s.JA3)
	s.JA4R = strings.TrimSpace(s.JA4R)
	s.Preset = strings.TrimSpace(s.Preset)
	s.Randomize = strings.ToLower(strings.TrimSpace(s.Randomize))
	if s.Randomize == "" {
		s.Randomize = string(fingerprint.ModeAuto)
	}

	cleaned := make([]string, 0, len(s.Proxies))
	for _, line := range s.Proxies {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			cleaned = append(cleaned, line)
		}
	}
	s.Proxies = cleaned
}

func (s Settings) Validate() error {
	var problems []string

	if _, err := fingerprint.ParseMode(s.Randomize); err != nil {
		problems = append(problems, err.Error())
	}

	switch {
	case s.JA3 != "" && s.JA4R == "":
		problems = append(problems, "a JA3 needs its JA4_r: the JA4_r carries the signature algorithms and ALPN the JA3 does not")
	case s.JA3 == "" && s.JA4R != "":
		problems = append(problems, "a JA4_r needs its JA3: the JA3 carries the cipher and extension order the JA4_r does not")
	case s.JA3 == "" && s.JA4R == "" && s.Preset == "":
		problems = append(problems, "set a JA3 and JA4_r pair, or choose a preset")
	}

	if s.JA3 != "" && s.JA4R != "" {
		if _, err := fingerprint.ParseJA4R(s.JA4R); err != nil {
			problems = append(problems, "JA4_r: "+err.Error())
		}
		if n := len(strings.Split(s.JA3, ",")); n != 5 {
			problems = append(problems, fmt.Sprintf("JA3 should have 5 comma-separated fields, got %d", n))
		}
	}
	if s.Preset != "" && s.JA3 == "" && fingerprint.Get(s.Preset) == nil {
		problems = append(problems, fmt.Sprintf("unknown preset %q; available: %s",
			s.Preset, strings.Join(fingerprint.Names(), ", ")))
	}

	for i, line := range s.Proxies {
		if _, err := FormatProxyURL(line); err != nil {
			problems = append(problems, fmt.Sprintf("proxy line %d: %v", i+1, err))
		}
	}

	for name, d := range map[string]Dur{
		"timeout": s.Timeout, "dialTimeout": s.DialTimeout,
		"sessionTTL": s.SessionTTL, "sessionIdleConns": s.SessionIdleConns,
		"proxyCooldown": s.ProxyCooldown,
	} {
		if d < 0 {
			problems = append(problems, name+" cannot be negative")
		}
	}
	if s.Timeout > 0 && s.DialTimeout > s.Timeout {
		problems = append(problems, "dialTimeout longer than timeout means a dead proxy consumes the whole request budget before failing")
	}
	if s.MaxSessions < 0 {
		problems = append(problems, "maxSessions cannot be negative (0 means no cap)")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

type SettingsStore struct {
	path string

	mu  sync.RWMutex
	cur Settings
}

const settingsFile = "settings.json"

func OpenSettings(dir string) (*SettingsStore, error) {
	st := &SettingsStore{cur: DefaultSettings()}
	if dir == "" {
		return st, nil
	}
	st.path = filepath.Join(dir, settingsFile)

	raw, err := os.ReadFile(st.path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", st.path, err)
	}

	loaded := DefaultSettings()
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, fmt.Errorf("parse %s: %w", st.path, err)
	}
	loaded.Normalize()
	st.cur = loaded
	return st, nil
}

func (st *SettingsStore) Path() string { return st.path }

func (st *SettingsStore) Get() Settings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cur
}

func (st *SettingsStore) Put(next Settings) error {
	next.Normalize()
	if err := next.Validate(); err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.path != "" {
		body, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return fmt.Errorf("encode settings: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
			return fmt.Errorf("create settings directory: %w", err)
		}
		tmp := st.path + ".tmp"
		if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
			return fmt.Errorf("write settings: %w", err)
		}
		if err := os.Rename(tmp, st.path); err != nil {
			return fmt.Errorf("replace settings: %w", err)
		}
	}

	st.cur = next
	return nil
}
