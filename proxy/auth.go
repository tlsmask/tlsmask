package proxy

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SignInTTL = 12 * time.Hour

	MinPasswordLen = 8

	loginMaxFails = 8
	loginLockout  = 2 * time.Minute
)

type credentials struct {
	Password string `json:"password"`

	ProxyUser     string `json:"proxyUser"`
	ProxyPassword string `json:"proxyPassword"`

	LegacyKey string `json:"proxyKey,omitempty"`

	UpdatedAt time.Time `json:"updatedAt"`
}

func (c *credentials) upgrade() bool {
	changed := false
	if c.LegacyKey != "" {
		if c.ProxyPassword == "" {
			c.ProxyPassword = c.LegacyKey
		}
		c.LegacyKey = ""
		changed = true
	}
	if c.ProxyPassword != "" && c.ProxyUser == "" {
		c.ProxyUser = newProxyUser()
		changed = true
	}
	return changed
}

func newProxyUser() string     { return randomHex(6) }
func newProxyPassword() string { return randomHex(16) }

type AuthStore struct {
	path string

	mu       sync.RWMutex
	creds    credentials
	token    string
	sessions map[string]time.Time
	fails    map[string]*loginFails

	loaded    fileStamp
	checkedAt time.Time
}

type loginFails struct {
	count int
	until time.Time
}

var pbkdf2Iterations = 600_000

const (
	authFile       = "auth.json"
	setupTokenFile = "setup-token"
)

func OpenAuth(dir string) (*AuthStore, error) {
	a := &AuthStore{
		sessions: make(map[string]time.Time),
		fails:    make(map[string]*loginFails),
	}
	if dir != "" {
		a.path = filepath.Join(dir, authFile)
	}

	if a.path != "" {
		raw, err := os.ReadFile(a.path)
		switch {
		case err == nil:
			if err := json.Unmarshal(raw, &a.creds); err != nil {
				return nil, fmt.Errorf("parse %s: %w", a.path, err)
			}
			if info, statErr := os.Stat(a.path); statErr == nil {
				a.loaded = stampOf(info)
			}
			if a.creds.upgrade() {
				if err := a.saveLocked(); err != nil {
					return nil, err
				}
			}
		case !os.IsNotExist(err):
			return nil, fmt.Errorf("read %s: %w", a.path, err)
		}
	}

	if a.creds.Password == "" {
		a.token = a.readOrMintToken()
	}
	return a, nil
}

func ResetPassword(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("there is no data directory, so the password only ever lived in memory; restart tlsmask instead")
	}

	a := &AuthStore{path: filepath.Join(dir, authFile)}
	raw, err := os.ReadFile(a.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &a.creds); err != nil {
			return "", fmt.Errorf("parse %s: %w", a.path, err)
		}
		a.creds.upgrade()
	case !os.IsNotExist(err):
		return "", fmt.Errorf("read %s: %w", a.path, err)
	}

	os.Remove(filepath.Join(dir, setupTokenFile))
	token := a.readOrMintToken()

	a.creds.Password = ""
	a.creds.UpdatedAt = time.Now()
	if err := a.saveLocked(); err != nil {
		return "", err
	}
	return token, nil
}

func (a *AuthStore) readOrMintToken() string {
	if a.path == "" {
		return randomHex(8)
	}

	path := filepath.Join(filepath.Dir(a.path), setupTokenFile)
	if raw, err := os.ReadFile(path); err == nil {
		if token := strings.TrimSpace(string(raw)); token != "" {
			return token
		}
	}

	token := randomHex(8)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		os.WriteFile(path, []byte(token+"\n"), 0o600)
	}
	return token
}

func (a *AuthStore) clearSetupToken() {
	a.token = ""
	if a.path != "" {
		os.Remove(filepath.Join(filepath.Dir(a.path), setupTokenFile))
	}
}

func (a *AuthStore) syncLocked() {
	if a.path == "" {
		return
	}
	now := time.Now()
	if now.Sub(a.checkedAt) < time.Second {
		return
	}
	a.checkedAt = now

	var stamp fileStamp
	info, err := os.Stat(a.path)
	switch {
	case err == nil:
		stamp = stampOf(info)
	case !os.IsNotExist(err):
		return
	}
	if stamp == a.loaded {
		return
	}

	var next credentials
	if err == nil {
		raw, readErr := os.ReadFile(a.path)
		if readErr != nil || json.Unmarshal(raw, &next) != nil {
			return
		}
		next.upgrade()
	}
	a.loaded = stamp

	if next.Password != a.creds.Password {
		a.sessions = make(map[string]time.Time)
	}
	a.creds = next

	switch {
	case a.creds.Password == "" && a.token == "":
		a.token = a.readOrMintToken()
		LogWarn("web UI password was reset; set a new one in the UI with the setup token")
	case a.creds.Password != "":
		a.token = ""
	}
}

func (a *AuthStore) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.syncLocked()
	return a.creds.Password != ""
}

func (a *AuthStore) SetupToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.syncLocked()
	return a.token
}

func (a *AuthStore) Path() string { return a.path }

func (a *AuthStore) TokenPath() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.token == "" || a.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(a.path), setupTokenFile)
}

func (a *AuthStore) Setup(password, token string, fromLoopback bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.syncLocked()

	if a.creds.Password != "" {
		return "", fmt.Errorf("a password is already set, sign in instead")
	}
	if !fromLoopback {
		if token == "" {
			return "", fmt.Errorf("this request did not come from the machine running tlsmask, so it needs the setup token printed in the console")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
			return "", fmt.Errorf("that is not the setup token in the console")
		}
	}
	if err := checkPasswordLen(password); err != nil {
		return "", err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	prev := a.creds
	next := prev
	next.Password = hash
	next.UpdatedAt = time.Now()
	if next.ProxyUser == "" {
		next.ProxyUser = newProxyUser()
	}
	if next.ProxyPassword == "" {
		next.ProxyPassword = newProxyPassword()
	}
	a.creds = next
	if err := a.saveLocked(); err != nil {
		a.creds = prev
		return "", err
	}
	a.clearSetupToken()
	return a.newSessionLocked(), nil
}

func (a *AuthStore) Login(password, addr string) (string, error) {
	a.mu.Lock()
	a.syncLocked()
	if a.creds.Password == "" {
		a.mu.Unlock()
		return "", fmt.Errorf("no password is set yet")
	}
	ip := clientIP(addr)
	if f := a.fails[ip]; f != nil && time.Now().Before(f.until) {
		wait := time.Until(f.until).Round(time.Second)
		a.mu.Unlock()
		return "", fmt.Errorf("too many attempts, try again in %s", wait)
	}
	hash := a.creds.Password
	a.mu.Unlock()

	ok := verifyPassword(hash, password)

	a.mu.Lock()
	defer a.mu.Unlock()
	if !ok {
		a.recordFailLocked(ip)
		return "", fmt.Errorf("wrong password")
	}
	delete(a.fails, ip)
	return a.newSessionLocked(), nil
}

func (a *AuthStore) recordFailLocked(ip string) {
	f := a.fails[ip]
	if f == nil {
		f = &loginFails{}
		a.fails[ip] = f
	}
	f.count++
	if f.count >= loginMaxFails {
		f.count = 0
		f.until = time.Now().Add(loginLockout)
		LogWarn("web UI: locking out " + ip + " for " + loginLockout.String() + " after repeated failed logins")
	}
}

func (a *AuthStore) ChangePassword(current, next string) error {
	a.mu.RLock()
	hash := a.creds.Password
	a.mu.RUnlock()

	if !verifyPassword(hash, current) {
		return fmt.Errorf("the current password is wrong")
	}
	if err := checkPasswordLen(next); err != nil {
		return err
	}

	newHash, err := hashPassword(next)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.creds.Password
	a.creds.Password = newHash
	a.creds.UpdatedAt = time.Now()
	if err := a.saveLocked(); err != nil {
		a.creds.Password = prev
		return err
	}
	a.sessions = make(map[string]time.Time)
	return nil
}

func (a *AuthStore) ProxyCredentials() (user, password string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.creds.ProxyUser, a.creds.ProxyPassword
}

func (a *AuthStore) RotateProxyPassword() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	prev := a.creds.ProxyPassword
	a.creds.ProxyPassword = newProxyPassword()
	a.creds.UpdatedAt = time.Now()
	if err := a.saveLocked(); err != nil {
		a.creds.ProxyPassword = prev
		return "", err
	}
	return a.creds.ProxyPassword, nil
}

func (a *AuthStore) CheckProxyCredentials(user, password string) bool {
	a.mu.RLock()
	wantUser, wantPassword := a.creds.ProxyUser, a.creds.ProxyPassword
	a.mu.RUnlock()

	if wantUser == "" || wantPassword == "" {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser))
	passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(wantPassword))
	return userOK&passwordOK == 1
}

func (a *AuthStore) newSessionLocked() string {
	now := time.Now()
	for tok, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, tok)
		}
	}
	tok := randomHex(32)
	a.sessions[tok] = now.Add(SignInTTL)
	return tok
}

func (a *AuthStore) ValidSession(token string) bool {
	if token == "" {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.syncLocked()

	expiry, ok := a.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(a.sessions, token)
		return false
	}
	a.sessions[token] = time.Now().Add(SignInTTL)
	return true
}

func (a *AuthStore) EndSession(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

func (a *AuthStore) saveLocked() error {
	if a.path == "" {
		return nil
	}

	body, err := json.MarshalIndent(a.creds, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return fmt.Errorf("create the data directory: %w", err)
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return fmt.Errorf("replace credentials: %w", err)
	}

	if info, err := os.Stat(a.path); err == nil {
		a.loaded = stampOf(info)
	}
	return nil
}

type fileStamp struct {
	mod  int64
	size int64
}

func stampOf(info os.FileInfo) fileStamp {
	return fileStamp{mod: info.ModTime().UnixNano(), size: info.Size()}
}

func checkPasswordLen(password string) error {
	if len([]rune(password)) < MinPasswordLen {
		return fmt.Errorf("the password needs at least %d characters", MinPasswordLen)
	}
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	sum, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("tlsmask: no randomness available: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func clientIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func IsLoopback(addr string) bool {
	ip := net.ParseIP(clientIP(addr))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) checkProxyAuth(req *http.Request) (string, bool) {
	return s.checkCredentials(parseProxyAuth(req))
}

func (s *Server) checkControlAuth(req *http.Request) (string, bool) {
	auth := parseProxyAuth(req)
	if auth.user == "" && auth.password == "" {
		auth = parseBasicAuth(req.Header.Get("Authorization"))
	}
	return s.checkCredentials(auth)
}

func (s *Server) checkCredentials(auth proxyAuth) (string, bool) {
	if s.Auth == nil {
		return "", true
	}

	if user, _ := s.Auth.ProxyCredentials(); user == "" {
		return "tlsmask has not been set up yet. Open the web UI" + s.uiHint() +
			", set a password, and use the proxy credentials it generates", false
	}

	switch {
	case auth.user == "" && auth.password == "":
		return "proxy credentials required. Use http://<username>:<password>@" + s.ClientAddr() +
			"; they are under Access in the web UI" + s.uiHint(), false
	case !s.Auth.CheckProxyCredentials(auth.user, auth.password):
		return "wrong proxy username or password. Check Access in the web UI" + s.uiHint(), false
	}
	return "", true
}

func (s *Server) ClientAddr() string {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return s.Addr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func (s *Server) refuseUnauthorized(conn net.Conn, req *http.Request, reason string) {
	if s.logRefusal(conn.RemoteAddr().String()) {
		LogWarn("refused " + clientIP(conn.RemoteAddr().String()) + ": " + reason)
	}

	if req.Method != http.MethodConnect && s.isSelfAddressed(req) {
		body, _ := json.Marshal(map[string]any{"error": reason})
		const status = http.StatusUnauthorized
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nWWW-Authenticate: Basic realm=\"tlsmask\"\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			status, http.StatusText(status), len(body), body)
		return
	}

	const status = http.StatusProxyAuthRequired
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nProxy-Authenticate: Basic realm=\"tlsmask\"\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		status, http.StatusText(status), len(reason)+1, reason)
}

func (s *Server) logRefusal(addr string) bool {
	const quiet = 5 * time.Second

	ip := clientIP(addr)
	now := time.Now()

	if last, ok := s.refusals.Load(ip); ok {
		if now.Sub(last.(time.Time)) < quiet {
			return false
		}
	} else if s.refusalHosts.Add(1) > 2048 {
		s.refusals.Clear()
		s.refusalHosts.Store(1)
	}

	s.refusals.Store(ip, now)
	return true
}

func (s *Server) uiHint() string {
	if url := s.uiURL.Load(); url != nil && *url != "" {
		return " at " + *url
	}
	return ""
}
