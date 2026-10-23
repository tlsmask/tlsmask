package proxy

import (
	"container/list"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

const (
	SessionHeader = "X-TLS-Session"

	DefaultSessionTTL = 10 * time.Minute

	DefaultMaxSessions = 0

	DefaultSessionIdleConns = 60 * time.Second
)

type Session struct {
	ID       string
	Client   tls_client.HttpClient
	ProxyURL string
	ProxyIdx int

	Created  time.Time
	Requests atomic.Int64

	lastUsed   time.Time
	idleClosed bool
	elem       *list.Element

	ready chan struct{}
	err   error
}

type SessionFactory func() (tls_client.HttpClient, string, int, error)

type SessionStore struct {
	ttl       time.Duration
	max       int
	idleConns time.Duration

	created atomic.Int64

	mu       sync.Mutex
	sessions map[string]*Session
	lru      *list.List

	stop     chan struct{}
	stopOnce sync.Once
}

func NewSessionStore(ttl time.Duration, max int, idleConns time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if max < 0 {
		max = 0
	}

	st := &SessionStore{
		ttl:       ttl,
		max:       max,
		idleConns: idleConns,
		sessions:  make(map[string]*Session),
		lru:       list.New(),
		stop:      make(chan struct{}),
	}
	go st.janitor()
	return st
}

func (st *SessionStore) Reconfigure(ttl time.Duration, max int, idleConns time.Duration) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.ttl = ttl
	st.max = max
	st.idleConns = idleConns

	st.trimLocked()
}

func (st *SessionStore) TTL() time.Duration {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.ttl
}

func (st *SessionStore) Max() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.max
}

func (st *SessionStore) Created() int64 { return st.created.Load() }

func (st *SessionStore) Get(id string, newClient SessionFactory) (*Session, bool, error) {
	now := time.Now()

	st.mu.Lock()
	if sess, ok := st.sessions[id]; ok {
		sess.lastUsed = now
		sess.idleClosed = false
		st.lru.MoveToFront(sess.elem)
		st.mu.Unlock()

		<-sess.ready
		if sess.err != nil {
			return nil, false, sess.err
		}
		return sess, false, nil
	}

	sess := &Session{
		ID:       id,
		Created:  now,
		lastUsed: now,
		ProxyIdx: -1,
		ready:    make(chan struct{}),
	}
	st.created.Add(1)
	st.sessions[id] = sess
	sess.elem = st.lru.PushFront(sess)
	evicted := st.trimLocked()
	st.mu.Unlock()

	client, proxyURL, proxyIdx, err := newClient()

	st.mu.Lock()
	if err != nil {
		st.removeLocked(sess)
		sess.err = err
	} else {
		sess.Client, sess.ProxyURL, sess.ProxyIdx = client, proxyURL, proxyIdx
	}
	st.mu.Unlock()
	close(sess.ready)

	releaseAll(evicted)

	if err != nil {
		return nil, false, err
	}
	return sess, true, nil
}

func (st *SessionStore) removeLocked(sess *Session) {
	if cur, ok := st.sessions[sess.ID]; ok && cur == sess {
		delete(st.sessions, sess.ID)
	}
	if sess.elem != nil {
		st.lru.Remove(sess.elem)
		sess.elem = nil
	}
}

func releaseAll(sessions []*Session) {
	for _, sess := range sessions {
		go func(sess *Session) {
			<-sess.ready
			if sess.Client != nil {
				sess.Client.CloseIdleConnections()
			}
		}(sess)
	}
}

func (st *SessionStore) End(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	sess, ok := st.sessions[id]
	if !ok {
		return false
	}
	st.removeLocked(sess)
	releaseAll([]*Session{sess})
	return true
}

func (st *SessionStore) EndAll() int {
	st.mu.Lock()
	defer st.mu.Unlock()

	n := len(st.sessions)
	all := make([]*Session, 0, n)
	for _, sess := range st.sessions {
		all = append(all, sess)
	}
	for _, sess := range all {
		st.removeLocked(sess)
	}
	releaseAll(all)
	return n
}

func (st *SessionStore) Len() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.sessions)
}

type SessionInfo struct {
	ID string `json:"id"`

	Proxy       string `json:"proxy"`
	ProxySource string `json:"proxy_source"`
	ProxySlot   int    `json:"proxy_slot"`

	Requests int64   `json:"requests"`
	AgeSec   float64 `json:"age_seconds"`
	IdleSec  float64 `json:"idle_seconds"`
}

func (s *Session) proxySource() string {
	switch {
	case s.ProxyIdx >= 0:
		return "pool"
	case s.ProxyURL != "":
		return "client"
	default:
		return "none"
	}
}

func (st *SessionStore) Snapshot() []SessionInfo {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	out := make([]SessionInfo, 0, len(st.sessions))
	for _, sess := range st.sessions {
		out = append(out, SessionInfo{
			ID:          sess.ID,
			Proxy:       maskProxyCredentials(sess.ProxyURL),
			ProxySource: sess.proxySource(),
			ProxySlot:   sess.ProxyIdx + 1,
			Requests:    sess.Requests.Load(),
			AgeSec:      now.Sub(sess.Created).Seconds(),
			IdleSec:     now.Sub(sess.lastUsed).Seconds(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IdleSec < out[j].IdleSec })
	return out
}

func (st *SessionStore) Close() {
	st.stopOnce.Do(func() { close(st.stop) })
	st.EndAll()
}

func (st *SessionStore) janitor() {
	ticker := time.NewTicker(st.sweepInterval())
	defer ticker.Stop()

	for {
		select {
		case <-st.stop:
			return
		case now := <-ticker.C:
			ticker.Reset(st.sweepInterval())

			st.mu.Lock()
			expired := st.expireLocked(now)
			release := st.idleConnSessionsLocked(now)
			st.mu.Unlock()

			releaseAll(expired)

			for _, sess := range release {
				sess.Client.CloseIdleConnections()
			}
		}
	}
}

func (st *SessionStore) sweepInterval() time.Duration {
	st.mu.Lock()
	ttl, idleConns := st.ttl, st.idleConns
	st.mu.Unlock()

	interval := ttl / 4
	if idleConns > 0 && idleConns/2 < interval {
		interval = idleConns / 2
	}
	switch {
	case interval < time.Second:
		return time.Second
	case interval > time.Minute:
		return time.Minute
	}
	return interval
}

func (st *SessionStore) idleConnSessionsLocked(now time.Time) []*Session {
	if st.idleConns <= 0 {
		return nil
	}

	var out []*Session
	for e := st.lru.Back(); e != nil; e = e.Prev() {
		sess := e.Value.(*Session)
		if now.Sub(sess.lastUsed) <= st.idleConns {
			break
		}
		if !sess.idleClosed {
			sess.idleClosed = true
			out = append(out, sess)
		}
	}
	return out
}

func (st *SessionStore) expireLocked(now time.Time) []*Session {
	var dropped []*Session
	for {
		back := st.lru.Back()
		if back == nil {
			return dropped
		}
		sess := back.Value.(*Session)
		if now.Sub(sess.lastUsed) <= st.ttl {
			return dropped
		}
		st.removeLocked(sess)
		dropped = append(dropped, sess)
	}
}

func (st *SessionStore) trimLocked() []*Session {
	if st.max <= 0 {
		return nil
	}

	var dropped []*Session
	for st.lru.Len() > st.max {
		back := st.lru.Back()
		if back == nil {
			break
		}
		sess := back.Value.(*Session)
		st.removeLocked(sess)
		dropped = append(dropped, sess)
	}
	return dropped
}

type proxyAuth struct {
	user      string
	password  string
	sessionID string
}

const SessionMarker = "-session-"

func parseProxyAuth(req *http.Request) proxyAuth {
	return parseBasicAuth(req.Header.Get("Proxy-Authorization"))
}

func parseBasicAuth(value string) proxyAuth {
	encoded, ok := cutPrefixFold(strings.TrimSpace(value), "Basic ")
	if !ok {
		return proxyAuth{}
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return proxyAuth{}
	}

	user, password, _ := strings.Cut(string(decoded), ":")
	base, session, _ := strings.Cut(user, SessionMarker)
	return proxyAuth{user: base, password: password, sessionID: session}
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}
