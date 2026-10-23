package proxy

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultRecordCapacity  = 500
	DefaultRecordBodyLimit = 32 << 10
)

type Outcome string

const (
	OutcomeOK          Outcome = "ok"
	OutcomeProxyFailed Outcome = "proxy-failed"
	OutcomeClientGone  Outcome = "client-gone"
	OutcomeFailed      Outcome = "failed"
)

type Record struct {
	Num     int64     `json:"num"`
	At      time.Time `json:"at"`
	Method  string    `json:"method"`
	Host    string    `json:"host"`
	Path    string    `json:"path"`
	Status  int       `json:"status"`
	Bytes   int64     `json:"bytes"`
	Millis  int64     `json:"millis"`
	Proto   string    `json:"proto"`
	Outcome Outcome   `json:"outcome"`
	Error   string    `json:"error,omitempty"`

	Session   string `json:"session,omitempty"`
	ProxyURL  string `json:"proxy,omitempty"`
	ProxySlot int    `json:"proxySlot"`
	Conn      string `json:"conn,omitempty"`

	RawRequest  string `json:"rawRequest,omitempty"`
	RawResponse string `json:"rawResponse,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`

	RawBody       string `json:"rawBody,omitempty"`
	BodyBytes     int64  `json:"bodyBytes,omitempty"`
	BodyTruncated bool   `json:"bodyTruncated,omitempty"`

	body *bodyCapture
}

func (r *Record) withBody() *Record {
	out := *r
	out.body = nil
	if r.body != nil {
		out.RawBody, out.BodyBytes, out.BodyTruncated = r.body.snapshot()
	}
	return &out
}

type Recorder struct {
	capacity  int
	bodyLimit int

	mu      sync.RWMutex
	records []*Record
	head    int
	size    int

	subsMu sync.Mutex
	subs   map[int]chan *Record
	nextID int

	dropped atomic.Int64
}

func NewRecorder(capacity, bodyLimit int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultRecordCapacity
	}
	if bodyLimit <= 0 {
		bodyLimit = DefaultRecordBodyLimit
	}
	return &Recorder{
		capacity:  capacity,
		bodyLimit: bodyLimit,
		records:   make([]*Record, capacity),
		subs:      make(map[int]chan *Record),
	}
}

func (r *Recorder) BodyLimit() int { return r.bodyLimit }

func (r *Recorder) Add(rec *Record) {
	if r == nil || rec == nil {
		return
	}

	rec.RawRequest, rec.Truncated = truncate(rec.RawRequest, r.bodyLimit)
	if cut, t := truncate(rec.RawResponse, r.bodyLimit); t || cut != rec.RawResponse {
		rec.RawResponse, rec.Truncated = cut, rec.Truncated || t
	}

	r.mu.Lock()
	idx := (r.head + r.size) % r.capacity
	if r.size == r.capacity {
		idx = r.head
		r.head = (r.head + 1) % r.capacity
	} else {
		r.size++
	}
	r.records[idx] = rec
	r.mu.Unlock()

	r.publish(rec)
}

func (r *Recorder) Snapshot(limit int) []*Record {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit > r.size {
		limit = r.size
	}
	out := make([]*Record, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (r.head + r.size - 1 - i + r.capacity) % r.capacity
		if rec := r.records[idx]; rec != nil {
			out = append(out, rec)
		}
	}
	return out
}

func (r *Recorder) Find(num int64) *Record {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := 0; i < r.size; i++ {
		idx := (r.head + i) % r.capacity
		if rec := r.records[idx]; rec != nil && rec.Num == num {
			return rec.withBody()
		}
	}
	return nil
}

func (r *Recorder) Dropped() int64 { return r.dropped.Load() }

func (r *Recorder) Subscribe() (<-chan *Record, func()) {
	ch := make(chan *Record, 256)

	r.subsMu.Lock()
	id := r.nextID
	r.nextID++
	r.subs[id] = ch
	r.subsMu.Unlock()

	return ch, func() {
		r.subsMu.Lock()
		if existing, ok := r.subs[id]; ok {
			delete(r.subs, id)
			close(existing)
		}
		r.subsMu.Unlock()
	}
}

func (r *Recorder) publish(rec *Record) {
	r.subsMu.Lock()
	defer r.subsMu.Unlock()

	for _, ch := range r.subs {
		select {
		case ch <- rec:
		default:
			r.dropped.Add(1)
		}
	}
}

type bodyCapture struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	total     int64
	truncated bool
}

func newBodyCapture(limit int) *bodyCapture {
	return &bodyCapture{limit: limit}
}

func (c *bodyCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.total += int64(len(p))
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) <= room {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:room]...)
			c.truncated = true
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

func (c *bodyCapture) snapshot() (string, int64, bool) {
	if c == nil {
		return "", 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf), c.total, c.truncated
}

type teeBody struct {
	rc      io.ReadCloser
	capture *bodyCapture
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.capture.Write(p[:n])
	}
	return n, err
}

func (t *teeBody) Close() error { return t.rc.Close() }

func truncate(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	return s[:limit], true
}

func classify(err error) (Outcome, string) {
	switch {
	case err == nil:
		return OutcomeOK, ""
	case isProxyRefusal(err) || isDialFailure(err):
		return OutcomeProxyFailed, err.Error()
	case isClientGone(err):
		return OutcomeClientGone, err.Error()
	default:
		return OutcomeFailed, err.Error()
	}
}
