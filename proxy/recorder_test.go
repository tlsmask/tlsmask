package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBodyCaptureDoesNotHoldWholeBodies(t *testing.T) {
	const limit = 1 << 10
	payload := bytes.Repeat([]byte("abcdefgh"), 4096)

	capture := newBodyCapture(limit)
	tee := &teeBody{rc: io.NopCloser(bytes.NewReader(payload)), capture: capture}

	relayed, err := io.ReadAll(tee)
	if err != nil {
		t.Fatalf("read through the tee: %v", err)
	}

	if !bytes.Equal(relayed, payload) {
		t.Fatalf("relayed %d bytes, want the full %d unchanged", len(relayed), len(payload))
	}

	kept, total, truncated := capture.snapshot()
	if len(kept) != limit {
		t.Errorf("kept %d bytes, want the cap of %d", len(kept), limit)
	}
	if !truncated {
		t.Error("a body over the cap was not reported as truncated")
	}
	if total != int64(len(payload)) {
		t.Errorf("reported %d bytes seen, want %d", total, len(payload))
	}
	if !bytes.Equal([]byte(kept), payload[:limit]) {
		t.Error("the kept prefix is not the start of the body")
	}
}

func TestBodyCaptureKeepsShortBodiesWhole(t *testing.T) {
	payload := `{"ok":true,"ip":"203.0.113.9"}`

	capture := newBodyCapture(DefaultRecordBodyLimit)
	tee := &teeBody{rc: io.NopCloser(strings.NewReader(payload)), capture: capture}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		t.Fatalf("copy: %v", err)
	}

	kept, total, truncated := capture.snapshot()
	if kept != payload {
		t.Errorf("kept %q, want %q", kept, payload)
	}
	if truncated {
		t.Error("a body under the cap was marked truncated")
	}
	if total != int64(len(payload)) {
		t.Errorf("reported %d bytes, want %d", total, len(payload))
	}
}

func TestBodyCapturePartialOnEarlyClose(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)

	capture := newBodyCapture(DefaultRecordBodyLimit)
	tee := &teeBody{rc: io.NopCloser(bytes.NewReader(payload)), capture: capture}

	half := make([]byte, 1000)
	if _, err := io.ReadFull(tee, half); err != nil {
		t.Fatalf("partial read: %v", err)
	}
	tee.Close()

	kept, total, truncated := capture.snapshot()
	if len(kept) != 1000 || total != 1000 {
		t.Errorf("captured %d bytes (total %d), want 1000", len(kept), total)
	}
	if truncated {
		t.Error("a short partial read was marked truncated")
	}
}

func TestRecordBodyIsOnlyServedOnOpen(t *testing.T) {
	rec := &Record{Num: 1, Host: "example.com", body: newBodyCapture(1024)}
	rec.body.Write([]byte("hello"))

	r := NewRecorder(4, 1024)
	r.Add(rec)

	for _, listed := range r.Snapshot(0) {
		if listed.RawBody != "" {
			t.Error("a listed record carried its body")
		}
	}

	opened := r.Find(1)
	if opened == nil {
		t.Fatal("the record is not in the window")
	}
	if opened.RawBody != "hello" {
		t.Errorf("opened record body = %q, want %q", opened.RawBody, "hello")
	}
}

func TestResponseHeadFollowsTheUpstreamProtocol(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"application/json"}}}

	h2 := responseHead(resp, "HTTP/2.0")
	if !strings.HasPrefix(h2, ":status: 200") || !strings.Contains(h2, "content-type: application/json") {
		t.Errorf("HTTP/2 head = %q, want a :status field and lowercase names", h2)
	}

	h1 := responseHead(resp, "HTTP/1.1")
	if !strings.HasPrefix(h1, "HTTP/1.1 200 OK") || !strings.Contains(h1, "Content-Type: application/json") {
		t.Errorf("HTTP/1.1 head = %q, want a status line and canonical names", h1)
	}
}
