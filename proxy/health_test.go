package proxy

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func dialErr() error {
	return fmt.Errorf("upstream request failed: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")})
}

func TestUpstreamHealthTripsAfterRepeatedDialFailures(t *testing.T) {
	h := newUpstreamHealth(time.Minute)
	const px = "http://user:pass@proxy:9000"

	for i := 0; i < breakerThreshold-1; i++ {
		h.record(px, dialErr())
		if !h.allow(px) {
			t.Fatalf("proxy sidelined after only %d failures, threshold is %d", i+1, breakerThreshold)
		}
	}

	h.record(px, dialErr())
	if h.allow(px) {
		t.Error("proxy still admitted after reaching the failure threshold")
	}
	if h.tripped() != 1 {
		t.Errorf("tripped() = %d, want 1", h.tripped())
	}
}

func TestUpstreamHealthResetsOnSuccess(t *testing.T) {
	h := newUpstreamHealth(time.Minute)
	const px = "http://proxy:9000"

	for i := 0; i < breakerThreshold-1; i++ {
		h.record(px, dialErr())
	}
	h.record(px, nil)

	for i := 0; i < breakerThreshold-1; i++ {
		h.record(px, dialErr())
		if !h.allow(px) {
			t.Fatal("streak was not reset by the successful request")
		}
	}
}

func TestUpstreamHealthIgnoresTargetErrors(t *testing.T) {
	h := newUpstreamHealth(time.Minute)
	const px = "http://proxy:9000"

	for i := 0; i < breakerThreshold*3; i++ {
		h.record(px, errors.New("upstream request failed: unexpected EOF"))
	}
	if !h.allow(px) {
		t.Error("proxy sidelined by errors that came from the target, not the proxy")
	}
}

func TestUpstreamHealthAdmitsOneProbePerCooldown(t *testing.T) {
	h := newUpstreamHealth(80 * time.Millisecond)
	const px = "http://proxy:9000"

	for i := 0; i < breakerThreshold; i++ {
		h.record(px, dialErr())
	}
	if h.allow(px) {
		t.Fatal("proxy admitted while cooling down")
	}

	time.Sleep(120 * time.Millisecond)
	if !h.allow(px) {
		t.Fatal("no probe admitted after the cooldown elapsed")
	}
	if h.allow(px) {
		t.Error("a second request slipped through in the same cooldown window")
	}
}

func TestUpstreamHealthDisabled(t *testing.T) {
	h := newUpstreamHealth(0)
	const px = "http://proxy:9000"

	for i := 0; i < breakerThreshold*2; i++ {
		h.record(px, dialErr())
	}
	if !h.allow(px) {
		t.Error("breaker acted while disabled")
	}
}

func TestErrorClassification(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		dial, refusal bool
	}{
		{"nil", nil, false, false},
		{"wrapped dial error", dialErr(), true, false},
		{"dial text from the transport", errors.New("dial tcp 1.2.3.4:9000: i/o timeout"), true, false},
		{"proxy refused CONNECT", errors.New("Proxy responded with non 200 code: 407"), false, true},
		{"target sent garbage", errors.New("http: server gave HTTP response to HTTPS client"), false, false},
		{"target reset", errors.New("unexpected EOF"), false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDialFailure(tc.err); got != tc.dial {
				t.Errorf("isDialFailure(%v) = %v, want %v", tc.err, got, tc.dial)
			}
			if got := isProxyRefusal(tc.err); got != tc.refusal {
				t.Errorf("isProxyRefusal(%v) = %v, want %v", tc.err, got, tc.refusal)
			}
		})
	}
}

func TestUpstreamHealthTripsPerHostOnDialFailure(t *testing.T) {
	h := newUpstreamHealth(time.Minute)
	url := func(port int) string {
		return fmt.Sprintf("http://user:pass@gate.example.com:%d", port)
	}

	for i := 0; i < breakerThreshold; i++ {
		h.record(url(40000+i), dialErr())
	}

	if h.allow(url(59999)) {
		t.Error("a port never seen before was admitted to a gateway that is not answering")
	}
	if !h.allow("http://user:pass@other.example.com:8080") {
		t.Error("an unrelated host was sidelined")
	}
}

func TestUpstreamHealthTripsPerEndpointOnRefusal(t *testing.T) {
	h := newUpstreamHealth(time.Minute)
	const bad = "http://user:pass@gate.example.com:40001"

	for i := 0; i < breakerThreshold; i++ {
		h.record(bad, errors.New("Proxy responded with non 200 code: 407"))
	}

	if h.allow(bad) {
		t.Error("the refusing endpoint was still admitted")
	}
	if !h.allow("http://user:pass@gate.example.com:40002") {
		t.Error("one refused port sidelined the whole gateway")
	}
}
