package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

func canonicalHeader(lk string) string {
	return http.CanonicalHeaderKey(lk)
}

var hopByHopHeaders = map[string]bool{
	"proxy-connection":    true,
	"proxy-authorization": true,
	"connection":          true,
	"keep-alive":          true,
	"transfer-encoding":   true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"x-tls-ja3":           true,
	"x-tls-ja4r":          true,
	"x-tls-session":       true,
}

var rawLog atomic.Bool

func setRawLog(on bool) { rawLog.Store(on) }

func RawLog() bool { return rawLog.Load() }

var pseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

func relay(ctx context.Context, num int64, client tls_client.HttpClient, downstream *http.Request, headerOrder []string, obs *exchange) (*http.Response, error) {
	var bodyBytes []byte
	if downstream.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(downstream.Body)
		if err != nil {
			return nil, fmt.Errorf("read downstream body: %w", err)
		}
		downstream.Body.Close()
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	upReq, err := fhttp.NewRequest(downstream.Method, downstream.URL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	if ctx != nil {
		upReq = upReq.WithContext(ctx)
	}

	if len(headerOrder) > 0 {
		canonicalOrder := make([]string, 0, len(headerOrder))
		for _, lk := range headerOrder {
			ck := canonicalHeader(lk)
			for k, vals := range downstream.Header {
				if strings.ToLower(k) == lk {
					upReq.Header[ck] = append(upReq.Header[ck], vals...)
					break
				}
			}
			canonicalOrder = append(canonicalOrder, ck)
		}
		upReq.Header[fhttp.HeaderOrderKey] = canonicalOrder
	} else {
		var order []string
		for _, lk := range stableHeaderOrder(downstream.Header) {
			ck := canonicalHeader(lk)
			for k, vals := range downstream.Header {
				if strings.ToLower(k) == lk {
					upReq.Header[ck] = append(upReq.Header[ck], vals...)
					break
				}
			}
			order = append(order, ck)
		}
		if len(order) > 0 {
			upReq.Header[fhttp.HeaderOrderKey] = order
		}
	}

	if _, sent := upReq.Header["User-Agent"]; !sent {
		upReq.Header["User-Agent"] = []string{}
	}

	if len(bodyBytes) > 0 {
		upReq.ContentLength = int64(len(bodyBytes))
	}

	upResp, err := client.Do(upReq)

	proto := "HTTP/1.1"
	if upResp != nil && upResp.Proto != "" {
		proto = upResp.Proto
	}
	if obs != nil {
		obs.Proto = proto
	}

	if RawLog() || obs != nil {
		if raw, dumpErr := dumpUpstreamRequest(client, upReq, bodyBytes, pseudoHeaderOrder, proto); dumpErr == nil {
			if RawLog() {
				logRawRequest(num, proto, raw)
			}
			if obs != nil {
				obs.RawRequest = raw
			}
		} else if RawLog() {
			log.Printf("raw dump failed: %v", dumpErr)
		}
	}

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, fmt.Errorf("client went away before the upstream replied: %w", ctx.Err())
		}
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}

	body := io.ReadCloser(upResp.Body)
	if obs != nil {
		obs.Body = newBodyCapture(BodyCaptureLimit)
		body = &teeBody{rc: upResp.Body, capture: obs.Body}
	}

	stdResp := &http.Response{
		StatusCode:    upResp.StatusCode,
		Status:        fmt.Sprintf("%d %s", upResp.StatusCode, http.StatusText(upResp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          body,
		ContentLength: upResp.ContentLength,
	}

	for key, vals := range upResp.Header {
		for _, val := range vals {
			stdResp.Header.Add(key, val)
		}
	}

	return stdResp, nil
}

type exchange struct {
	RawRequest string
	Proto      string

	Body *bodyCapture
}

var recording atomic.Bool

func SetRecording(on bool) { recording.Store(on) }

func Recording() bool { return recording.Load() }

var BodyCaptureLimit = DefaultRecordBodyLimit
