package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

var hopByHopHeaders = map[string]bool{
	"proxy-connection": true, "proxy-authorization": true,
	"connection": true, "keep-alive": true,
	"transfer-encoding": true, "te": true,
	"trailer": true, "upgrade": true,
}

func relay(client tls_client.HttpClient, downstream *http.Request) (*http.Response, error) {
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

	var headerOrder []string
	for key, vals := range downstream.Header {
		lowerKey := strings.ToLower(key)
		if hopByHopHeaders[lowerKey] || lowerKey == "host" || lowerKey == "content-length" {
			continue
		}
		headerOrder = append(headerOrder, lowerKey)
		for _, val := range vals {
			upReq.Header.Add(key, val)
		}
	}

	if len(headerOrder) > 0 {
		upReq.Header[fhttp.HeaderOrderKey] = headerOrder
	}
	if len(bodyBytes) > 0 {
		upReq.ContentLength = int64(len(bodyBytes))
	}

	upResp, err := client.Do(upReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}

	stdResp := &http.Response{
		StatusCode:    upResp.StatusCode,
		Status:        fmt.Sprintf("%d %s", upResp.StatusCode, http.StatusText(upResp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          upResp.Body,
		ContentLength: upResp.ContentLength,
	}

	for key, vals := range upResp.Header {
		for _, val := range vals {
			stdResp.Header.Add(key, val)
		}
	}

	return stdResp, nil
}
