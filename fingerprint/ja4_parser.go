package fingerprint

import (
	"fmt"
	"strings"
)

type JA4RInfo struct {
	Protocol   string
	TLSVersion string
	HasSNI     bool
	ALPN       string

	SignatureAlgorithmsHex []string
}

func ParseJA4R(ja4r string) (*JA4RInfo, error) {
	segments := strings.Split(ja4r, "_")
	if len(segments) < 4 {
		return nil, fmt.Errorf("invalid JA4_r: expected 4 segments, got %d", len(segments))
	}

	header := segments[0]
	sigAlgsRaw := segments[3]

	if len(header) < 4 {
		return nil, fmt.Errorf("invalid JA4_r header: too short: %q", header)
	}

	info := &JA4RInfo{
		Protocol:   string(header[0]),
		TLSVersion: header[1:3],
		HasSNI:     header[3] == 'd',
	}

	if len(header) >= 6 {
		info.ALPN = header[len(header)-2:]
	}

	if sigAlgsRaw != "" {
		info.SignatureAlgorithmsHex = strings.Split(sigAlgsRaw, ",")
	}

	return info, nil
}

func (info *JA4RInfo) ALPNProtocols() []string {
	switch info.ALPN {
	case "h2":
		return []string{"h2", "http/1.1"}
	case "h1":
		return []string{"http/1.1"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

func (info *JA4RInfo) SupportedVersions() []string {
	switch info.TLSVersion {
	case "13":
		return []string{"1.3", "1.2"}
	case "12":
		return []string{"1.2", "1.1"}
	case "11":
		return []string{"1.1", "1.0"}
	case "10":
		return []string{"1.0"}
	default:
		return []string{"1.3", "1.2"}
	}
}
