package fingerprint

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ParseClientHelloHex parses a raw ClientHello hex stream and returns
// the JA3 fullstring and JA4_r raw string.
func ParseClientHelloHex(hexStr string) (ja3 string, ja4r string, err error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ToLower(hexStr)

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid hex: %w", err)
	}

	off := 0

	// TLS record layer (optional - might start directly at handshake)
	if off+5 <= len(data) && data[off] == 0x16 {
		off += 5 // skip: type(1) + version(2) + length(2)
	}

	// Handshake header
	if off+4 > len(data) || data[off] != 0x01 {
		return "", "", fmt.Errorf("not a ClientHello handshake")
	}
	off += 4 // type(1) + length(3)

	// ClientHello version
	if off+2 > len(data) {
		return "", "", fmt.Errorf("truncated: version")
	}
	chVersion := uint16(data[off])<<8 | uint16(data[off+1])
	off += 2

	// Random (32 bytes)
	if off+32 > len(data) {
		return "", "", fmt.Errorf("truncated: random")
	}
	off += 32

	// Session ID
	if off+1 > len(data) {
		return "", "", fmt.Errorf("truncated: session id length")
	}
	sidLen := int(data[off])
	off += 1 + sidLen

	// Cipher Suites
	if off+2 > len(data) {
		return "", "", fmt.Errorf("truncated: cipher suites length")
	}
	csLen := int(data[off])<<8 | int(data[off+1])
	off += 2

	if off+csLen > len(data) {
		return "", "", fmt.Errorf("truncated: cipher suites")
	}

	var ciphers []uint16
	for i := 0; i < csLen; i += 2 {
		cs := uint16(data[off+i])<<8 | uint16(data[off+i+1])
		if !isGREASE(cs) {
			ciphers = append(ciphers, cs)
		}
	}
	off += csLen

	// Compression Methods
	if off+1 > len(data) {
		return "", "", fmt.Errorf("truncated: compression")
	}
	cmLen := int(data[off])
	off += 1 + cmLen

	// Extensions
	if off+2 > len(data) {
		return "", "", fmt.Errorf("truncated: extensions length")
	}
	extLen := int(data[off])<<8 | int(data[off+1])
	off += 2

	if off+extLen > len(data) {
		return "", "", fmt.Errorf("truncated: extensions")
	}

	var extIDs []uint16
	var curves []uint16
	var pointFormats []uint8
	var sigAlgs []uint16
	var alpnStr string
	var supportedVersions []uint16
	hasSNI := false
	hasPadding := false

	extEnd := off + extLen
	for off < extEnd {
		if off+4 > extEnd {
			break
		}
		extType := uint16(data[off])<<8 | uint16(data[off+1])
		eLen := int(data[off+2])<<8 | int(data[off+3])
		off += 4

		if off+eLen > extEnd {
			break
		}
		extData := data[off : off+eLen]
		off += eLen

		if isGREASE(extType) {
			continue
		}

		extIDs = append(extIDs, extType)

		switch extType {
		case 0x0000: // SNI
			hasSNI = true

		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				gLen := int(extData[0])<<8 | int(extData[1])
				for i := 2; i+1 < 2+gLen && i+1 < len(extData); i += 2 {
					g := uint16(extData[i])<<8 | uint16(extData[i+1])
					if !isGREASE(g) {
						curves = append(curves, g)
					}
				}
			}

		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				pfLen := int(extData[0])
				for i := 1; i < 1+pfLen && i < len(extData); i++ {
					pointFormats = append(pointFormats, extData[i])
				}
			}

		case 0x000d: // signature_algorithms
			if len(extData) >= 2 {
				saLen := int(extData[0])<<8 | int(extData[1])
				for i := 2; i+1 < 2+saLen && i+1 < len(extData); i += 2 {
					sa := uint16(extData[i])<<8 | uint16(extData[i+1])
					sigAlgs = append(sigAlgs, sa)
				}
			}

		case 0x0010: // ALPN
			if len(extData) >= 2 {
				aLen := int(extData[0])<<8 | int(extData[1])
				pos := 2
				if pos < 2+aLen && pos < len(extData) {
					sLen := int(extData[pos])
					pos++
					if pos+sLen <= len(extData) {
						first := string(extData[pos : pos+sLen])
						if first == "h2" {
							alpnStr = "h2"
						} else {
							alpnStr = "h1"
						}
					}
				}
			}

		case 0x0015: // padding
			hasPadding = true

		case 0x002b: // supported_versions
			if len(extData) >= 1 {
				svLen := int(extData[0])
				for i := 1; i+1 < 1+svLen && i+1 < len(extData); i += 2 {
					v := uint16(extData[i])<<8 | uint16(extData[i+1])
					if !isGREASE(v) {
						supportedVersions = append(supportedVersions, v)
					}
				}
			}
		}

		_ = hasPadding
	}

	// Determine TLS version for JA3 and JA4
	ja3Version := chVersion
	ja4TLSVer := "12"
	if len(supportedVersions) > 0 {
		highest := supportedVersions[0]
		for _, v := range supportedVersions {
			if v > highest {
				highest = v
			}
		}
		if highest == 0x0304 {
			ja3Version = 771 // TLS 1.2 record but 1.3 in supported_versions
			ja4TLSVer = "13"
		} else if highest == 0x0303 {
			ja4TLSVer = "12"
		} else if highest == 0x0302 {
			ja4TLSVer = "11"
		} else if highest == 0x0301 {
			ja4TLSVer = "10"
		}
	} else {
		switch chVersion {
		case 0x0303:
			ja4TLSVer = "12"
		case 0x0302:
			ja4TLSVer = "11"
		case 0x0301:
			ja4TLSVer = "10"
		}
	}

	// ── Build JA3 ──
	ja3Parts := make([]string, 5)

	// Field 1: TLS version
	ja3Parts[0] = fmt.Sprintf("%d", ja3Version)

	// Field 2: Cipher suites (decimal, dash-separated, original order)
	csDec := make([]string, len(ciphers))
	for i, c := range ciphers {
		csDec[i] = fmt.Sprintf("%d", c)
	}
	ja3Parts[1] = strings.Join(csDec, "-")

	// Field 3: Extensions (decimal, dash-separated, original order)
	extDec := make([]string, len(extIDs))
	for i, e := range extIDs {
		extDec[i] = fmt.Sprintf("%d", e)
	}
	ja3Parts[2] = strings.Join(extDec, "-")

	// Field 4: Elliptic curves (decimal, dash-separated)
	curveDec := make([]string, len(curves))
	for i, c := range curves {
		curveDec[i] = fmt.Sprintf("%d", c)
	}
	ja3Parts[3] = strings.Join(curveDec, "-")

	// Field 5: Point formats (decimal, dash-separated)
	pfDec := make([]string, len(pointFormats))
	for i, p := range pointFormats {
		pfDec[i] = fmt.Sprintf("%d", p)
	}
	ja3Parts[4] = strings.Join(pfDec, "-")

	ja3 = strings.Join(ja3Parts, ",")

	// ── Build JA4_r ──
	sniChar := "i"
	if hasSNI {
		sniChar = "d"
	}
	if alpnStr == "" {
		alpnStr = "00"
	}

	// Count extensions (including GREASE-excluded ones we collected)
	extCount := len(extIDs)

	header := fmt.Sprintf("t%s%s%02d%02d%s", ja4TLSVer, sniChar, len(ciphers), extCount, alpnStr)

	// Sorted cipher suites hex
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	csHex := make([]string, len(sortedCiphers))
	for i, c := range sortedCiphers {
		csHex[i] = fmt.Sprintf("%04x", c)
	}

	// Sorted extensions hex (exclude SNI 0x0000 and ALPN 0x0010)
	var filteredExts []uint16
	for _, e := range extIDs {
		if e != 0x0000 && e != 0x0010 {
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extHex := make([]string, len(filteredExts))
	for i, e := range filteredExts {
		extHex[i] = fmt.Sprintf("%04x", e)
	}

	// Signature algorithms hex (original order)
	saHex := make([]string, len(sigAlgs))
	for i, sa := range sigAlgs {
		saHex[i] = fmt.Sprintf("%04x", sa)
	}

	ja4r = fmt.Sprintf("%s_%s_%s_%s",
		header,
		strings.Join(csHex, ","),
		strings.Join(extHex, ","),
		strings.Join(saHex, ","),
	)

	return ja3, ja4r, nil
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}
