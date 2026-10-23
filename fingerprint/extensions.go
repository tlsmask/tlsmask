package fingerprint

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"

	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
)

type passthroughExt struct {
	ID    uint16
	Index int
}

var passthroughBodies = map[uint16][]byte{
	0xCA34: {0x00, 0x00},
}

func passthroughBody(id uint16) []byte {
	return passthroughBodies[id]
}

var unknownExtensionRe = regexp.MustCompile(`unknown extension with id (\d+)`)

func unknownExtensionID(err error) (uint16, bool) {
	if err == nil {
		return 0, false
	}
	m := unknownExtensionRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	id, parseErr := strconv.ParseUint(m[1], 10, 16)
	if parseErr != nil {
		return 0, false
	}
	return uint16(id), true
}

type specFactoryArgs struct {
	SigAlgs         []string
	DelegatedCreds  []string
	Versions        []string
	KeyShareCurves  []string
	ALPN            []string
	ALPS            []string
	ECHCipherSuites []tls_client.CandidateCipherSuites
	ECHPayloadLens  []uint16
	CertCompression []string
	RecordSizeLimit uint16
}

func (a specFactoryArgs) build(ja3 string) (func() (tls.ClientHelloSpec, error), error) {
	factory, err := tls_client.GetSpecFactoryFromJa3String(
		ja3, a.SigAlgs, a.DelegatedCreds, a.Versions, a.KeyShareCurves, a.ALPN,
		a.ALPS, a.ECHCipherSuites, a.ECHPayloadLens, a.CertCompression, a.RecordSizeLimit,
	)
	if err != nil {
		return nil, err
	}

	if _, specErr := factory(); specErr != nil {
		return nil, specErr
	}
	return factory, nil
}

func buildSpecFactory(ja3 string, args specFactoryArgs) (func() (tls.ClientHelloSpec, error), error) {
	fields := strings.Split(ja3, ",")
	if len(fields) < 5 {
		return nil, fmt.Errorf("malformed JA3: expected 5 comma-separated fields, got %d", len(fields))
	}

	original := splitFields(fields[2])
	var passthrough []passthroughExt

	for {
		factory, err := args.build(withExtensions(fields, original, passthrough))
		if err == nil {
			if len(passthrough) == 0 {
				return factory, nil
			}
			return reinsertingFactory(factory, original, passthrough), nil
		}

		id, ok := unknownExtensionID(err)
		if !ok {
			return nil, err
		}

		idx := indexOfExtension(original, id, passthrough)
		if idx < 0 {
			return nil, err
		}
		passthrough = append(passthrough, passthroughExt{ID: id, Index: idx})
		warnPassthrough(id)
	}
}

func withExtensions(fields []string, original []string, skip []passthroughExt) string {
	skipped := make(map[int]bool, len(skip))
	for _, p := range skip {
		skipped[p.Index] = true
	}

	kept := make([]string, 0, len(original))
	for i, e := range original {
		if !skipped[i] {
			kept = append(kept, e)
		}
	}

	out := make([]string, len(fields))
	copy(out, fields)
	out[2] = strings.Join(kept, "-")
	return strings.Join(out, ",")
}

func indexOfExtension(original []string, id uint16, skip []passthroughExt) int {
	skipped := make(map[int]bool, len(skip))
	for _, p := range skip {
		skipped[p.Index] = true
	}

	want := strconv.FormatUint(uint64(id), 10)
	for i, e := range original {
		if e == want && !skipped[i] {
			return i
		}
	}
	return -1
}

func reinsertingFactory(inner func() (tls.ClientHelloSpec, error), original []string, passthrough []passthroughExt) func() (tls.ClientHelloSpec, error) {
	byIndex := make(map[int]uint16, len(passthrough))
	for _, p := range passthrough {
		byIndex[p.Index] = p.ID
	}

	return func() (tls.ClientHelloSpec, error) {
		spec, err := inner()
		if err != nil {
			return spec, err
		}

		merged := make([]tls.TLSExtension, 0, len(original))
		next := 0
		for i := range original {
			if id, ok := byIndex[i]; ok {
				merged = append(merged, &tls.GenericExtension{Id: id, Data: passthroughBody(id)})
				continue
			}
			if next < len(spec.Extensions) {
				merged = append(merged, spec.Extensions[next])
				next++
			}
		}
		merged = append(merged, spec.Extensions[next:]...)

		spec.Extensions = merged
		return spec, nil
	}
}

var warnedExtensions sync.Map

func warnPassthrough(id uint16) {
	if _, seen := warnedExtensions.LoadOrStore(id, true); seen {
		return
	}
	if _, known := passthroughBodies[id]; known {
		log.Printf("extension %d (0x%04X) has no builder in this TLS library; sending its known minimal body so the JA3/JA4 stays exact", id, id)
		return
	}
	log.Printf("extension %d (0x%04X) has no builder in this TLS library and no known body; sending it empty to keep the JA3/JA4 exact; a peer that implements it may answer illegal_parameter", id, id)
}
