package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

func BuildClient(tmpl *Template, proxyURL string, plan Plan) (tls_client.HttpClient, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("template is nil")
	}

	ja3String := tmpl.JA3String
	keyShareCurves := tmpl.KeyShareCurves
	if plan.GREASE {
		ja3String = GreaseJA3(ja3String)
		keyShareCurves = GreaseKeyShareCurves(keyShareCurves)
	}

	specFactory, err := buildSpecFactory(ja3String, specFactoryArgs{
		SigAlgs:         tmpl.SupportedSignatureAlgorithms,
		DelegatedCreds:  tmpl.DelegatedCredentialsAlgorithms,
		Versions:        tmpl.SupportedVersions,
		KeyShareCurves:  keyShareCurves,
		ALPN:            tmpl.ALPNProtocols,
		CertCompression: tmpl.CertCompressionAlgorithms,
		RecordSizeLimit: tmpl.RecordSizeLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("build spec factory from JA3: %w", err)
	}

	clientHelloID := tls.ClientHelloID{
		Client:      "tlsmask",
		Version:     tmpl.Name,
		Seed:        nil,
		SpecFactory: specFactory,
	}

	h2Settings, h2SettingsOrder := mapH2Settings(tmpl)

	profile := profiles.NewClientProfile(
		clientHelloID,
		h2Settings,
		h2SettingsOrder,
		tmpl.PseudoHeaderOrder,
		tmpl.ConnectionFlow,
		nil, nil, 0, false,
		tmpl.H3Settings, tmpl.H3SettingsOrder, 0, tmpl.H3PseudoHeaderOrder, false,
	)

	return tls_client.NewHttpClient(nil, clientOptions(profile, proxyURL, plan)...)
}

func clientOptions(profile profiles.ClientProfile, proxyURL string, plan Plan) []tls_client.HttpClientOption {
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTimeoutMilliseconds(int(ClientTimeout() / time.Millisecond)),
		tls_client.WithDialer(net.Dialer{Timeout: DialTimeout(), KeepAlive: 30 * time.Second}),
	}
	if !VerifyUpstream() {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	if plan.ShuffleExtensions {
		options = append(options, tls_client.WithRandomTLSExtensionOrder())
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyDialerFactory(countingProxyDialer(proxyURL)))
	}
	return options
}

func BuildClientFromRaw(ja3String, ja4rString, proxyURL string, plan Plan) (tls_client.HttpClient, string, error) {
	specFactory, ja4r, err := rawSpecFactory(ja3String, ja4rString, plan)
	if err != nil {
		return nil, "", err
	}

	clientHelloID := tls.ClientHelloID{
		Client:      "tlsmask",
		Version:     "custom",
		SpecFactory: specFactory,
	}

	h2Settings, h2SettingsOrder := rawH2Settings(ja3String)

	profile := profiles.NewClientProfile(
		clientHelloID,
		h2Settings, h2SettingsOrder,
		[]string{":method", ":authority", ":scheme", ":path"},
		15663105,
		nil, nil, 0, false,
		nil, nil, 0, nil, false,
	)

	client, err := tls_client.NewHttpClient(nil, clientOptions(profile, proxyURL, plan)...)
	if err != nil {
		return nil, "", fmt.Errorf("create HTTP client: %w", err)
	}

	displayName := fmt.Sprintf("custom (TLS %s, %s, %d ciphers, %d sig_algs)",
		ja4r.TLSVersion, ja4r.ALPN, countJA3Ciphers(ja3String), len(ja4r.SignatureAlgorithmsHex))

	return client, displayName, nil
}

func rawH2Settings(ja3String string) (map[http2.SettingID]uint32, []http2.SettingID) {
	if DetectBrowser(ja3String) == BrowserChrome {
		return map[http2.SettingID]uint32{
				http2.SettingHeaderTableSize:   65536,
				http2.SettingEnablePush:        0,
				http2.SettingInitialWindowSize: 6291456,
				http2.SettingMaxHeaderListSize: 262144,
			}, []http2.SettingID{
				http2.SettingHeaderTableSize,
				http2.SettingEnablePush,
				http2.SettingInitialWindowSize,
				http2.SettingMaxHeaderListSize,
			}
	}
	return map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		}, []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
}

func rawSpecFactory(ja3String, ja4rString string, plan Plan) (func() (tls.ClientHelloSpec, error), *JA4RInfo, error) {
	ja4r, err := ParseJA4R(ja4rString)
	if err != nil {
		return nil, nil, fmt.Errorf("parse JA4_r: %w", err)
	}

	sigAlgs := ja4r.SignatureAlgorithmsHex
	alpn := ja4r.ALPNProtocols()
	versions := ja4r.SupportedVersions()

	if hasTLS13Ciphers(ja3String) && !containsVersion(versions, "1.3") {
		versions = []string{"1.3", "1.2"}
	}

	keyShareCurves := inferKeyShareCurves(ja3String, ja4r.TLSVersion)
	certCompression := inferCertCompression(ja3String)

	var alps []string
	if containsExtensionID(ja3String, "17613") {
		alps = inferALPS(alpn)
	}

	var echCipherSuites []tls_client.CandidateCipherSuites
	var echPayloadLens []uint16
	if containsExtensionID(ja3String, "65037") {
		echCipherSuites = []tls_client.CandidateCipherSuites{
			{KdfId: "HKDF_SHA256", AeadId: "AEAD_AES_128_GCM"},
			{KdfId: "HKDF_SHA256", AeadId: "AEAD_AES_256_GCM"},
			{KdfId: "HKDF_SHA256", AeadId: "AEAD_CHACHA20_POLY1305"},
		}
		echPayloadLens = []uint16{128, 223}
	}

	var delegatedCreds []string
	if containsExtensionID(ja3String, "34") {
		delegatedCreds = sigAlgs
	}

	var recordSizeLimit uint16
	if containsExtensionID(ja3String, "28") {
		recordSizeLimit = 16385
	}

	if plan.GREASE {
		ja3String = GreaseJA3(ja3String)
		keyShareCurves = GreaseKeyShareCurves(keyShareCurves)
	}

	specFactory, err := buildSpecFactory(ja3String, specFactoryArgs{
		SigAlgs:         sigAlgs,
		DelegatedCreds:  delegatedCreds,
		Versions:        versions,
		KeyShareCurves:  keyShareCurves,
		ALPN:            alpn,
		ALPS:            alps,
		ECHCipherSuites: echCipherSuites,
		ECHPayloadLens:  echPayloadLens,
		CertCompression: certCompression,
		RecordSizeLimit: recordSizeLimit,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build spec from JA3+JA4_r: %w", err)
	}

	return specFactory, ja4r, nil
}

func inferKeyShareCurves(ja3String, tlsVersion string) []string {
	needKeyShare := tlsVersion == "13" || hasTLS13Ciphers(ja3String)
	if !needKeyShare {
		return nil
	}

	parts := strings.Split(ja3String, ",")
	if len(parts) < 4 || parts[3] == "" {
		return []string{"X25519"}
	}

	curveMap := map[string]string{
		"29": "X25519", "23": "P256", "24": "P384", "25": "P521",
		"25497": "X25519Kyber768", "4588": "X25519MLKEM768",
	}

	curves := strings.Split(parts[3], "-")
	var result []string
	for _, c := range curves {
		if name, ok := curveMap[c]; ok {
			result = append(result, name)
			if len(result) >= 2 {
				break
			}
		}
	}
	if len(result) == 0 {
		return []string{"X25519"}
	}
	return result
}

func containsVersion(versions []string, v string) bool {
	for _, ver := range versions {
		if ver == v {
			return true
		}
	}
	return false
}

func hasTLS13Ciphers(ja3String string) bool {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 2 {
		return false
	}
	for _, c := range strings.Split(parts[1], "-") {
		if c == "4865" || c == "4866" || c == "4867" {
			return true
		}
	}
	return false
}

func containsExtensionID(ja3String, extID string) bool {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 3 {
		return false
	}
	for _, e := range strings.Split(parts[2], "-") {
		if e == extID {
			return true
		}
	}
	return false
}

func inferALPS(alpn []string) []string {
	for _, p := range alpn {
		if p == "h2" {
			return []string{"h2"}
		}
	}
	return nil
}

func inferCertCompression(ja3String string) []string {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 3 {
		return nil
	}
	for _, ext := range strings.Split(parts[2], "-") {
		if ext == "27" {
			return []string{"brotli"}
		}
	}
	return nil
}

func countJA3Ciphers(ja3String string) int {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 2 || parts[1] == "" {
		return 0
	}
	return len(strings.Split(parts[1], "-"))
}

func mapH2Settings(tmpl *Template) (map[http2.SettingID]uint32, []http2.SettingID) {
	if len(tmpl.H2Settings) == 0 {
		return nil, nil
	}

	settings := make(map[http2.SettingID]uint32, len(tmpl.H2Settings))
	for key, val := range tmpl.H2Settings {
		if id, ok := tls_client.H2SettingsMap[key]; ok {
			settings[id] = val
		}
	}

	var order []http2.SettingID
	for _, key := range tmpl.H2SettingsOrder {
		if id, ok := tls_client.H2SettingsMap[key]; ok {
			order = append(order, id)
		}
	}

	return settings, order
}
