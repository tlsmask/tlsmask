package fingerprint

import (
	"fmt"
	"strings"

	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

func BuildClient(tmpl *Template, proxyURL string) (tls_client.HttpClient, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("template is nil")
	}

	specFactory, err := tls_client.GetSpecFactoryFromJa3String(
		tmpl.JA3String,
		tmpl.SupportedSignatureAlgorithms,
		tmpl.DelegatedCredentialsAlgorithms,
		tmpl.SupportedVersions,
		tmpl.KeyShareCurves,
		tmpl.ALPNProtocols,
		nil, nil, nil,
		tmpl.CertCompressionAlgorithms,
		tmpl.RecordSizeLimit,
	)
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

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTimeoutSeconds(30),
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}

	return tls_client.NewHttpClient(nil, options...)
}

func BuildClientFromRaw(ja3String, ja4rString, proxyURL string) (tls_client.HttpClient, string, error) {
	ja4r, err := ParseJA4R(ja4rString)
	if err != nil {
		return nil, "", fmt.Errorf("parse JA4_r: %w", err)
	}

	sigAlgs := ja4r.SignatureAlgorithmsHex
	alpn := ja4r.ALPNProtocols()
	versions := ja4r.SupportedVersions()

	if hasTLS13Ciphers(ja3String) && !containsVersion(versions, "1.3") {
		versions = []string{"1.3", "1.2"}
	}

	keyShareCurves := inferKeyShareCurves(ja3String, ja4r.TLSVersion)
	certCompression := inferCertCompression(ja3String)

	specFactory, err := tls_client.GetSpecFactoryFromJa3String(
		ja3String, sigAlgs, nil, versions, keyShareCurves, alpn,
		nil, nil, nil, certCompression, 0,
	)
	if err != nil {
		return nil, "", fmt.Errorf("build spec from JA3+JA4_r: %w", err)
	}

	clientHelloID := tls.ClientHelloID{
		Client:      "tlsmask",
		Version:     "custom",
		SpecFactory: specFactory,
	}

	h2Settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams:  1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	}
	h2SettingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}

	profile := profiles.NewClientProfile(
		clientHelloID,
		h2Settings, h2SettingsOrder,
		[]string{":method", ":authority", ":scheme", ":path"},
		15663105,
		nil, nil, 0, false,
		nil, nil, 0, nil, false,
	)

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTimeoutSeconds(30),
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		return nil, "", fmt.Errorf("create HTTP client: %w", err)
	}

	displayName := fmt.Sprintf("custom (TLS %s, %s, %d ciphers, %d sig_algs)",
		ja4r.TLSVersion, ja4r.ALPN, countJA3Ciphers(ja3String), len(sigAlgs))

	return client, displayName, nil
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
	if name, ok := curveMap[curves[0]]; ok {
		return []string{name}
	}
	return []string{"X25519"}
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
