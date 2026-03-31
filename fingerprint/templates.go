package fingerprint

type Template struct {
	Name string

	JA3String                      string
	SupportedSignatureAlgorithms   []string
	DelegatedCredentialsAlgorithms []string
	SupportedVersions              []string
	KeyShareCurves                 []string
	ALPNProtocols                  []string
	CertCompressionAlgorithms      []string
	RecordSizeLimit                uint16

	H2Settings        map[string]uint32
	H2SettingsOrder   []string
	PseudoHeaderOrder []string
	ConnectionFlow    uint32

	H3Settings          map[uint64]uint64
	H3SettingsOrder     []uint64
	H3PseudoHeaderOrder []string
}

var Registry = map[string]*Template{
	"okhttp4": {
		Name: "okhttp4",
		JA3String: "771," +
			"4865-4866-4867-49195-49196-52393-49199-49200-52392," +
			"0-23-65281-10-11-35-16-5-13-51-45-43-21," +
			"29-23-24," +
			"0",
		SupportedSignatureAlgorithms: []string{
			"ECDSAWithP256AndSHA256", "PSSWithSHA256", "PKCS1WithSHA256",
			"ECDSAWithP384AndSHA384", "PSSWithSHA384", "PKCS1WithSHA384",
			"PSSWithSHA512", "PKCS1WithSHA512", "PKCS1WithSHA1",
		},
		SupportedVersions: []string{"1.3", "1.2"},
		KeyShareCurves:    []string{"X25519"},
		ALPNProtocols:     []string{"h2", "http/1.1"},
		H2Settings: map[string]uint32{
			"HEADER_TABLE_SIZE":      65536,
			"MAX_CONCURRENT_STREAMS": 1000,
			"INITIAL_WINDOW_SIZE":    6291456,
			"MAX_HEADER_LIST_SIZE":   262144,
		},
		H2SettingsOrder: []string{
			"HEADER_TABLE_SIZE", "MAX_CONCURRENT_STREAMS",
			"INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE",
		},
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		ConnectionFlow:    15663105,
	},
}

func Get(name string) *Template {
	return Registry[name]
}

func Names() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	return names
}
