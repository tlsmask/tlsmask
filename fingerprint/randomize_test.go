package fingerprint

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

const (
	chromeJA3 = "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"43-5-27-11-51-18-65281-16-23-17613-10-45-13-35-0-65037," +
		"4588-29-23-24,0"

	chromeJA4R = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9" +
		"_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01" +
		"_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"

	okhttpJA3 = "771,4865-4866-4867-49195-49196-52393-49199-49200-52392," +
		"0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0"
)

func TestDetectBrowser(t *testing.T) {
	tests := []struct {
		name string
		ja3  string
		want string
	}{
		{"chrome via ALPS", chromeJA3, BrowserChrome},
		{"chrome via legacy ALPS", "771,4865,0-17513-10,29,0", BrowserChrome},
		{"firefox via delegated credentials", "771,4865,0-34-10,29,0", BrowserFirefox},
		{"firefox via record size limit", "771,4865,0-28-10,29,0", BrowserFirefox},
		{"okhttp is not a browser", okhttpJA3, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectBrowser(tc.ja3); got != tc.want {
				t.Errorf("DetectBrowser() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfigPlan(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		ja3         string
		wantBrowser string
		wantShuffle bool
		wantGREASE  bool
	}{
		{"auto on chrome", Config{Mode: ModeAuto}, chromeJA3, BrowserChrome, true, true},
		{"auto on okhttp stays deterministic", Config{Mode: ModeAuto}, okhttpJA3, "", false, false},
		{"zero value behaves as auto", Config{}, chromeJA3, BrowserChrome, true, true},
		{"off wins over detection", Config{Mode: ModeOff}, chromeJA3, "", false, false},
		{"forced chrome on okhttp", Config{Mode: ModeChrome}, okhttpJA3, BrowserChrome, true, true},
		{"firefox never randomizes", Config{Mode: ModeFirefox}, chromeJA3, BrowserFirefox, false, false},
		{"no-grease keeps the shuffle", Config{Mode: ModeChrome, DisableGREASE: true}, chromeJA3, BrowserChrome, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Plan(tc.ja3)
			if got.Browser != tc.wantBrowser || got.ShuffleExtensions != tc.wantShuffle || got.GREASE != tc.wantGREASE {
				t.Errorf("Plan() = %+v, want browser=%q shuffle=%v grease=%v",
					got, tc.wantBrowser, tc.wantShuffle, tc.wantGREASE)
			}
		})
	}
}

func TestPlanDescribe(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		ja3  string
		want string
	}{
		{"chrome", Config{Mode: ModeAuto}, chromeJA3, "chrome (extension permutation + GREASE)"},
		{"chrome without grease", Config{Mode: ModeAuto, DisableGREASE: true}, chromeJA3, "chrome (extension permutation)"},
		{"firefox", Config{Mode: ModeFirefox}, chromeJA3, "firefox (deterministic by design)"},
		{"explicitly off", Config{Mode: ModeOff}, chromeJA3, "off"},
		{"auto on a non-browser", Config{Mode: ModeAuto}, okhttpJA3, "off (fingerprint is not a browser)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Plan(tc.ja3).Describe(); got != tc.want {
				t.Errorf("Describe() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGreaseJA3(t *testing.T) {
	got := GreaseJA3(chromeJA3)
	parts := strings.Split(got, ",")

	ciphers := strings.Split(parts[1], "-")
	if ciphers[0] != extGREASE {
		t.Errorf("first cipher = %q, want GREASE", ciphers[0])
	}

	exts := strings.Split(parts[2], "-")
	if exts[0] != extGREASE || exts[len(exts)-1] != extGREASE {
		t.Errorf("extension list = %v, want GREASE first and last", exts)
	}

	curves := strings.Split(parts[3], "-")
	if curves[0] != extGREASE {
		t.Errorf("first curve = %q, want GREASE", curves[0])
	}

	if stripped := stripGREASEFromJA3(got); stripped != chromeJA3 {
		t.Errorf("GREASE-stripped result = %q, want %q", stripped, chromeJA3)
	}
}

func TestGreaseJA3PaddingStaysLast(t *testing.T) {
	got := GreaseJA3(okhttpJA3)
	exts := strings.Split(strings.Split(got, ",")[2], "-")

	if last, beforeLast := exts[len(exts)-1], exts[len(exts)-2]; last != extPadding || beforeLast != extGREASE {
		t.Errorf("extension tail = [%s %s], want [GREASE padding]", beforeLast, last)
	}
}

func TestGreaseJA3IsIdempotent(t *testing.T) {
	once := GreaseJA3(chromeJA3)
	if twice := GreaseJA3(once); twice != once {
		t.Errorf("GreaseJA3 applied twice = %q, want %q", twice, once)
	}
}

func TestClientHelloVariesPerConnection(t *testing.T) {
	plan := Config{Mode: ModeAuto}.Plan(chromeJA3)
	if !plan.Active() {
		t.Fatal("expected the Chrome fingerprint to be randomized")
	}

	const rounds = 12
	orders := make(map[string]int, rounds)
	wantExtSet := sortedFields(strings.Split(chromeJA3, ",")[2])

	for i := 0; i < rounds; i++ {
		hello := buildClientHello(t, plan)

		orders[strings.Join(hello.extensions, "-")]++

		if n := len(hello.extensions); !isGREASEField(hello.extensions[0]) || !isGREASEField(hello.extensions[n-1]) {
			t.Fatalf("round %d: extensions = %v, want GREASE at both ends", i, hello.extensions)
		}
		if !isGREASEField(hello.ciphers[0]) {
			t.Fatalf("round %d: ciphers = %v, want GREASE first", i, hello.ciphers)
		}

		if got := sortedFields(strings.Join(dropGREASE(hello.extensions), "-")); got != wantExtSet {
			t.Fatalf("round %d: extension set = %q, want %q", i, got, wantExtSet)
		}
		if got, want := strings.Join(dropGREASE(hello.ciphers), "-"), strings.Split(chromeJA3, ",")[1]; got != want {
			t.Fatalf("round %d: ciphers = %q, want %q (order must stay fixed)", i, got, want)
		}
	}

	if len(orders) < 2 {
		t.Errorf("extension order never changed across %d handshakes: %v", rounds, orders)
	}
}

func TestClientHelloStableWhenRandomizationOff(t *testing.T) {
	plan := Config{Mode: ModeOff}.Plan(chromeJA3)

	first := buildClientHello(t, plan)
	for i := 0; i < 5; i++ {
		next := buildClientHello(t, plan)
		if strings.Join(next.extensions, "-") != strings.Join(first.extensions, "-") {
			t.Fatalf("round %d: extension order changed with --randomize off", i)
		}
	}

	if strings.Join(first.extensions, "-") != strings.Split(chromeJA3, ",")[2] {
		t.Errorf("extensions = %v, want the JA3 order verbatim", first.extensions)
	}
}

type parsedHello struct {
	ciphers    []string
	extensions []string
}

func buildClientHello(t *testing.T, plan Plan) parsedHello {
	t.Helper()

	specFactory, _, err := rawSpecFactory(chromeJA3, chromeJA4R, plan)
	if err != nil {
		t.Fatalf("rawSpecFactory: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uconn := tls.UClient(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true},
		tls.ClientHelloID{Client: "tlsmask", Version: "custom", SpecFactory: specFactory},
		plan.ShuffleExtensions, false, false)
	defer uconn.Close()

	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	hello, err := parseClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	return hello
}

func parseClientHello(raw []byte) (parsedHello, error) {
	var out parsedHello

	p := 4 + 2 + 32
	if len(raw) < p+1 {
		return out, errTruncated
	}

	p += 1 + int(raw[p])
	if len(raw) < p+2 {
		return out, errTruncated
	}

	cipherLen := int(binary.BigEndian.Uint16(raw[p:]))
	p += 2
	if len(raw) < p+cipherLen {
		return out, errTruncated
	}
	for i := 0; i+1 < cipherLen; i += 2 {
		out.ciphers = append(out.ciphers, strconv.Itoa(int(binary.BigEndian.Uint16(raw[p+i:]))))
	}
	p += cipherLen

	if len(raw) < p+1 {
		return out, errTruncated
	}
	p += 1 + int(raw[p])

	if len(raw) < p+2 {
		return out, errTruncated
	}
	extLen := int(binary.BigEndian.Uint16(raw[p:]))
	p += 2
	end := p + extLen
	if len(raw) < end {
		return out, errTruncated
	}
	for p+4 <= end {
		out.extensions = append(out.extensions, strconv.Itoa(int(binary.BigEndian.Uint16(raw[p:]))))
		p += 4 + int(binary.BigEndian.Uint16(raw[p+2:]))
	}

	return out, nil
}

var errTruncated = errorString("truncated ClientHello")

type errorString string

func (e errorString) Error() string { return string(e) }

func isGREASEField(s string) bool {
	v, err := strconv.ParseUint(s, 10, 16)
	return err == nil && isGREASEValue(uint16(v))
}

func dropGREASE(fields []string) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if !isGREASEField(f) {
			out = append(out, f)
		}
	}
	return out
}

func sortedFields(list string) string {
	fields := append([]string(nil), strings.Split(list, "-")...)
	for i := 1; i < len(fields); i++ {
		for j := i; j > 0 && numLess(fields[j], fields[j-1]); j-- {
			fields[j], fields[j-1] = fields[j-1], fields[j]
		}
	}
	return strings.Join(fields, "-")
}

func numLess(a, b string) bool {
	av, _ := strconv.Atoi(a)
	bv, _ := strconv.Atoi(b)
	return av < bv
}

func stripGREASEFromJA3(ja3 string) string {
	parts := strings.Split(ja3, ",")
	for _, idx := range []int{1, 2, 3} {
		parts[idx] = strings.Join(dropGREASE(strings.Split(parts[idx], "-")), "-")
	}
	return strings.Join(parts, ",")
}
