package fingerprint

import (
	"io"
	"strconv"
	"strings"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

const (
	chromeTrustAnchorsJA3 = "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"18-27-5-16-0-65037-13-23-65281-51-10-43-45-35-51764-17613-11," +
		"4588-29-23-24,0"

	chromeTrustAnchorsJA4R = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9" +
		"_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01" +
		"_4a4a,0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
)

func TestUnbuildableExtensionIsCarried(t *testing.T) {
	factory, _, err := rawSpecFactory(chromeTrustAnchorsJA3, chromeTrustAnchorsJA4R, Plan{})
	if err != nil {
		t.Fatalf("rawSpecFactory: %v", err)
	}

	spec, err := factory()
	if err != nil {
		t.Fatalf("spec factory: %v", err)
	}

	want := splitFields(strings.Split(chromeTrustAnchorsJA3, ",")[2])
	if len(spec.Extensions) != len(want) {
		t.Fatalf("built %d extensions, want %d", len(spec.Extensions), len(want))
	}

	idx := -1
	for i, e := range want {
		if e == "51764" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("test fixture no longer contains 51764")
	}

	generic, ok := spec.Extensions[idx].(*tls.GenericExtension)
	if !ok {
		t.Fatalf("extension at index %d is %T, want *tls.GenericExtension", idx, spec.Extensions[idx])
	}
	if generic.Id != 0xCA34 {
		t.Errorf("carried extension id = 0x%04X, want 0xCA34", generic.Id)
	}

	if got := generic.Data; len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Errorf("trust_anchors body = %x, want 0000", got)
	}
}

func TestUnbuildableExtensionKeepsOrder(t *testing.T) {
	factory, _, err := rawSpecFactory(chromeTrustAnchorsJA3, chromeTrustAnchorsJA4R, Plan{})
	if err != nil {
		t.Fatalf("rawSpecFactory: %v", err)
	}
	spec, err := factory()
	if err != nil {
		t.Fatalf("spec factory: %v", err)
	}

	want := splitFields(strings.Split(chromeTrustAnchorsJA3, ",")[2])
	for i, e := range want {
		id, convErr := strconv.ParseUint(e, 10, 16)
		if convErr != nil {
			t.Fatalf("fixture extension %q: %v", e, convErr)
		}
		if got := extensionID(spec.Extensions[i]); got != uint16(id) {
			t.Errorf("position %d holds 0x%04X, want 0x%04X (%s)", i, got, id, e)
		}
	}
}

func TestUnknownExtensionID(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want uint16
		ok   bool
	}{
		{"builder refusal", errString("unknown extension with id 51764 provided"), 0xCA34, true},
		{"unrelated failure", errString("dial tcp: i/o timeout"), 0, false},
		{"no error", nil, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := unknownExtensionID(tc.err)
			if got != tc.want || ok != tc.ok {
				t.Errorf("unknownExtensionID() = (0x%04X, %v), want (0x%04X, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func extensionID(e tls.TLSExtension) uint16 {
	if g, ok := e.(*tls.GenericExtension); ok {
		return g.Id
	}
	buf := make([]byte, e.Len())
	if _, err := e.Read(buf); err != nil && err != io.EOF {
		return 0
	}
	if len(buf) < 2 {
		return 0
	}
	return uint16(buf[0])<<8 | uint16(buf[1])
}
