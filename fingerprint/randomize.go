package fingerprint

import (
	"fmt"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeOff Mode = "off"

	ModeAuto Mode = "auto"

	ModeChrome Mode = "chrome"

	ModeFirefox Mode = "firefox"
)

const (
	BrowserChrome  = "chrome"
	BrowserFirefox = "firefox"
)

const (
	extALPS            = "17613"
	extALPSOld         = "17513"
	extRecordSizeLimit = "28"
	extDelegatedCreds  = "34"
	extPadding         = "21"
	extGREASE          = "2570"
)

func ModeNames() []string {
	return []string{string(ModeOff), string(ModeAuto), string(ModeChrome), string(ModeFirefox)}
}

func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case ModeOff, ModeAuto, ModeChrome, ModeFirefox:
		return m, nil
	default:
		return "", fmt.Errorf("unknown randomize mode %q, expected one of: %s", s, strings.Join(ModeNames(), ", "))
	}
}

type Config struct {
	Mode          Mode
	DisableGREASE bool
}

type Plan struct {
	Mode Mode

	Browser string

	ShuffleExtensions bool

	GREASE bool
}

func (c Config) Plan(ja3String string) Plan {
	mode := c.Mode
	if mode == "" {
		mode = ModeAuto
	}

	var browser string
	switch mode {
	case ModeOff:
		return Plan{Mode: ModeOff}
	case ModeChrome:
		browser = BrowserChrome
	case ModeFirefox:
		browser = BrowserFirefox
	default:
		browser = DetectBrowser(ja3String)
	}

	plan := Plan{Mode: mode, Browser: browser}
	switch browser {
	case BrowserChrome:
		plan.ShuffleExtensions = true
		plan.GREASE = !c.DisableGREASE
	case BrowserFirefox:
	}
	return plan
}

func (p Plan) Active() bool { return p.ShuffleExtensions || p.GREASE }

func (p Plan) Describe() string {
	switch {
	case p.Mode == ModeOff:
		return "off"
	case p.Browser == "":
		return "off (fingerprint is not a browser)"
	}

	var on []string
	if p.ShuffleExtensions {
		on = append(on, "extension permutation")
	}
	if p.GREASE {
		on = append(on, "GREASE")
	}
	if len(on) == 0 {
		return p.Browser + " (deterministic by design)"
	}
	return fmt.Sprintf("%s (%s)", p.Browser, strings.Join(on, " + "))
}

func DetectBrowser(ja3String string) string {
	switch {
	case containsExtensionID(ja3String, extALPS), containsExtensionID(ja3String, extALPSOld):
		return BrowserChrome
	case containsExtensionID(ja3String, extDelegatedCreds), containsExtensionID(ja3String, extRecordSizeLimit):
		return BrowserFirefox
	}
	return ""
}

func GreaseJA3(ja3String string) string {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 5 || hasGREASE(parts) {
		return ja3String
	}

	parts[1] = prependField(parts[1], extGREASE)
	parts[2] = greaseExtensionList(parts[2])
	parts[3] = prependField(parts[3], extGREASE)
	return strings.Join(parts, ",")
}

func GreaseKeyShareCurves(curves []string) []string {
	if len(curves) == 0 || curves[0] == "GREASE" {
		return curves
	}
	return append([]string{"GREASE"}, curves...)
}

func greaseExtensionList(extensions string) string {
	fields := splitFields(extensions)
	if len(fields) == 0 {
		return extensions
	}

	out := append([]string{extGREASE}, fields...)
	if last := len(out) - 1; out[last] == extPadding {
		out = append(out[:last], extGREASE, extPadding)
	} else {
		out = append(out, extGREASE)
	}
	return strings.Join(out, "-")
}

func prependField(field, value string) string {
	if field == "" {
		return value
	}
	return value + "-" + field
}

func splitFields(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "-")
}

func hasGREASE(parts []string) bool {
	for _, idx := range []int{1, 2, 3} {
		if idx >= len(parts) {
			break
		}
		for _, field := range splitFields(parts[idx]) {
			v, err := strconv.ParseUint(field, 10, 16)
			if err != nil {
				continue
			}
			if isGREASEValue(uint16(v)) {
				return true
			}
		}
	}
	return false
}

func isGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}
