package fingerprint

import (
	"fmt"
	"strings"
	"testing"
)

func settingsString(ja3 string) string {
	values, order := rawH2Settings(ja3)
	parts := make([]string, 0, len(order))
	for _, id := range order {
		parts = append(parts, fmt.Sprintf("%d:%d", id, values[id]))
	}
	return strings.Join(parts, ";")
}

func TestRawH2SettingsFollowTheBrowser(t *testing.T) {
	chrome := "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613,29-23-24,0"
	if got, want := settingsString(chrome), "1:65536;2:0;4:6291456;6:262144"; got != want {
		t.Errorf("Chrome SETTINGS = %s, want %s (measured from a real browser)", got, want)
	}

	other := "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0"
	if got, want := settingsString(other), "1:65536;3:1000;4:6291456;6:262144"; got != want {
		t.Errorf("non-browser SETTINGS = %s, want %s", got, want)
	}
}
