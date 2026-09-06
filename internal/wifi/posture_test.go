package wifi

import (
	"path/filepath"
	"testing"
)

func TestPostureDetectsOpenAndNewBSSID(t *testing.T) {
	s := NewPostureStore(filepath.Join(t.TempDir(), "wifi.json"))
	r, e := s.Assess([]Network{{SSID: "Lab", BSSID: "00:11:22:33:44:55", Security: "WPA2-PSK / CCMP (AES)"}})
	if e != nil || !r.BaselineCreated {
		t.Fatalf("baseline %+v %v", r, e)
	}
	r, e = s.Assess([]Network{{SSID: "Guest", BSSID: "AA:BB:CC:DD:EE:FF", Security: "Abierta"}})
	if e != nil || r.Score >= 100 || len(r.Findings) < 2 {
		t.Fatalf("assessment %+v %v", r, e)
	}
}
