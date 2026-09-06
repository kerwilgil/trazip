package lan

import "testing"

func TestInterfaces(t *testing.T) {
	// Every host has at least a loopback interface.
	ifs := Interfaces()
	if len(ifs) == 0 {
		t.Fatal("expected at least one interface")
	}
	found := false
	for _, it := range ifs {
		if it.Loopback {
			found = true
		}
	}
	if !found {
		t.Error("no loopback interface found")
	}
}

func TestVendor(t *testing.T) {
	cases := map[string]string{
		"B8:27:EB:12:34:56": "Raspberry Pi",
		"b827eb123456":      "Raspberry Pi",
		"50-C7-BF-00-11-22": "TP-Link",
		"FF:FF:FF:00:00:00": "",
	}
	for mac, want := range cases {
		if got := Vendor(mac); got != want {
			t.Errorf("Vendor(%q) = %q, want %q", mac, got, want)
		}
	}
	if Vendor("aa") != "" {
		t.Error("short MAC should yield empty vendor")
	}
}

func TestDiscover(t *testing.T) {
	// Should not panic and should return interfaces.
	r := Discover()
	if len(r.Interfaces) == 0 {
		t.Error("Discover returned no interfaces")
	}
}
