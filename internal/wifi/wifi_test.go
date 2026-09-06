package wifi

import "testing"

func TestChannelFromFrequencyKHz(t *testing.T) {
	cases := []struct {
		khz  uint32
		want int
	}{
		{2412000, 1},   // channel 1
		{2437000, 6},   // channel 6
		{2472000, 13},  // channel 13
		{2484000, 14},  // channel 14 (Japan)
		{5180000, 36},  // channel 36 (5 GHz)
		{5825000, 165}, // channel 165 (5 GHz)
		{5955000, 1},   // channel 1 (6 GHz)
		{6415000, 93},  // channel 93 (6 GHz)
		{900000, 0},    // unrecognized band
	}
	for _, c := range cases {
		if got := channelFromFrequencyKHz(c.khz); got != c.want {
			t.Errorf("channelFromFrequencyKHz(%d) = %d, want %d", c.khz, got, c.want)
		}
	}
}

func TestBandFromFrequencyKHz(t *testing.T) {
	cases := []struct {
		khz  uint32
		want string
	}{
		{2412000, "2.4 GHz"},
		{2484000, "2.4 GHz"},
		{5180000, "5 GHz"},
		{5825000, "5 GHz"},
		{5955000, "6 GHz"}, // 6 GHz channel 1 — same channel number as 2.4 GHz channel 1
		{6415000, "6 GHz"},
		{900000, ""},
	}
	for _, c := range cases {
		if got := bandFromFrequencyKHz(c.khz); got != c.want {
			t.Errorf("bandFromFrequencyKHz(%d) = %q, want %q", c.khz, got, c.want)
		}
	}
}

func TestAuthAlgorithmString(t *testing.T) {
	if got := authAlgorithmString(1); got != "Abierta" {
		t.Errorf("authAlgorithmString(1) = %q, want Abierta", got)
	}
	if got := authAlgorithmString(7); got != "WPA2-PSK" {
		t.Errorf("authAlgorithmString(7) = %q, want WPA2-PSK", got)
	}
	if got := authAlgorithmString(999); got == "" {
		t.Error("authAlgorithmString for an unknown value should not be empty")
	}
}

func TestCipherAlgorithmString(t *testing.T) {
	if got := cipherAlgorithmString(0x04); got != "CCMP (AES)" {
		t.Errorf("cipherAlgorithmString(0x04) = %q, want CCMP (AES)", got)
	}
	if got := cipherAlgorithmString(0xFFFF); got == "" {
		t.Error("cipherAlgorithmString for an unknown value should not be empty")
	}
}

func TestSecurityLabel(t *testing.T) {
	if got := securityLabel(false, 0, 0); got != "Abierta" {
		t.Errorf("securityLabel(unsecured) = %q, want Abierta", got)
	}
	got := securityLabel(true, 7, 0x04)
	if got != "WPA2-PSK / CCMP (AES)" {
		t.Errorf("securityLabel(WPA2-PSK,CCMP) = %q", got)
	}
}
