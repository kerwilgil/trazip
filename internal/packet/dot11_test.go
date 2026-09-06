package packet

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestWiFiChannelFromFrequency(t *testing.T) {
	for mhz, want := range map[int]int{2412: 1, 2484: 14, 5180: 36, 5955: 1, 6115: 33, 1234: 0} {
		if got := wifiChannelFromFrequency(mhz); got != want {
			t.Errorf("wifiChannelFromFrequency(%d) = %d, want %d", mhz, got, want)
		}
	}
}

func TestDataFrameBSSIDFollowsDSFlags(t *testing.T) {
	a1 := net.HardwareAddr{1, 1, 1, 1, 1, 1}
	a2 := net.HardwareAddr{2, 2, 2, 2, 2, 2}
	a3 := net.HardwareAddr{3, 3, 3, 3, 3, 3}
	for _, tc := range []struct {
		name  string
		flags byte
		want  string
	}{
		{"independent", 0, a3.String()},
		{"to-ds", 1, a1.String()},
		{"from-ds", 2, a2.String()},
		{"wds", 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := []byte{0x08, tc.flags, 0, 0}
			frame = append(frame, a1...)
			frame = append(frame, a2...)
			frame = append(frame, a3...)
			frame = append(frame, 0, 0, 0, 0, 0, 0) // sequence + placeholder FCS
			p := gopacket.NewPacket(frame, layers.LayerTypeDot11, gopacket.Default)
			var s Summary
			summarizeDot11(&s, p)
			if s.BSSID != tc.want {
				t.Fatalf("BSSID = %q, want %q", s.BSSID, tc.want)
			}
		})
	}
}
