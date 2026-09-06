// Package wifi discovers nearby WiFi networks via Windows' native WLAN API
// (WlanGetAvailableNetworkList / WlanGetNetworkBssList) — the same
// "available networks" data Windows' own WiFi picker reads, no monitor mode
// and no special hardware required. This is the portable, always-working
// alternative to raw 802.11 capture (see internal/capture's monitorMode
// support, which only works on adapters/drivers that expose it — most
// don't; CONTEXT-trazip.md has the full explanation of why).
package wifi

import "fmt"

// Network is one nearby WiFi network — every access point (BSSID)
// broadcasting the same SSID is merged into one entry, keeping the
// strongest signal's BSSID/RSSI/channel as representative.
type Network struct {
	SSID        string `json:"ssid"`
	BSSID       string `json:"bssid,omitempty"`
	SignalPct   int    `json:"signalPct"`
	RSSIdBm     int    `json:"rssiDbm,omitempty"`
	Channel     int    `json:"channel,omitempty"`
	Band        string `json:"band,omitempty"` // "2.4 GHz" | "5 GHz" | "6 GHz"
	Security    string `json:"security"`
	Connectable bool   `json:"connectable"`
	APCount     int    `json:"apCount"`
}

// IfaceStatus reports whether a WLAN interface is currently associated to a
// network — used to tell the operator "your WiFi isn't connected, there's no
// traffic to capture" instead of leaving them staring at an empty capture.
type IfaceStatus struct {
	Description string `json:"description"`
	Connected   bool   `json:"connected"`
	SSID        string `json:"ssid,omitempty"`
}

// channelFromFrequencyKHz converts a center frequency (as reported by
// WLAN_BSS_ENTRY.ulChCenterFrequency, in kHz) to a WiFi channel number
// across the 2.4/5/6 GHz bands. Returns 0 for anything unrecognized.
func channelFromFrequencyKHz(khz uint32) int {
	mhz := khz / 1000
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return int((mhz-2412)/5) + 1
	case mhz >= 5955 && mhz < 7115: // 6 GHz (WiFi 6E/7)
		return int((mhz-5955)/5) + 1
	case mhz >= 5000 && mhz < 5900:
		return int((mhz - 5000) / 5)
	default:
		return 0
	}
}

// bandFromFrequencyKHz labels the WiFi band for a center frequency. Channel
// numbers alone are ambiguous across bands (2.4 GHz channel 1 and 6 GHz
// channel 1 are different frequencies), so the band travels alongside the
// channel for anything that reasons about congestion.
func bandFromFrequencyKHz(khz uint32) string {
	mhz := khz / 1000
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4 GHz"
	case mhz >= 5955 && mhz < 7115:
		return "6 GHz"
	case mhz >= 5000 && mhz < 5900:
		return "5 GHz"
	default:
		return ""
	}
}

// authAlgorithmString labels DOT11_AUTH_ALGORITHM values. Anything past
// WPA3-SAE is reported with its raw numeric value rather than guessed at —
// newer auth types get added to Windows over time and a wrong guess is
// worse than an honest "otra (N)".
func authAlgorithmString(a uint32) string {
	switch a {
	case 1:
		return "Abierta"
	case 2:
		return "Clave compartida"
	case 3:
		return "WPA"
	case 4:
		return "WPA-PSK"
	case 5:
		return "WPA-None"
	case 6:
		return "WPA2 (RSNA)"
	case 7:
		return "WPA2-PSK"
	case 8:
		return "WPA3"
	case 9:
		return "WPA3-SAE"
	default:
		return fmt.Sprintf("otra (%d)", a)
	}
}

func cipherAlgorithmString(c uint32) string {
	switch c {
	case 0x00:
		return "ninguno"
	case 0x01:
		return "WEP40"
	case 0x02:
		return "TKIP"
	case 0x04:
		return "CCMP (AES)"
	case 0x05:
		return "WEP104"
	case 0x100:
		return "cifrado de grupo"
	case 0x101:
		return "WEP"
	default:
		return fmt.Sprintf("otro (%#x)", c)
	}
}

func securityLabel(enabled bool, auth, cipher uint32) string {
	if !enabled {
		return "Abierta"
	}
	return authAlgorithmString(auth) + " / " + cipherAlgorithmString(cipher)
}
