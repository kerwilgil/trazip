//go:build darwin

package wifi

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// macOS dropped the airport CLI (14.4+) and CoreWLAN needs cgo + Location
// entitlements, so the scanner reads system_profiler SPAirPortDataType -json:
// stable, sandbox-friendly and available on every Mac. One privacy caveat:
// without Location Services permission for the app, macOS reports foreign
// SSIDs as "<redacted>" — channel, band, security and signal still come
// through, so posture assessment keeps working.
func Available() bool { return true }

type spRoot struct {
	SPAirPortDataType []struct {
		Interfaces []spInterface `json:"spairport_airport_interfaces"`
	} `json:"SPAirPortDataType"`
}

type spInterface struct {
	Name          string      `json:"_name"`
	Status        string      `json:"spairport_status_information"`
	CurrentNet    *spNetwork  `json:"spairport_current_network_information"`
	OtherNetworks []spNetwork `json:"spairport_airport_other_local_wireless_networks"`
}

type spNetwork struct {
	Name        string `json:"_name"`
	Channel     string `json:"spairport_network_channel"` // "149 (5GHz, 80MHz)"
	Security    string `json:"spairport_security_mode"`   // "spairport_security_mode_wpa2_personal"
	SignalNoise string `json:"spairport_signal_noise"`    // "-75 dBm / -90 dBm"
}

func profilerData() (*spRoot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/system_profiler", "SPAirPortDataType", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler SPAirPortDataType: %w", err)
	}
	var root spRoot
	if err := json.Unmarshal(out, &root); err != nil {
		return nil, fmt.Errorf("parseando salida de system_profiler: %w", err)
	}
	return &root, nil
}

// Scan lists visible networks across all WLAN interfaces, deduplicated by
// SSID keeping the strongest signal (APCount counts the BSSIDs merged, same
// as the Windows scanner).
func Scan() ([]Network, error) {
	root, err := profilerData()
	if err != nil {
		return nil, err
	}
	var networks []Network
	bySSID := map[string]int{}
	add := func(sp spNetwork, connected bool) {
		if sp.Name == "" {
			return
		}
		n := Network{
			SSID:        sp.Name,
			SignalPct:   signalPctFromRSSI(parseRSSI(sp.SignalNoise)),
			RSSIdBm:     parseRSSI(sp.SignalNoise),
			Channel:     parseChannel(sp.Channel),
			Band:        bandFromChannelString(sp.Channel),
			Security:    securityLabelDarwin(sp.Security),
			Connectable: true,
			APCount:     1,
		}
		if connected && n.SignalPct == 0 {
			n.SignalPct = 100 // current network omits signal_noise on some builds
		}
		// Without Location permission macOS reports every foreign SSID as
		// "<redacted>"; merging those would collapse distinct networks and
		// starve the channel-recommendation feature, so they stay separate.
		if idx, ok := bySSID[n.SSID]; ok && n.SSID != "<redacted>" {
			networks[idx].APCount++
			if n.RSSIdBm != 0 && (networks[idx].RSSIdBm == 0 || n.RSSIdBm > networks[idx].RSSIdBm) {
				sig, ap := networks[idx].SignalPct, networks[idx].APCount
				networks[idx] = n
				networks[idx].APCount = ap
				if n.SignalPct == 0 {
					networks[idx].SignalPct = sig
				}
			}
			return
		}
		networks = append(networks, n)
		bySSID[n.SSID] = len(networks) - 1
	}
	for _, data := range root.SPAirPortDataType {
		for _, iface := range data.Interfaces {
			if iface.CurrentNet != nil {
				add(*iface.CurrentNet, true)
			}
			for _, other := range iface.OtherNetworks {
				add(other, false)
			}
		}
	}
	return networks, nil
}

// Status reports association state per WLAN interface.
func Status() ([]IfaceStatus, error) {
	root, err := profilerData()
	if err != nil {
		return nil, nil // same contract as the stub: no interfaces, no error → UI omits the hint
	}
	var out []IfaceStatus
	for _, data := range root.SPAirPortDataType {
		for _, iface := range data.Interfaces {
			st := IfaceStatus{Description: iface.Name}
			if strings.Contains(iface.Status, "connected") && iface.CurrentNet != nil {
				st.Connected = true
				st.SSID = iface.CurrentNet.Name
			}
			out = append(out, st)
		}
	}
	return out, nil
}

// parseRSSI extracts the signal part of "-75 dBm / -90 dBm". Returns 0 when absent.
func parseRSSI(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0
	}
	return v
}

// signalPctFromRSSI maps RSSI to the 0-100 scale the Windows WLAN API reports
// natively: −50 dBm or better → 100, −100 dBm → 0, linear in between.
func signalPctFromRSSI(rssi int) int {
	if rssi == 0 {
		return 0
	}
	pct := 2 * (rssi + 100)
	if pct > 100 {
		pct = 100
	}
	if pct < 0 {
		pct = 0
	}
	return pct
}

// parseChannel extracts the leading channel number of "149 (5GHz, 80MHz)".
func parseChannel(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.Atoi(fields[0])
	return v
}

func bandFromChannelString(s string) string {
	switch {
	case strings.Contains(s, "(2GHz"):
		return "2.4 GHz"
	case strings.Contains(s, "(5GHz"):
		return "5 GHz"
	case strings.Contains(s, "(6GHz"):
		return "6 GHz"
	}
	return ""
}

// securityLabelDarwin maps system_profiler's spairport_security_mode_* codes
// to the same labels the Windows scanner produces, so posture.go's checks
// ("abierta", "wep", "wpa ") behave identically on both platforms.
func securityLabelDarwin(mode string) string {
	switch code := strings.TrimPrefix(mode, "spairport_security_mode_"); code {
	case "none", "":
		return "Abierta"
	case "wep":
		return "WEP"
	case "wpa_personal":
		return "WPA Personal"
	case "wpa_personal_mixed":
		return "WPA/WPA2 Personal"
	case "wpa2_personal":
		return "WPA2 Personal"
	case "wpa2_personal_mixed":
		return "WPA2 Personal (mixto)"
	case "wpa3_personal":
		return "WPA3 Personal"
	case "wpa3_transition":
		return "WPA2/WPA3 Personal"
	case "wpa_enterprise":
		return "WPA Enterprise"
	case "wpa2_enterprise":
		return "WPA2 Enterprise"
	case "wpa3_enterprise":
		return "WPA3 Enterprise"
	default:
		// Unknown future mode: prettify the raw code instead of hiding it.
		return strings.ReplaceAll(code, "_", " ")
	}
}
