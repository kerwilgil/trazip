package packet

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// summarizeDot11 fills the WiFi fields of s when p is an 802.11 frame.
//
// A capture taken in monitor mode is mostly management frames — beacons and
// probes — which carry nothing above layer 2. Summarized like an Ethernet
// packet they all look identical and empty: same broadcast destination, no
// EtherType, no addresses. What actually distinguishes one from another is the
// network being announced and the channel it was heard on, so those are pulled
// out here.
func summarizeDot11(s *Summary, p gopacket.Packet) {
	d11, ok := p.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if !ok {
		return
	}

	s.WiFiType = frameTypeName(d11.Type)
	// In data frames the DS flags determine which address is the AP. Management
	// frames use Address3. WDS frames have no single unambiguous BSSID.
	var bssid string
	switch {
	case d11.Type.MainType() != layers.Dot11TypeData:
		bssid = d11.Address3.String()
	case d11.Flags.ToDS() && !d11.Flags.FromDS():
		bssid = d11.Address1.String()
	case d11.Flags.FromDS() && !d11.Flags.ToDS():
		bssid = d11.Address2.String()
	case !d11.Flags.ToDS() && !d11.Flags.FromDS():
		bssid = d11.Address3.String()
	}
	if bssid != "" && bssid != "00:00:00:00:00:00" {
		s.BSSID = bssid
	}
	if s.SrcMAC == "" {
		s.SrcMAC = d11.Address2.String()
		s.DstMAC = d11.Address1.String()
	}

	// Information elements carry the SSID and the channel. They appear in
	// beacons, probe requests and probe responses alike.
	for _, l := range p.Layers() {
		ie, ok := l.(*layers.Dot11InformationElement)
		if !ok {
			continue
		}
		switch ie.ID {
		case layers.Dot11InformationElementIDSSID:
			s.SSID = ssidText(ie.Info)
		case layers.Dot11InformationElementIDDSSet:
			if len(ie.Info) >= 1 {
				s.Channel = int(ie.Info[0])
			}
		case layers.Dot11InformationElementIDHTInfo:
			if s.Channel == 0 && len(ie.Info) >= 1 {
				s.Channel = int(ie.Info[0])
			}
		}
	}
	if s.Channel == 0 {
		if rt, ok := p.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap); ok {
			if len(rt.RadioTapValues) > 0 {
				s.Channel = wifiChannelFromFrequency(int(rt.RadioTapValues[0].ChannelFrequency))
			}
		}
	}

	// Una trama de gestión o control no lleva nada por encima de la capa 2, y
	// describirla por su capa más alta da etiquetas inútiles como
	// "Dot11InformationElement". Una trama de datos sí transporta IP, y ahí el
	// protocolo real (DNS, TLS…) es mucho más informativo: no se toca.
	if p.NetworkLayer() == nil {
		s.Proto = "802.11"
		if desc := dot11Info(s); desc != "" {
			s.Info = desc
		}
	}
}

func wifiChannelFromFrequency(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz >= 5000 && mhz <= 5895:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5
	default:
		return 0
	}
}

// ssidText renders an SSID for display. A hidden network advertises a
// zero-length or all-zero SSID, which is a fact worth stating rather than
// rendering as an empty cell that looks like a parsing failure.
func ssidText(b []byte) string {
	if len(b) == 0 {
		return "(hidden)"
	}
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "(hidden)"
	}
	// SSIDs are arbitrary bytes, not guaranteed UTF-8; anything unprintable is
	// replaced so a crafted name cannot scramble the table it lands in.
	var sb strings.Builder
	for _, r := range string(b) {
		if r < 0x20 || r == 0x7f {
			sb.WriteRune('.')
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func frameTypeName(t layers.Dot11Type) string {
	switch t {
	case layers.Dot11TypeMgmtBeacon:
		return "beacon"
	case layers.Dot11TypeMgmtProbeReq:
		return "probe request"
	case layers.Dot11TypeMgmtProbeResp:
		return "probe response"
	case layers.Dot11TypeMgmtAssociationReq:
		return "association request"
	case layers.Dot11TypeMgmtAssociationResp:
		return "association response"
	case layers.Dot11TypeMgmtDeauthentication:
		return "deauth"
	case layers.Dot11TypeMgmtDisassociation:
		return "disassociation"
	case layers.Dot11TypeMgmtAuthentication:
		return "authentication"
	}
	switch {
	case t.MainType() == layers.Dot11TypeData:
		return "data"
	case t.MainType() == layers.Dot11TypeCtrl:
		return "control"
	case t.MainType() == layers.Dot11TypeMgmt:
		return "management"
	}
	return ""
}

func dot11Info(s *Summary) string {
	parts := make([]string, 0, 3)
	if s.WiFiType != "" {
		parts = append(parts, s.WiFiType)
	}
	if s.SSID != "" {
		parts = append(parts, "SSID "+s.SSID)
	}
	if s.Channel > 0 {
		parts = append(parts, "channel "+strconv.Itoa(s.Channel))
	}
	return strings.Join(parts, " · ")
}
