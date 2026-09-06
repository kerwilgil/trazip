// Package packet turns a decoded gopacket.Packet into a compact, UI-friendly
// summary. It is shared by the PCAP reader and (later) the live capture engine
// so both present packets identically (prompt maestro §9 Fase 1 #5, Fase 2 #10).
package packet

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// maxPayloadPreview caps how many payload bytes are hex-encoded per packet —
// a full capture's worth of payloads sent over the Wails IPC channel would
// bloat every live-capture batch and PCAP load; a Wireshark-bytes-pane-sized
// preview is enough for Raw Traffic's hex/ASCII view.
const maxPayloadPreview = 256

// Summary is a flat, serializable view of one packet.
type Summary struct {
	Index      int      `json:"index"`
	Time       string   `json:"time"`     // RFC3339Nano
	TimeUnix   float64  `json:"timeUnix"` // seconds since epoch
	Length     int      `json:"length"`
	Src        string   `json:"src"`
	Dst        string   `json:"dst"`
	SrcMAC     string   `json:"srcMAC,omitempty"`    // link layer, needed for L2 diagnosis
	DstMAC     string   `json:"dstMAC,omitempty"`    // ff:ff:ff:ff:ff:ff marks a broadcast
	EtherType  string   `json:"etherType,omitempty"` // e.g. IPv4, ARP, LLDP
	IPID       uint16   `json:"ipID,omitempty"`      // IPv4 identification: the dedup key for loop detection
	SrcPort    uint16   `json:"srcPort,omitempty"`
	DstPort    uint16   `json:"dstPort,omitempty"`
	Proto      string   `json:"proto"`               // highest meaningful label (DNS, TCP, ARP…)
	Transport  string   `json:"transport,omitempty"` // tcp | udp | icmp | icmp6 (5-tuple protocol)
	TTL        int      `json:"ttl,omitempty"`       // IPv4 TTL or IPv6 hop limit
	TCPFlags   []string `json:"tcpFlags,omitempty"`
	PayloadLen int      `json:"payloadLen,omitempty"` // full application-layer payload length
	PayloadHex string   `json:"payloadHex,omitempty"` // hex of up to maxPayloadPreview bytes
	Info       string   `json:"info"`
	App        string   `json:"app,omitempty"` // friendly app name from a known SNI/Host suffix, e.g. "Spotify"
	Layers     []string `json:"layers"`
	Err        string   `json:"err,omitempty"`

	// WiFi fields, only present on 802.11 captures (monitor mode, radiotap or
	// PPI). On those there is no EtherType and often no IP at all: a beacon is
	// the whole point of the capture and carries nothing above layer 2, so
	// without these a survey would read as a list of empty frames.
	SSID     string `json:"ssid,omitempty"`
	BSSID    string `json:"bssid,omitempty"`
	Channel  int    `json:"channel,omitempty"`  // derivado del IE de parámetros DS
	WiFiType string `json:"wifiType,omitempty"` // beacon, probe request, data…
}

// Summarize builds a Summary from a decoded packet.
func Summarize(index int, p gopacket.Packet) Summary {
	s := Summary{Index: index, Length: len(p.Data())}
	if md := p.Metadata(); md != nil {
		s.Time = md.Timestamp.Format(time.RFC3339Nano)
		s.TimeUnix = float64(md.Timestamp.UnixNano()) / 1e9
		if md.Length > 0 {
			s.Length = md.Length
		}
	}
	for _, l := range p.Layers() {
		s.Layers = append(s.Layers, l.LayerType().String())
	}
	if err := p.ErrorLayer(); err != nil {
		s.Err = err.Error().Error()
	}

	// Addresses: prefer network layer, fall back to ARP or link.
	if net := p.NetworkLayer(); net != nil {
		f := net.NetworkFlow()
		s.Src, s.Dst = endpointStr(f.Src()), endpointStr(f.Dst())
	}
	if arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		s.Src = ipStr(arp.SourceProtAddress)
		s.Dst = ipStr(arp.DstProtAddress)
	}
	if s.Src == "" {
		if link := p.LinkLayer(); link != nil {
			f := link.LinkFlow()
			s.Src, s.Dst = endpointStr(f.Src()), endpointStr(f.Dst())
		}
	}

	// Link layer kept separately from Src/Dst: the L2 diagnostics (loops,
	// broadcast storms, duplicate IPs) need the MACs even when the packet
	// also has network-layer addresses, and Src/Dst are overwritten above.
	if eth, ok := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		s.SrcMAC = eth.SrcMAC.String()
		s.DstMAC = eth.DstMAC.String()
		s.EtherType = eth.EthernetType.String()
	} else if link := p.LinkLayer(); link != nil {
		f := link.LinkFlow()
		s.SrcMAC, s.DstMAC = endpointStr(f.Src()), endpointStr(f.Dst())
	}
	if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		s.IPID = ip4.Id
	}

	// Ports and transport protocol.
	if tl := p.TransportLayer(); tl != nil {
		f := tl.TransportFlow()
		s.SrcPort = portNum(endpointStr(f.Src()))
		s.DstPort = portNum(endpointStr(f.Dst()))
	}
	switch {
	case p.Layer(layers.LayerTypeTCP) != nil:
		s.Transport = "tcp"
	case p.Layer(layers.LayerTypeUDP) != nil:
		s.Transport = "udp"
	case p.Layer(layers.LayerTypeICMPv4) != nil:
		s.Transport = "icmp"
	case p.Layer(layers.LayerTypeICMPv6) != nil:
		s.Transport = "icmp6"
	}

	// TTL/hop limit — same field conceptually on IPv4 and IPv6, different name.
	if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		s.TTL = int(ip4.TTL)
	} else if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		s.TTL = int(ip6.HopLimit)
	}
	if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		s.TCPFlags = tcpFlagList(tcp)
	}

	s.Proto, s.Info = protoAndInfo(p)
	// After protoAndInfo, which would otherwise overwrite the description a
	// management frame gets: for a beacon the network being announced *is* the
	// content, and "Dot11" alone says nothing.
	summarizeDot11(&s, p)

	// Application-layer metadata (TLS SNI / HTTP host, WebSocket upgrade) over TCP.
	if s.Transport == "tcp" {
		if app := p.ApplicationLayer(); app != nil {
			if pr, inf, host, ok := appMetadata(app.Payload()); ok {
				s.Proto = pr
				if inf != "" {
					s.Info = inf
				}
				if host != "" {
					s.App = knownApp(host)
				}
			}
		}
	}

	// Raw payload preview (any transport) for Raw Traffic's hex/ASCII view.
	if app := p.ApplicationLayer(); app != nil {
		payload := app.Payload()
		s.PayloadLen = len(payload)
		if len(payload) > maxPayloadPreview {
			payload = payload[:maxPayloadPreview]
		}
		if len(payload) > 0 {
			s.PayloadHex = hex.EncodeToString(payload)
		}
	}
	return s
}

// appMetadata detects TLS ClientHello (with SNI), HTTP requests/responses and
// WebSocket upgrades from a TCP payload. Best-effort and fully bounds-checked.
// host is the SNI or HTTP Host, if any, for knownApp() to label; it is only
// ever populated from the plaintext seen on THIS packet (typically just the
// handshake) — once a TLS session is established, later packets are opaque
// ciphertext and get no further classification.
func appMetadata(b []byte) (proto, info, host string, ok bool) {
	if len(b) < 3 {
		return "", "", "", false
	}
	// TLS handshake record: type=0x16, version 0x03xx.
	if b[0] == 0x16 && b[1] == 0x03 {
		if sni := parseSNI(b); sni != "" {
			return "TLS", "ClientHello · SNI=" + sni, sni, true
		}
		return "TLS", "handshake", "", true
	}
	// HTTP request methods — a plaintext ws:// handshake is an HTTP GET with
	// "Upgrade: websocket"; wss:// upgrades happen inside TLS and are opaque.
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "} {
		if hasPrefix(b, m) {
			line := firstLine(b)
			h := headerValue(b, "Host:")
			proto := "HTTP"
			if strings.EqualFold(headerValue(b, "Upgrade:"), "websocket") {
				proto = "WS"
				line += "  (Upgrade: websocket)"
			}
			if h != "" {
				return proto, line + "  (Host: " + h + ")", h, true
			}
			return proto, line, "", true
		}
	}
	if hasPrefix(b, "HTTP/") {
		if strings.EqualFold(headerValue(b, "Upgrade:"), "websocket") {
			return "WS", firstLine(b) + "  (Upgrade: websocket)", "", true
		}
		return "HTTP", firstLine(b), "", true
	}
	return "", "", "", false
}

// knownApps maps well-known SNI/Host domain suffixes to a friendly app name —
// best-effort brand labeling on top of the raw hostname Info already shows.
// Deliberately small and curated (not an exhaustive SaaS directory): common
// consumer/dev apps a home-network operator would recognize at a glance.
var knownApps = []struct{ suffix, name string }{
	{"spotify.com", "Spotify"},
	{"scdn.co", "Spotify"},
	{"discord.com", "Discord"},
	{"discord.gg", "Discord"},
	{"discordapp.com", "Discord"},
	{"discordapp.net", "Discord"},
	{"whatsapp.com", "WhatsApp"},
	{"whatsapp.net", "WhatsApp"},
	{"netflix.com", "Netflix"},
	{"nflxvideo.net", "Netflix"},
	{"youtube.com", "YouTube"},
	{"googlevideo.com", "YouTube"},
	{"ytimg.com", "YouTube"},
	{"instagram.com", "Instagram"},
	{"cdninstagram.com", "Instagram"},
	{"facebook.com", "Facebook"},
	{"fbcdn.net", "Facebook"},
	{"twitter.com", "Twitter/X"},
	{"x.com", "Twitter/X"},
	{"twimg.com", "Twitter/X"},
	{"tiktok.com", "TikTok"},
	{"tiktokcdn.com", "TikTok"},
	{"tiktokv.com", "TikTok"},
	{"zoom.us", "Zoom"},
	{"teams.microsoft.com", "Microsoft Teams"},
	{"skype.com", "Skype"},
	{"steamcommunity.com", "Steam"},
	{"steampowered.com", "Steam"},
	{"epicgames.com", "Epic Games"},
	{"riotgames.com", "Riot Games"},
	{"slack.com", "Slack"},
	{"dropbox.com", "Dropbox"},
	{"icloud.com", "iCloud"},
	{"apple.com", "Apple"},
	{"github.com", "GitHub"},
	{"githubusercontent.com", "GitHub"},
	{"amazonaws.com", "AWS"},
	{"cloudflare.com", "Cloudflare"},
	{"googleapis.com", "Google"},
	{"gstatic.com", "Google"},
	{"google.com", "Google"},
	{"twitch.tv", "Twitch"},
	{"ttvnw.net", "Twitch"},
	{"office.com", "Microsoft Office"},
	{"live.com", "Microsoft"},
	{"xboxlive.com", "Xbox Live"},
	{"anthropic.com", "Claude/Anthropic"},
	{"openai.com", "OpenAI"},
}

// knownApp returns a friendly brand name for host (an SNI or HTTP Host
// value) by matching known domain suffixes, or "" if unrecognized.
func knownApp(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, e := range knownApps {
		if h == e.suffix || strings.HasSuffix(h, "."+e.suffix) {
			return e.name
		}
	}
	return ""
}

// parseSNI extracts the server_name from a TLS ClientHello. Returns "" on any
// inconsistency (never panics).
func parseSNI(b []byte) string {
	// Record header (5) then handshake.
	if len(b) < 43 || b[5] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	p := 5 + 4 + 2 + 32 // record hdr + handshake hdr + client version + random
	if p >= len(b) {
		return ""
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return ""
	}
	csLen := int(b[p])<<8 | int(b[p+1])
	p += 2 + csLen
	if p+1 > len(b) {
		return ""
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return ""
	}
	extTotal := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extTotal
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := int(b[p])<<8 | int(b[p+1])
		elen := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if p+elen > len(b) {
			return ""
		}
		if etype == 0x0000 { // server_name
			e := b[p : p+elen]
			// server_name_list: listLen(2), type(1), nameLen(2), name
			if len(e) >= 5 && e[2] == 0x00 {
				nameLen := int(e[3])<<8 | int(e[4])
				if 5+nameLen <= len(e) {
					return string(e[5 : 5+nameLen])
				}
			}
			return ""
		}
		p += elen
	}
	return ""
}

func hasPrefix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

func firstLine(b []byte) string {
	for i := 0; i < len(b) && i < 256; i++ {
		if b[i] == '\r' || b[i] == '\n' {
			return string(b[:i])
		}
	}
	if len(b) > 256 {
		return string(b[:256])
	}
	return string(b)
}

func headerValue(b []byte, name string) string {
	s := string(b)
	idx := indexFold(s, name)
	if idx < 0 {
		return ""
	}
	idx += len(name)
	// skip spaces
	for idx < len(s) && (s[idx] == ' ' || s[idx] == '\t') {
		idx++
	}
	end := idx
	for end < len(s) && s[end] != '\r' && s[end] != '\n' {
		end++
	}
	if end <= idx {
		return ""
	}
	return s[idx:end]
}

func indexFold(s, sub string) int {
	ls, lsub := len(s), len(sub)
	if lsub == 0 || ls < lsub {
		return -1
	}
	for i := 0; i+lsub <= ls && i < 2048; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func protoAndInfo(p gopacket.Packet) (proto, info string) {
	if dns, ok := p.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
		return "DNS", dnsInfo(dns)
	}
	if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		return "TCP", tcpInfo(tcp)
	}
	if udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		return "UDP", fmt.Sprintf("%d → %d  len=%d", udp.SrcPort, udp.DstPort, udp.Length)
	}
	if _, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		icmp := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		return "ICMP", icmp.TypeCode.String()
	}
	if icmp6, ok := p.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
		return "ICMPv6", icmp6.TypeCode.String()
	}
	if arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		if arp.Operation == layers.ARPRequest {
			return "ARP", fmt.Sprintf("who has %s? tell %s", ipStr(arp.DstProtAddress), ipStr(arp.SourceProtAddress))
		}
		return "ARP", fmt.Sprintf("%s is at %s", ipStr(arp.SourceProtAddress), macStr(arp.SourceHwAddress))
	}
	// Fall back to the highest decoded layer type.
	ls := p.Layers()
	if len(ls) > 0 {
		return ls[len(ls)-1].LayerType().String(), ""
	}
	return "?", ""
}

func tcpFlagList(t *layers.TCP) []string {
	var fl []string
	if t.SYN {
		fl = append(fl, "SYN")
	}
	if t.ACK {
		fl = append(fl, "ACK")
	}
	if t.FIN {
		fl = append(fl, "FIN")
	}
	if t.RST {
		fl = append(fl, "RST")
	}
	if t.PSH {
		fl = append(fl, "PSH")
	}
	if t.URG {
		fl = append(fl, "URG")
	}
	return fl
}

func tcpInfo(t *layers.TCP) string {
	fl := tcpFlagList(t)
	return fmt.Sprintf("%d → %d  [%s]  seq=%d win=%d", t.SrcPort, t.DstPort, strings.Join(fl, ","), t.Seq, t.Window)
}

func dnsInfo(d *layers.DNS) string {
	if len(d.Questions) > 0 {
		q := d.Questions[0]
		kind := "query"
		if d.QR {
			kind = "response"
		}
		return fmt.Sprintf("%s %s %s", kind, q.Type, string(q.Name))
	}
	return "DNS"
}

func ipStr(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ".")
}

// endpointStr renders a gopacket flow endpoint defensively. gopacket's
// Endpoint.String() indexes into the endpoint's raw bytes according to its
// declared type, so an endpoint that declares a type but carries no bytes
// panics with an index-out-of-range — which a real MikroTik capture does
// produce. A malformed frame must never take down the analyzer, so an empty
// endpoint becomes an empty string instead.
func endpointStr(e gopacket.Endpoint) string {
	if len(e.Raw()) == 0 {
		return ""
	}
	return e.String()
}

func macStr(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func portNum(s string) uint16 {
	var n uint16
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + uint16(s[i]-'0')
	}
	return n
}
