package packet

import (
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestAppMetadataHTTP(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n")
	proto, info, host, ok := appMetadata(payload)
	if !ok || proto != "HTTP" {
		t.Fatalf("proto=%q ok=%v, want HTTP", proto, ok)
	}
	if !strings.Contains(info, "example.com") || !strings.Contains(info, "GET") {
		t.Errorf("info = %q, want GET + example.com", info)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want example.com", host)
	}
}

func TestAppMetadataHTTPResponse(t *testing.T) {
	proto, info, _, ok := appMetadata([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if !ok || proto != "HTTP" || !strings.Contains(info, "200") {
		t.Errorf("response parse wrong: proto=%q info=%q", proto, info)
	}
}

func TestAppMetadataWebSocketUpgradeRequest(t *testing.T) {
	payload := []byte("GET /chat HTTP/1.1\r\nHost: chat.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	proto, info, host, ok := appMetadata(payload)
	if !ok || proto != "WS" {
		t.Fatalf("proto=%q ok=%v, want WS", proto, ok)
	}
	if !strings.Contains(info, "websocket") || !strings.Contains(info, "chat.example.com") {
		t.Errorf("info = %q, want websocket + chat.example.com", info)
	}
	if host != "chat.example.com" {
		t.Errorf("host = %q, want chat.example.com", host)
	}
}

func TestAppMetadataWebSocketUpgradeResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	proto, info, _, ok := appMetadata(payload)
	if !ok || proto != "WS" || !strings.Contains(info, "101") {
		t.Errorf("WS response parse wrong: proto=%q info=%q", proto, info)
	}
}

func TestKnownApp(t *testing.T) {
	cases := map[string]string{
		"spclient.wg.spotify.com": "Spotify",
		"spotify.com":             "Spotify",
		"api.discord.com":         "Discord",
		"unknown.example.net":     "",
	}
	for host, want := range cases {
		if got := knownApp(host); got != want {
			t.Errorf("knownApp(%q) = %q, want %q", host, got, want)
		}
	}
}

// buildClientHello builds a minimal TLS ClientHello carrying an SNI extension.
func buildClientHello(sni string) []byte {
	name := []byte(sni)
	// server_name entry: type(0)=host_name + nameLen(2) + name
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	// server_name_list: listLen(2) + entry
	snList := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	// extension: type(0x0000) + extLen(2) + snList
	ext := append([]byte{0x00, 0x00, byte(len(snList) >> 8), byte(len(snList))}, snList...)
	extensions := ext

	var hs []byte
	hs = append(hs, 0x03, 0x03)             // client version
	hs = append(hs, make([]byte, 32)...)    // random
	hs = append(hs, 0x00)                   // session id len
	hs = append(hs, 0x00, 0x02, 0x00, 0x2f) // cipher suites (len 2 + one suite)
	hs = append(hs, 0x01, 0x00)             // compression (len 1 + null)
	hs = append(hs, byte(len(extensions)>>8), byte(len(extensions)))
	hs = append(hs, extensions...)

	// handshake: type(0x01) + len(3) + hs
	handshake := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	// record: type(0x16) + version(0x0301) + len(2) + handshake
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return rec
}

func TestParseSNI(t *testing.T) {
	rec := buildClientHello("test.example.com")
	if got := parseSNI(rec); got != "test.example.com" {
		t.Errorf("parseSNI = %q, want test.example.com", got)
	}
	proto, info, host, ok := appMetadata(rec)
	if !ok || proto != "TLS" || !strings.Contains(info, "test.example.com") {
		t.Errorf("TLS metadata wrong: proto=%q info=%q", proto, info)
	}
	if host != "test.example.com" {
		t.Errorf("host = %q, want test.example.com", host)
	}
}

func TestAppMetadataRobust(t *testing.T) {
	// Must never panic and should not misclassify garbage.
	for _, b := range [][]byte{nil, {}, {0x16}, {0x16, 0x03}, {0x16, 0x03, 0x01, 0xff}, []byte("random junk not http")} {
		_, _, _, _ = appMetadata(b)
		_ = parseSNI(b)
	}
}

func TestSummarizeTTLFlagsAndPayload(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 55, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, ACK: true, Window: 64240}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := gopacket.Payload([]byte("hello raw traffic"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	s := Summarize(0, p)

	if s.TTL != 55 {
		t.Errorf("TTL = %d, want 55", s.TTL)
	}
	wantFlags := "SYN,ACK"
	if strings.Join(s.TCPFlags, ",") != wantFlags {
		t.Errorf("TCPFlags = %v, want %s", s.TCPFlags, wantFlags)
	}
	if s.PayloadLen != len("hello raw traffic") {
		t.Errorf("PayloadLen = %d, want %d", s.PayloadLen, len("hello raw traffic"))
	}
	wantHex := "68656c6c6f207261772074726166666963" // "hello raw traffic"
	if s.PayloadHex != wantHex {
		t.Errorf("PayloadHex = %q, want %q", s.PayloadHex, wantHex)
	}
}

func TestSummarizePayloadPreviewCapped(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 40001} // avoid well-known ports gopacket maps to a specific decoder (e.g. 53=DNS)
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, maxPayloadPreview+100)
	for i := range big {
		big[i] = byte('a' + i%26)
	}
	payload := gopacket.Payload(big)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, payload); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	s := Summarize(0, p)

	if s.PayloadLen != len(big) {
		t.Errorf("PayloadLen = %d, want %d (full length, not truncated)", s.PayloadLen, len(big))
	}
	if len(s.PayloadHex) != maxPayloadPreview*2 {
		t.Errorf("PayloadHex hex length = %d, want %d (preview capped at %d bytes)", len(s.PayloadHex), maxPayloadPreview*2, maxPayloadPreview)
	}
}
