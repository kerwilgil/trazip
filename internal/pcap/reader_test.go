package pcap

import (
	"compress/gzip"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"trazip/internal/packet"
)

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func writeTestPcap(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	srcIP := net.IP{192, 168, 1, 10}
	dstIP := net.IP{8, 8, 8, 8}

	// 1) TCP SYN
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, Window: 64240}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	pkt1 := serialize(t, eth, ip, tcp)

	// 2) UDP + DNS query
	eth2 := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip2 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: 55000, DstPort: 53}
	_ = udp.SetNetworkLayerForChecksum(ip2)
	dns := &layers.DNS{ID: 1234, QDCount: 1, Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	pkt2 := serialize(t, eth2, ip2, udp, dns)

	// 3) ARP request
	eth3 := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: srcMAC, SourceProtAddress: srcIP,
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: net.IP{192, 168, 1, 1},
	}
	pkt3 := serialize(t, eth3, arp)

	now := time.Now()
	for i, data := range [][]byte{pkt1, pkt2, pkt3} {
		ci := gopacket.CaptureInfo{Timestamp: now.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestReadPcap(t *testing.T) {
	path := writeTestPcap(t)
	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Format != "pcap" {
		t.Errorf("format = %q, want pcap", info.Format)
	}
	if info.Packets != 3 || len(got) != 3 {
		t.Fatalf("packets = %d, summaries = %d, want 3", info.Packets, len(got))
	}

	protos := map[string]packet.Summary{}
	for _, s := range got {
		protos[s.Proto] = s
	}
	if _, ok := protos["TCP"]; !ok {
		t.Errorf("missing TCP packet; protos=%v", keys(protos))
	}
	if _, ok := protos["DNS"]; !ok {
		t.Errorf("missing DNS packet; protos=%v", keys(protos))
	}
	if _, ok := protos["ARP"]; !ok {
		t.Errorf("missing ARP packet; protos=%v", keys(protos))
	}
	if tcp := protos["TCP"]; tcp.DstPort != 443 || tcp.Src != "192.168.1.10" {
		t.Errorf("TCP summary wrong: %+v", tcp)
	}
}

func TestReadFilterAndLimit(t *testing.T) {
	path := writeTestPcap(t)
	var got []packet.Summary
	_, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) },
		Options{Filter: func(s packet.Summary) bool { return s.Proto == "TCP" || s.Proto == "DNS" }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("filtered = %d, want 2", len(got))
	}
}

// Some capture tools (e.g. per-call SIP/RTP exports from Homer/FreeSWITCH)
// ship ".pcap" files that are actually gzip-compressed. Read must unwrap
// that transparently, the same way Wireshark/tshark do.
func TestReadGzippedPcap(t *testing.T) {
	plainPath := writeTestPcap(t)
	raw, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}

	gzPath := filepath.Join(t.TempDir(), "call.pcap")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	var got []packet.Summary
	info, err := Read(context.Background(), gzPath, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read on gzipped pcap: %v", err)
	}
	if info.Format != "pcap" {
		t.Errorf("format = %q, want pcap", info.Format)
	}
	if info.Packets != 3 || len(got) != 3 {
		t.Fatalf("packets = %d, summaries = %d, want 3", info.Packets, len(got))
	}
}

func TestReadRejectsCaptureBeyondByteLimit(t *testing.T) {
	plainPath := writeTestPcap(t)
	raw, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}

	gzPath := filepath.Join(t.TempDir(), "oversized.pcap.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Read(context.Background(), gzPath, nil, Options{MaxBytes: int64(len(raw) - 1)})
	if !errors.Is(err, ErrCaptureLimit) {
		t.Fatalf("Read error = %v, want ErrCaptureLimit", err)
	}
}

func TestReadRejectsCaptureBeyondPacketLimit(t *testing.T) {
	path := writeTestPcap(t)
	seen := 0
	_, err := Read(context.Background(), path, func(packet.Summary) { seen++ }, Options{MaxPackets: 2})
	if !errors.Is(err, ErrCaptureLimit) {
		t.Fatalf("Read error = %v, want ErrCaptureLimit", err)
	}
	if seen != 2 {
		t.Fatalf("callbacks = %d, want 2 before rejecting the third packet", seen)
	}
}

func TestReadPacketsWithOptionsRejectsBeyondPacketLimit(t *testing.T) {
	path := writeTestPcap(t)
	seen := 0
	_, err := ReadPacketsWithOptions(context.Background(), path, func(_ int, _ gopacket.Packet) { seen++ }, Options{MaxPackets: 2})
	if !errors.Is(err, ErrCaptureLimit) {
		t.Fatalf("ReadPacketsWithOptions error = %v, want ErrCaptureLimit", err)
	}
	if seen != 2 {
		t.Fatalf("callbacks = %d, want 2 before rejecting the third packet", seen)
	}
}

func TestBadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pcap")
	os.WriteFile(path, []byte("not a pcap file at all"), 0o644)
	if _, err := Read(context.Background(), path, nil, Options{}); err == nil {
		t.Error("expected error for non-pcap file")
	}
}

func keys(m map[string]packet.Summary) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
