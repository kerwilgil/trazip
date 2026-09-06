package voip

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// TestUlawSymmetry checks a property that must hold regardless of the exact
// ITU conformance table (which isn't available to verify against offline):
// flipping only the sign bit must negate the magnitude, since the sign bit is
// decoded independently of the exponent/mantissa.
func TestUlawSymmetry(t *testing.T) {
	for _, b := range []byte{0x00, 0x0f, 0x33, 0x55, 0x70, 0x7f} {
		pos := ulaw2linear(b | 0x80)  // sign bit set
		neg := ulaw2linear(b &^ 0x80) // sign bit clear
		diff := int(pos) + int(neg)
		if diff < -2 || diff > 2 { // allow ±1 for the DC bias in the companding formula
			t.Errorf("ulaw2linear(%#x)=%d and ulaw2linear(%#x)=%d should be near-opposite, sum=%d", b|0x80, pos, b&^0x80, neg, diff)
		}
	}
}

func TestUlawMonotonicMagnitude(t *testing.T) {
	// ulaw2linear inverts the byte before reading sign/exponent/mantissa (per
	// the G.711 spec), so to target "post-inversion exponent = X, sign
	// positive, mantissa 0" the wire byte we pass in must be the bitwise NOT
	// of that. Increasing exponent must increase the decoded magnitude — that
	// wider dynamic-range step per exponent is the entire point of companding.
	prevMag := -1
	for exp := 0; exp < 8; exp++ {
		postInversion := byte(exp << 4) // sign=0 (positive), mantissa=0
		wireByte := ^postInversion
		v := int(ulaw2linear(wireByte))
		if v < 0 {
			t.Fatalf("exp=%d: expected a positive sample, got %d", exp, v)
		}
		if prevMag >= 0 && v < prevMag {
			t.Errorf("magnitude should not decrease as exponent grows: exp=%d val=%d prev=%d", exp, v, prevMag)
		}
		prevMag = v
	}
}

func TestWriteWAVHeader(t *testing.T) {
	samples := []int16{0, 100, -100, 32767, -32768}
	data := WriteWAV(8000, samples)

	if string(data[0:4]) != "RIFF" || string(data[8:12]) != "WAVE" {
		t.Fatalf("missing RIFF/WAVE markers")
	}
	if string(data[12:16]) != "fmt " || string(data[36:40]) != "data" {
		t.Fatalf("missing fmt/data chunk markers")
	}
	channels := binary.LittleEndian.Uint16(data[22:24])
	sampleRate := binary.LittleEndian.Uint32(data[24:28])
	bitsPerSample := binary.LittleEndian.Uint16(data[34:36])
	dataSize := binary.LittleEndian.Uint32(data[40:44])
	if channels != 1 || sampleRate != 8000 || bitsPerSample != 16 {
		t.Errorf("fmt chunk wrong: channels=%d rate=%d bits=%d", channels, sampleRate, bitsPerSample)
	}
	if dataSize != uint32(len(samples)*2) {
		t.Errorf("data size = %d, want %d", dataSize, len(samples)*2)
	}
	if len(data) != 44+len(samples)*2 {
		t.Errorf("total WAV length = %d, want %d", len(data), 44+len(samples)*2)
	}
}

func TestExportStreamAudioFillsGaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rtp.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	srcIP, dstIP := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	srcMAC, dstMAC := net.HardwareAddr{1, 1, 1, 1, 1, 1}, net.HardwareAddr{2, 2, 2, 2, 2, 2}
	base := time.Now()

	for i := 0; i < 5; i++ {
		if i == 2 {
			continue // drop packet #2 to test silence-fill
		}
		payload := make([]byte, 12+160)
		payload[0] = 0x80
		payload[1] = 0 // PCMU
		binary.BigEndian.PutUint16(payload[2:4], uint16(i))
		binary.BigEndian.PutUint32(payload[4:8], uint32(i)*160)
		binary.BigEndian.PutUint32(payload[8:12], 0xCAFEBABE)
		for j := 12; j < len(payload); j++ {
			payload[j] = 0xFF // 0xFF ulaw = near-zero silence sample
		}

		eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
		udp := &layers.UDP{SrcPort: 40000, DstPort: 40002}
		_ = udp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * 20 * time.Millisecond), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	wav, filled, err := ExportStreamAudio(context.Background(), path, 0xCAFEBABE, "10.0.0.1:40000")
	if err != nil {
		t.Fatalf("ExportStreamAudio: %v", err)
	}
	if filled != 160 {
		t.Errorf("filledSamples = %d, want 160 (one dropped 20ms packet)", filled)
	}
	dataSize := binary.LittleEndian.Uint32(wav[40:44])
	wantSamples := 5 * 160 // 5 sequence slots (0..4), including the filled gap
	if int(dataSize) != wantSamples*2 {
		t.Errorf("wav data size = %d, want %d (missing packet should still occupy its slot)", dataSize, wantSamples*2)
	}
}

func TestExportStreamAudioUnsupportedCodec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opus.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	payload := make([]byte, 12+20)
	payload[0] = 0x80
	payload[1] = 111 // dynamic PT, e.g. opus — unsupported for export
	binary.BigEndian.PutUint32(payload[8:12], 0x1234)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 1, 1, 1, 1, 1}, DstMAC: net.HardwareAddr{2, 2, 2, 2, 2, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 40002}
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload))
	data := buf.Bytes()
	_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}, data)
	f.Close()

	if _, _, err := ExportStreamAudio(context.Background(), path, 0x1234, "10.0.0.1:40000"); err == nil {
		t.Error("expected an error naming the unsupported codec")
	}
}

func TestExportStreamAudioNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	f.Close()

	if _, _, err := ExportStreamAudio(context.Background(), path, 0x1, "1.2.3.4:1000"); err == nil {
		t.Error("expected error when no matching RTP packets exist")
	}
}
