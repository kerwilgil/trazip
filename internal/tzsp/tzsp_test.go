package tzsp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"trazip/internal/packet"
)

// buildEthernetFrame returns a minimal, valid Ethernet+IPv4+UDP frame — same
// shape a MikroTik sniffer would forward.
func buildEthernetFrame(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 5}, DstIP: net.IP{8, 8, 8, 8}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("hi"))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestEncodeRoundtrip proves the sender-side Encode produces exactly what
// this package's own receiver strips back out — the contract the tzsp-sender
// CLI depends on.
func TestEncodeRoundtrip(t *testing.T) {
	frame := buildEthernetFrame(t)
	got, ok := stripHeader(Encode(frame))
	if !ok {
		t.Fatal("stripHeader rejected an Encode()d datagram")
	}
	if !bytes.Equal(got, frame) {
		t.Fatal("frame did not survive the Encode/stripHeader roundtrip")
	}
}

// tzspWrap builds a minimal TZSP v1 header (Ethernet encapsulation, empty tag
// list) around frame, mirroring what a MikroTik sniffer sends.
func tzspWrap(frame []byte) []byte {
	header := []byte{tzspVersion1, 0 /* type */, 0x00, tzspEncapEthernet, tzspTagEnd}
	return append(header, frame...)
}

func TestStripHeaderValidPacket(t *testing.T) {
	frame := buildEthernetFrame(t)
	got, ok := stripHeader(tzspWrap(frame))
	if !ok {
		t.Fatal("stripHeader returned ok=false for a well-formed packet")
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("stripHeader returned %d bytes, want the original %d-byte frame back unchanged", len(got), len(frame))
	}
}

func TestStripHeaderSkipsPaddingTags(t *testing.T) {
	frame := buildEthernetFrame(t)
	header := []byte{tzspVersion1, 0, 0x00, tzspEncapEthernet, tzspTagPadding, tzspTagPadding, tzspTagEnd}
	got, ok := stripHeader(append(header, frame...))
	if !ok || !bytes.Equal(got, frame) {
		t.Fatalf("stripHeader with padding tags: ok=%v, got=%d bytes", ok, len(got))
	}
}

func TestStripHeaderSkipsDataTags(t *testing.T) {
	frame := buildEthernetFrame(t)
	// A tag with a 4-byte payload (e.g. RSSI-like), then END.
	header := []byte{tzspVersion1, 0, 0x00, tzspEncapEthernet, 0x0A, 0x04, 0x01, 0x02, 0x03, 0x04, tzspTagEnd}
	got, ok := stripHeader(append(header, frame...))
	if !ok || !bytes.Equal(got, frame) {
		t.Fatalf("stripHeader with a data tag: ok=%v, got=%d bytes", ok, len(got))
	}
}

func TestStripHeaderRejectsWrongVersion(t *testing.T) {
	frame := buildEthernetFrame(t)
	header := []byte{2 /* unsupported version */, 0, 0x00, tzspEncapEthernet, tzspTagEnd}
	if _, ok := stripHeader(append(header, frame...)); ok {
		t.Error("expected stripHeader to reject an unsupported TZSP version")
	}
}

func TestStripHeaderRejectsNonEthernet(t *testing.T) {
	frame := buildEthernetFrame(t)
	header := []byte{tzspVersion1, 0, 0x00, 0x02 /* not Ethernet */, tzspTagEnd}
	if _, ok := stripHeader(append(header, frame...)); ok {
		t.Error("expected stripHeader to reject a non-Ethernet encapsulation")
	}
}

func TestStripHeaderRobustAgainstGarbage(t *testing.T) {
	// Must never panic, regardless of how malformed the input is.
	cases := [][]byte{
		nil, {}, {1}, {1, 0}, {1, 0, 0}, {1, 0, 0, 1},
		{1, 0, 0, 1, 0x05}, // data tag with no length byte
		{1, 0, 0, 1, 0x05, 0xFF},
	}
	for _, c := range cases {
		_, _ = stripHeader(c)
	}
}

func TestListenDecodesReceivedDatagrams(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.LocalAddr().String()
	ln.Close() // free the port; Listen() will rebind it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan struct{}, 1)
	go func() {
		_ = Listen(ctx, addr, func(s packet.Summary) {
			select {
			case received <- struct{}{}:
			default:
			}
		})
	}()

	// Dial no espera a que Listen bindee: en UDP no hay handshake, asi que
	// DialUDP tiene exito aunque no haya nadie escuchando. La espera real la
	// hace el loop de escritura de abajo.
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	frame := buildEthernetFrame(t)
	payload := tzspWrap(frame)
	deadline := time.Now().Add(2 * time.Second)
	var lastWriteErr error
	for {
		// Si escribimos antes de que Listen bindee, el kernel contesta ICMP
		// port unreachable y el socket conectado devuelve ECONNREFUSED en la
		// escritura siguiente. Es transitorio: reintentamos hasta el deadline
		// en vez de fallar en el primer error.
		if _, err := conn.Write(payload); err != nil {
			lastWriteErr = err
		}
		select {
		case <-received:
			return
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				if lastWriteErr != nil {
					t.Fatalf("Listen no decodificó el datagrama TZSP a tiempo (ultimo error de escritura: %v)", lastWriteErr)
				}
				t.Fatal("Listen no decodificó el datagrama TZSP a tiempo")
			}
		}
	}
}

func TestSourceGatePinsFirstSenderAndRateLimits(t *testing.T) {
	g := newSourceGate(2)
	now := time.Now()
	if !g.allow("192.0.2.10:1000", now) || !g.allow("192.0.2.10:1000", now) {
		t.Fatal("the selected sender should be allowed up to the configured limit")
	}
	if g.allow("192.0.2.10:1000", now) {
		t.Fatal("sender exceeded the per-second decode limit")
	}
	if g.allow("192.0.2.11:1000", now.Add(2*time.Second)) {
		t.Fatal("a second sender was allowed to inject into the established stream")
	}
	if !g.allow("192.0.2.10:1000", now.Add(2*time.Second)) {
		t.Fatal("the selected sender should be allowed again in a new rate window")
	}
}
