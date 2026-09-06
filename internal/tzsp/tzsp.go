// Package tzsp receives TZSP-encapsulated packets over UDP — the protocol
// MikroTik RouterOS's "/tool sniffer" (and some other network gear) uses to
// stream a live packet capture to a remote host. This is how TRAZIP sees
// traffic beyond its own NIC: the operator's own router, which every packet
// on the segment already legitimately passes through, chooses to export a
// copy to TRAZIP — the same mechanism Wireshark's native TZSP support uses.
// It is not interception of traffic that doesn't already flow through
// infrastructure the operator administers, and it is not a MITM technique
// (no ARP poisoning, no traffic redirection).
//
// Decoded frames go through the exact same packet.Summarize() pipeline as
// local Npcap capture and PCAP files, so Live Capture, Flows and the
// App/SNI detection built for those work identically regardless of source.
package tzsp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"trazip/internal/packet"
)

// DefaultPort is the UDP port MikroTik documentation and most TZSP tooling
// (including Wireshark's default "Decode As") conventionally uses for
// sniffer streaming. RouterOS lets the operator pick any port via
// "/tool sniffer set streaming-server=<ip>:<port>"; this is only a sane
// default for the TRAZIP-side listener.
const DefaultPort = 37008

const (
	tzspVersion1        = 1
	tzspEncapEthernet   = 1 // "encapsulated protocol" field value for Ethernet
	tzspTagPadding      = 0
	tzspTagEnd          = 1
	maxPacketsPerSecond = 50000
)

// sourceGate pins one capture to the first sender that delivers a valid TZSP
// frame and caps the number of frames that reach the decoder each second.
// UDP still has to be read to keep the socket healthy, but an unrelated LAN
// host cannot mix telemetry into an established stream or trigger unbounded
// packet decoding/event work.
type sourceGate struct {
	source      string
	windowStart time.Time
	count       int
	limit       int
}

func newSourceGate(limit int) *sourceGate {
	return &sourceGate{limit: limit}
}

func (g *sourceGate) allow(source string, now time.Time) bool {
	if g.source == "" {
		g.source = source
	}
	if source != g.source {
		return false
	}
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= time.Second {
		g.windowStart = now
		g.count = 0
	}
	if g.count >= g.limit {
		return false
	}
	g.count++
	return true
}

// Listen opens addr (UDP "host:port") and decodes every well-formed
// TZSP-encapsulated Ethernet frame received until ctx is cancelled, calling
// onPacket for each one. Malformed or unsupported datagrams (wrong version,
// non-Ethernet encapsulation, truncated tag list) are silently skipped —
// a listener whose whole job is "consume whatever a router sends" cannot
// afford to abort on a single one-off garbled packet.
func Listen(ctx context.Context, addr string, onPacket func(packet.Summary)) error {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("dirección inválida: %w", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("no se pudo escuchar en %s: %w", addr, err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 65535)
	idx := 0
	gate := newSourceGate(maxPacketsPerSecond)
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue // malformed/transient read — keep listening
		}
		frame, ok := stripHeader(buf[:n])
		if !ok {
			continue
		}
		now := time.Now()
		if !gate.allow(sender.String(), now) {
			continue
		}
		p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		md := p.Metadata()
		md.Timestamp = now
		md.CaptureInfo = gopacket.CaptureInfo{Timestamp: now, CaptureLength: len(frame), Length: len(frame)}
		s := packet.Summarize(idx, p)
		idx++
		if onPacket != nil {
			onPacket(s)
		}
	}
}

// Encode wraps a raw Ethernet frame in the minimal TZSP header this
// package's own Listen understands (and Wireshark/MikroTik interop with):
// version 1, type 0 (received tagged packet), Ethernet encapsulation, and an
// immediate END tag — no optional tagged fields. Used by the tzsp-sender CLI
// to stream a capture from another machine into TRAZIP's TZSP listener.
func Encode(frame []byte) []byte {
	out := make([]byte, 0, 5+len(frame))
	out = append(out, tzspVersion1, 0)
	out = binary.BigEndian.AppendUint16(out, tzspEncapEthernet)
	out = append(out, tzspTagEnd)
	return append(out, frame...)
}

// Decapsulate returns the Ethernet frame carried inside a TZSP datagram, for
// callers holding a UDP payload that may or may not be TZSP — reading a capture
// file of a TZSP stream, where the sniffer was pointed at the receiving host
// instead of at the segment being diagnosed.
//
// It is stricter than the listener's own parsing, and deliberately so: Listen
// only ever sees datagrams sent to a port the operator configured as a TZSP
// endpoint, so a valid header is proof enough. Here the payload is arbitrary
// UDP traffic from a file, and a header check alone would misread any datagram
// that happens to start with those five bytes. So the frame inside must also
// look like Ethernet: full 14-byte header and an EtherType (or 802.3 length)
// that is actually plausible. A random payload passing both is not realistic.
func Decapsulate(payload []byte) ([]byte, bool) {
	frame, ok := stripHeader(payload)
	if !ok || !looksLikeEthernet(frame) {
		return nil, false
	}
	return frame, true
}

// looksLikeEthernet reports whether b plausibly starts with an Ethernet II or
// 802.3 header.
func looksLikeEthernet(b []byte) bool {
	if len(b) < 14 {
		return false
	}
	et := binary.BigEndian.Uint16(b[12:14])
	if et <= 1500 {
		return true // 802.3: the field is a length, not an EtherType
	}
	switch layers.EthernetType(et) {
	case layers.EthernetTypeIPv4, layers.EthernetTypeIPv6, layers.EthernetTypeARP,
		layers.EthernetTypeDot1Q, layers.EthernetTypeQinQ, layers.EthernetTypeMPLSUnicast,
		layers.EthernetTypeMPLSMulticast, layers.EthernetTypePPPoEDiscovery,
		layers.EthernetTypePPPoESession, layers.EthernetTypeLinkLayerDiscovery,
		layers.EthernetTypeEthernetCTP, layers.EthernetTypeCiscoDiscovery,
		layers.EthernetTypeNortelDiscovery:
		return true
	}
	return false
}

// stripHeader parses a TZSP datagram and returns the encapsulated Ethernet
// frame, or ok=false if the datagram isn't a version-1, Ethernet-encapsulated
// TZSP packet TRAZIP can decode.
//
// Wire format: version(1) type(1) encapsulatedProtocol(2, big-endian) then a
// sequence of tagged fields (each either a bare PADDING/END byte, or a byte
// tag + a byte length + that many bytes of data) terminated by END, followed
// by the raw encapsulated frame.
func stripHeader(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if data[0] != tzspVersion1 {
		return nil, false
	}
	if binary.BigEndian.Uint16(data[2:4]) != tzspEncapEthernet {
		return nil, false
	}

	i := 4
	for {
		if i >= len(data) {
			return nil, false // ran off the end without an END tag
		}
		tag := data[i]
		if tag == tzspTagPadding {
			i++
			continue
		}
		if tag == tzspTagEnd {
			i++
			break
		}
		if i+1 >= len(data) {
			return nil, false // length byte missing
		}
		length := int(data[i+1])
		i += 2 + length
	}
	if i > len(data) {
		return nil, false
	}
	return data[i:], true
}
