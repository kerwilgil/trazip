// Package pcap reads PCAP and PCAPNG capture files without any driver
// (prompt maestro §5.6, §9 Fase 1 #5). It streams packet summaries so large
// files are processed incrementally and cancellably.
package pcap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"trazip/internal/packet"
	"trazip/internal/ppi"
	"trazip/internal/tzsp"
)

const (
	// DefaultMaxCaptureBytes caps input after gzip decompression so an
	// externally supplied compressed capture cannot expand without bound.
	DefaultMaxCaptureBytes int64 = 512 << 20 // 512 MiB

	// DefaultMaxCapturePackets also bounds downstream flow cardinality.
	DefaultMaxCapturePackets = 250_000
)

// ErrCaptureLimit is returned instead of silently accepting a capture that
// exceeds a safety limit.
var ErrCaptureLimit = errors.New("la captura excede el límite de seguridad")

// Info summarizes a capture file.
type Info struct {
	Format      string  `json:"format"` // "pcap" | "pcapng"
	LinkType    string  `json:"linkType"`
	Packets     int     `json:"packets"`
	Bytes       int64   `json:"bytes"`
	FirstTime   string  `json:"firstTime,omitempty"`
	LastTime    string  `json:"lastTime,omitempty"`
	DurationSec float64 `json:"durationSec"`
	Truncated   bool    `json:"truncated"` // stopped at Limit

	// LinkTypeNum is the raw number from the file header. It is reported
	// alongside the name because gopacket renders every type it has no
	// decoder for as "UnknownLinkType", which tells the operator nothing —
	// the number is what they can look up.
	LinkTypeNum int `json:"linkTypeNum"`

	// Undecodable counts packets whose link layer could not be parsed. When
	// it equals Packets the capture is simply of a medium TRAZIP cannot read,
	// which is worth saying plainly instead of showing a list of failures.
	Undecodable int `json:"undecodable"`

	// TZSPDecapsulated counts packets that were TZSP envelopes and got
	// replaced by the frame they carried. Reported so the view can say the
	// analysis is of the transported traffic, not of the transport.
	TZSPDecapsulated int `json:"tzspDecapsulated"`

	// GPSFixes counts frames that arrived with a position attached (PPI
	// geolocation), and FirstFix/LastFix are the first and last of them —
	// enough for the view to say where a survey was taken without carrying a
	// coordinate per packet.
	GPSFixes int      `json:"gpsFixes"`
	FirstFix *ppi.Fix `json:"firstFix,omitempty"`
	LastFix  *ppi.Fix `json:"lastFix,omitempty"`
}

// Options tune a read.
type Options struct {
	Limit      int                       // 0 = unlimited emitted summaries
	MaxPackets int                       // 0 = DefaultMaxCapturePackets
	MaxBytes   int64                     // 0 = DefaultMaxCaptureBytes after gzip decompression
	Filter     func(packet.Summary) bool // nil = all packets
}

func (o Options) maxPackets() int {
	if o.MaxPackets > 0 {
		return o.MaxPackets
	}
	return DefaultMaxCapturePackets
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return DefaultMaxCaptureBytes
}

type pktReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// Read streams packet summaries from a capture file, invoking onPacket per
// packet that passes the filter. It returns file-level Info.
func Read(ctx context.Context, path string, onPacket func(packet.Summary), opts Options) (Info, error) {
	reader, format, closeFn, err := openCapture(path, opts.maxBytes())
	if err != nil {
		return Info{}, err
	}
	defer closeFn()
	budget := captureBudgetFor(reader)

	linkType := reader.LinkType()
	info := Info{Format: format, LinkType: linkTypeName(linkType), LinkTypeNum: int(linkType)}

	idx := 0
	emitted := 0
	var firstT, lastT time.Time
	for {
		if ctx.Err() != nil {
			return info, ctx.Err()
		}
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			if budget.exceeded {
				return info, budget.err()
			}
			// Skip malformed records without aborting the whole file.
			continue
		}
		info.Packets++
		if info.Packets > opts.maxPackets() {
			return info, fmt.Errorf("%w: máximo de %d paquetes", ErrCaptureLimit, opts.maxPackets())
		}
		info.Bytes += int64(ci.Length)
		if firstT.IsZero() {
			firstT = ci.Timestamp
		}
		lastT = ci.Timestamp

		p, fix := readFrame(data, linkType, ci)
		info.noteFix(fix)

		if inner := decapsulateTZSP(p, ci); inner != nil {
			p = inner
			info.TZSPDecapsulated++
		} else if isUndecodable(p) {
			info.Undecodable++
		}

		s := packet.Summarize(idx, p)
		idx++
		if opts.Filter != nil && !opts.Filter(s) {
			continue
		}
		if onPacket != nil {
			onPacket(s)
		}
		emitted++
		if opts.Limit > 0 && emitted >= opts.Limit {
			info.Truncated = true
			break
		}
	}

	if !firstT.IsZero() {
		info.FirstTime = firstT.Format(time.RFC3339Nano)
		info.LastTime = lastT.Format(time.RFC3339Nano)
		info.DurationSec = lastT.Sub(firstT).Seconds()
	}
	return info, nil
}

// ReadPackets is a sibling of Read for callers that need the fully decoded
// gopacket.Packet rather than a flat Summary — e.g. the VoIP correlator, which
// needs raw UDP/TCP payload bytes to feed SIP/RTP/RTCP parsers. It duplicates
// Read's small open/format-detect step rather than changing Read's contract,
// so existing callers (PCAP Analyzer, Flows) are unaffected.
func ReadPackets(ctx context.Context, path string, onPacket func(int, gopacket.Packet)) (Info, error) {
	return ReadPacketsWithOptions(ctx, path, onPacket, Options{})
}

// ReadPacketsWithOptions is ReadPackets with explicit resource limits for
// callers that need to tune the secure defaults for a trusted large capture.
func ReadPacketsWithOptions(ctx context.Context, path string, onPacket func(int, gopacket.Packet), opts Options) (Info, error) {
	reader, format, closeFn, err := openCapture(path, opts.maxBytes())
	if err != nil {
		return Info{}, err
	}
	defer closeFn()
	budget := captureBudgetFor(reader)

	linkType := reader.LinkType()
	info := Info{Format: format, LinkType: linkTypeName(linkType), LinkTypeNum: int(linkType)}

	idx := 0
	var firstT, lastT time.Time
	for {
		if ctx.Err() != nil {
			return info, ctx.Err()
		}
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			if budget.exceeded {
				return info, budget.err()
			}
			continue
		}
		info.Packets++
		if info.Packets > opts.maxPackets() {
			return info, fmt.Errorf("%w: máximo de %d paquetes", ErrCaptureLimit, opts.maxPackets())
		}
		info.Bytes += int64(ci.Length)
		if firstT.IsZero() {
			firstT = ci.Timestamp
		}
		lastT = ci.Timestamp

		p, fix := readFrame(data, linkType, ci)
		info.noteFix(fix)

		// The VoIP correlator reads SIP/RTP out of raw payloads, so it needs
		// the same unwrapping — a call captured off a TZSP collector is just
		// as much a call as one captured off the wire.
		if inner := decapsulateTZSP(p, ci); inner != nil {
			p = inner
			info.TZSPDecapsulated++
		} else if isUndecodable(p) {
			info.Undecodable++
		}

		if onPacket != nil {
			onPacket(idx, p)
		}
		idx++
	}

	if !firstT.IsZero() {
		info.FirstTime = firstT.Format(time.RFC3339Nano)
		info.LastTime = lastT.Format(time.RFC3339Nano)
		info.DurationSec = lastT.Sub(firstT).Seconds()
	}
	return info, nil
}

// openCapture opens path and returns a ready-to-read pktReader plus the
// detected inner format. It transparently unwraps a gzip envelope first —
// some capture tools (e.g. per-call SIP/RTP exports from Homer/FreeSWITCH)
// ship ".pcap" files that are actually gzip-compressed, the same case
// Wireshark/tshark handle by auto-decompressing before parsing. The
// returned closer must always be called.
func openCapture(path string, maxBytes int64) (pktReader, string, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("no se pudo abrir %q: %w", path, err)
	}
	closer := f.Close

	// Read only the envelope magic before applying the decoded-byte budget. A
	// buffered Peek over the raw file would otherwise let its prefetch bypass a
	// very small configured limit.
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(f, prefix); err != nil {
		f.Close()
		return nil, "", nil, fmt.Errorf("archivo demasiado corto o ilegible: %w", err)
	}

	var source io.Reader = io.MultiReader(bytes.NewReader(prefix), f)
	if prefix[0] == 0x1F && prefix[1] == 0x8B {
		gz, err := gzip.NewReader(source)
		if err != nil {
			f.Close()
			return nil, "", nil, fmt.Errorf("%q parece gzip pero no se pudo descomprimir: %w", path, err)
		}
		source = gz
		closer = func() error { gz.Close(); return f.Close() }
	}
	budget := &captureBudget{maxBytes: maxBytes}
	br := bufio.NewReader(&budgetReader{source: source, budget: budget})

	format, err := detectFormat(br)
	if err != nil {
		closer()
		if budget.exceeded {
			return nil, "", nil, budget.err()
		}
		return nil, "", nil, err
	}

	var reader pktReader
	if format == "pcapng" {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			closer()
			if budget.exceeded {
				return nil, "", nil, budget.err()
			}
			return nil, "", nil, fmt.Errorf("pcapng inválido: %w", err)
		}
		reader = ng
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			closer()
			if budget.exceeded {
				return nil, "", nil, budget.err()
			}
			return nil, "", nil, fmt.Errorf("pcap inválido: %w", err)
		}
		reader = r
	}
	return &budgetedPktReader{pktReader: reader, budget: budget}, format, closer, nil
}

type captureBudget struct {
	maxBytes int64
	read     int64
	exceeded bool
}

func (b *captureBudget) err() error {
	return fmt.Errorf("%w: máximo de %d MiB descomprimidos", ErrCaptureLimit, b.maxBytes>>20)
}

type budgetReader struct {
	source io.Reader
	budget *captureBudget
}

func (r *budgetReader) Read(p []byte) (int, error) {
	remaining := r.budget.maxBytes - r.budget.read
	if remaining <= 0 {
		r.budget.exceeded = true
		return 0, ErrCaptureLimit
	}
	if int64(len(p)) > remaining {
		p = p[:int(remaining)]
	}
	n, err := r.source.Read(p)
	r.budget.read += int64(n)
	return n, err
}

type budgetedPktReader struct {
	pktReader
	budget *captureBudget
}

func captureBudgetFor(reader pktReader) *captureBudget {
	return reader.(*budgetedPktReader).budget
}

// noteFix records a position that arrived with a frame. Only the first and
// last are kept: a survey of 80.000 frames would otherwise carry 80.000
// coordinates to the view for a question — "where was this taken" — that two
// answer.
func (i *Info) noteFix(f *ppi.Fix) {
	if !f.HasPosition() {
		return
	}
	i.GPSFixes++
	if i.FirstFix == nil {
		i.FirstFix = f
	}
	i.LastFix = f
}

// linkTypeName names a link type for display, supplying the ones gopacket has
// no name for but this package can read. Reporting "UnknownLinkType" for a
// capture we just decoded correctly would be plainly wrong.
func linkTypeName(lt layers.LinkType) string {
	if lt == ppi.LinkType {
		return "PPI"
	}
	return lt.String()
}

// isRawDot11 reports whether lt carries bare 802.11 frames, with no radio
// header in front to describe them.
func isRawDot11(lt layers.LinkType) bool {
	return lt == layers.LinkTypeIEEE802_11 || lt == layers.LinkTypePrismHeader
}

// dot11WithFCS returns the frame gopacket needs to decode data.
//
// gopacket's 802.11 decoder assumes every frame ends with a 4-byte FCS and
// removes it unconditionally. Plenty of captures are saved without one — the
// driver already checked it and dropped it — and on those gopacket eats four
// bytes of real frame instead. The damage is quiet and total: the last
// information element of a beacon comes up exactly 4 bytes short ("length 20
// too short, 24 required") and every ACK, 10 bytes long with no FCS, is
// rejected outright. On a real capture of 1.180 frames that was 800 frames
// mangled or lost.
//
// So the FCS is checked rather than assumed: if the last four bytes are the
// CRC-32 of everything before them, the frame has one and goes through
// untouched. If not, four bytes of padding are appended for gopacket to
// discard in place of real data. A frame whose FCS is genuinely corrupt gets
// padded too, which is the right trade — it was unreadable either way, and the
// alternative is mangling every frame in every capture saved without an FCS.
func dot11WithFCS(data []byte, lt layers.LinkType) []byte {
	crcData := data
	if lt == layers.LinkTypePrismHeader {
		if len(data) < 8 {
			return data
		}
		headerLen := int(binary.LittleEndian.Uint32(data[4:8]))
		if headerLen < 24 || headerLen > len(data) {
			return data
		}
		crcData = data[headerLen:]
	}
	if len(crcData) >= 8 {
		trailer := binary.LittleEndian.Uint32(crcData[len(crcData)-4:])
		if crc32.ChecksumIEEE(crcData[:len(crcData)-4]) == trailer {
			return data
		}
	}
	// A fresh slice: data points into the reader's buffer, which must not grow
	// under it.
	padded := make([]byte, len(data)+4)
	copy(padded, data)
	return padded
}

// linkDecoder returns the decoder to parse a frame of link type lt.
//
// gopacket maps most link types to a decoder itself, but not the 802.11 family:
// LinkTypeIEEE802_11.LayerType() answers "Unknown" even though LayerTypeDot11
// exists and decodes beacons, SSIDs and channels perfectly well. Without this
// table a monitor-mode capture reads as a file full of undecodable frames —
// the decoder was there all along, only unreachable through the link type.
//
// PPI is different: it is a wrapper, not a medium, so it gets unwrapped in
// readFrame instead of decoded here.
func linkDecoder(lt layers.LinkType) gopacket.Decoder {
	switch lt {
	case layers.LinkTypeIEEE802_11:
		return layers.LayerTypeDot11
	case layers.LinkTypePrismHeader:
		return layers.LayerTypePrismHeader
	}
	if d := lt.LayerType(); d != gopacket.LayerTypeZero {
		return lt
	}
	return lt // unknown: gopacket reports the failure per packet, counted as undecodable
}

// readFrame turns raw capture bytes into a packet, unwrapping a PPI header
// first when the capture has one.
//
// PPI is what wardriving tools put in front of each 802.11 frame to record what
// the radio knew — most usefully the GPS fix. Read as a medium it is opaque;
// unwrapped it is ordinary 802.11 plus, when the capture had a GPS attached,
// where the frame was heard. The position was recorded by whoever ran the
// capture on their own equipment: nothing is sent anywhere to interpret it.
func readFrame(data []byte, lt layers.LinkType, ci gopacket.CaptureInfo) (gopacket.Packet, *ppi.Fix) {
	if lt == ppi.LinkType {
		rec, err := ppi.Parse(data)
		if err != nil {
			// Falls through as an undecodable frame, which is what it is.
			return gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true}), nil
		}
		innerLT := layers.LinkType(rec.DLT)
		payload := rec.Payload
		if isRawDot11(innerLT) {
			payload = dot11WithFCS(payload, innerLT)
		}
		inner := gopacket.NewPacket(payload, linkDecoder(innerLT),
			gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		md := inner.Metadata()
		// La longitud reportada es la de la trama real, no la del relleno.
		md.CaptureInfo = gopacket.CaptureInfo{Timestamp: ci.Timestamp, CaptureLength: len(rec.Payload), Length: len(rec.Payload)}
		md.Timestamp = ci.Timestamp
		return inner, rec.Fix
	}
	frame := data
	if isRawDot11(lt) {
		frame = dot11WithFCS(frame, lt)
	}
	p := gopacket.NewPacket(frame, linkDecoder(lt), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	md := p.Metadata()
	// ci trae la longitud real de la trama; el relleno no debe contarse como bytes.
	md.CaptureInfo = ci
	md.Timestamp = ci.Timestamp
	return p, nil
}

// decapsulateTZSP returns the Ethernet packet travelling inside p when p is a
// TZSP datagram, or nil when it is not.
//
// A capture taken on the host that receives a TZSP stream — pointing the
// sniffer at the collector instead of at the segment being diagnosed — records
// every frame wrapped in one UDP conversation. Read literally that is a single
// flow between two endpoints, which is true and useless: the traffic the
// operator wants to see is inside. Live Capture already unwraps this when it
// receives the stream; doing it here too means the same capture reads the same
// way whether it arrived live or through a file.
func decapsulateTZSP(p gopacket.Packet, ci gopacket.CaptureInfo) gopacket.Packet {
	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || len(udp.Payload) == 0 {
		return nil
	}
	frame, ok := tzsp.Decapsulate(udp.Payload)
	if !ok {
		return nil
	}
	inner := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	// The envelope's timestamp is kept: it is when the frame was observed, and
	// the frame itself carries no time of its own.
	md := inner.Metadata()
	md.CaptureInfo = gopacket.CaptureInfo{Timestamp: ci.Timestamp, CaptureLength: len(frame), Length: len(frame)}
	md.Timestamp = ci.Timestamp
	return inner
}

// isUndecodable reports whether the link layer itself failed to parse, which
// is what happens with a capture of a medium gopacket has no decoder for.
func isUndecodable(p gopacket.Packet) bool {
	return p.ErrorLayer() != nil && len(p.Layers()) == 1
}

// detectFormat peeks the magic bytes without consuming them.
func detectFormat(br *bufio.Reader) (string, error) {
	magic, err := br.Peek(4)
	if err != nil {
		return "", fmt.Errorf("archivo demasiado corto o ilegible: %w", err)
	}
	// PCAPNG Section Header Block magic.
	if magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		return "pcapng", nil
	}
	// Classic PCAP magics (big/little endian, µs/ns).
	switch {
	case bytesEqual(magic, 0xA1, 0xB2, 0xC3, 0xD4),
		bytesEqual(magic, 0xD4, 0xC3, 0xB2, 0xA1),
		bytesEqual(magic, 0xA1, 0xB2, 0x3C, 0x4D),
		bytesEqual(magic, 0x4D, 0x3C, 0xB2, 0xA1):
		return "pcap", nil
	}
	return "", fmt.Errorf("formato no reconocido (no es PCAP ni PCAPNG)")
}

func bytesEqual(b []byte, a0, a1, a2, a3 byte) bool {
	return b[0] == a0 && b[1] == a1 && b[2] == a2 && b[3] == a3
}
