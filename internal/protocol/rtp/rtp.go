// Package rtp is a stateless RTP (RFC 3550) header parser plus a per-stream
// stats accumulator (jitter, loss, duplicates, reordering) — prompt maestro
// §9 Fase 3 #15. It never decodes audio; codec-level PCM decode for export
// lives in internal/voip/audio.go, gated behind an explicit user action per §16.
package rtp

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Header is a parsed RTP fixed header (plus CSRC count, no extension bytes kept).
type Header struct {
	Version     int
	Padding     bool
	Extension   bool
	CSRCCount   int
	Marker      bool
	PayloadType int
	SeqNum      uint16
	Timestamp   uint32
	SSRC        uint32
	HeaderLen   int // bytes consumed by the header (for locating the payload)
}

// rtcpPTMin/Max is the well-known RTCP packet-type range (RFC 3550/5761). RTP
// and RTCP share the same UDP port pair by convention (RTCP = RTP port + 1),
// but implementations increasingly multiplex both on one port, so packets must
// be told apart by inspecting this byte per RFC 5761 §4.
const rtcpPTMin, rtcpPTMax = 200, 204

// ParseHeader decodes an RTP fixed header. It rejects payloads that are too
// short, have the wrong version, or whose second byte falls in the RTCP
// packet-type range (RFC 5761 demux) — those are almost certainly RTCP, not RTP.
func ParseHeader(b []byte) (*Header, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("payload demasiado corto para RTP (%d bytes)", len(b))
	}
	version := int(b[0] >> 6)
	if version != 2 {
		return nil, fmt.Errorf("versión RTP inesperada: %d", version)
	}
	if b[1] >= rtcpPTMin && b[1] <= rtcpPTMax {
		return nil, fmt.Errorf("parece RTCP, no RTP (PT=%d)", b[1])
	}

	h := &Header{
		Version:     version,
		Padding:     b[0]&0x20 != 0,
		Extension:   b[0]&0x10 != 0,
		CSRCCount:   int(b[0] & 0x0f),
		Marker:      b[1]&0x80 != 0,
		PayloadType: int(b[1] & 0x7f),
		SeqNum:      binary.BigEndian.Uint16(b[2:4]),
		Timestamp:   binary.BigEndian.Uint32(b[4:8]),
		SSRC:        binary.BigEndian.Uint32(b[8:12]),
	}
	h.HeaderLen = 12 + h.CSRCCount*4
	if h.Extension && len(b) >= h.HeaderLen+4 {
		extLenWords := binary.BigEndian.Uint16(b[h.HeaderLen+2 : h.HeaderLen+4])
		h.HeaderLen += 4 + int(extLenWords)*4
	}
	if h.HeaderLen > len(b) {
		h.HeaderLen = len(b)
	}
	return h, nil
}

// Payload returns the RTP payload bytes for a raw packet given its parsed header.
func Payload(raw []byte, h *Header) []byte {
	if h.HeaderLen >= len(raw) {
		return nil
	}
	return raw[h.HeaderLen:]
}

// Sample is one received packet event fed to a Stream.
type Sample struct {
	Header  Header
	Arrival time.Time
}

// Stream accumulates RFC 3550 statistics for a single SSRC + 5-tuple.
type Stream struct {
	SSRC         uint32
	ClockRate    int // Hz; default 8000 if unknown (documented assumption)
	clockAssumed bool

	started    bool
	cycles     uint32 // sequence-number wrap count (RFC 3550 §A.1)
	baseSeq    uint16
	highestSeq uint16
	highestExt uint32 // extended form of highestSeq; avoids re-deriving via extend()
	received   int
	duplicates int
	reordered  int
	seen       map[uint32]struct{} // extended seq -> seen (bounded)

	lastArrival  time.Time
	firstArrival time.Time
	firstTS      uint32
	lastTS       uint32
	haveLast     bool
	jitter       float64 // RFC 3550 §A.8, in RTP timestamp units

	firstPT  int
	havePT   bool
	lastSeen time.Time
}

// NewStream creates an accumulator. clockRate should come from the negotiated
// SDP codec when known; pass 0 to fall back to 8000 Hz (the common VoIP rate),
// which is flagged as an assumption in the resulting Snapshot.
func NewStream(ssrc uint32, clockRate int) *Stream {
	assumed := clockRate <= 0
	if clockRate <= 0 {
		clockRate = 8000
	}
	return &Stream{SSRC: ssrc, ClockRate: clockRate, clockAssumed: assumed, seen: make(map[uint32]struct{})}
}

// Add folds one received packet into the stream statistics.
func (s *Stream) Add(sample Sample) {
	h := sample.Header
	s.lastSeen = sample.Arrival
	if !s.havePT {
		s.firstPT = h.PayloadType
		s.havePT = true
	}

	ext := s.extend(h.SeqNum)
	if _, dup := s.seen[ext]; dup {
		s.duplicates++
		return
	}
	if len(s.seen) < 100000 { // bound memory on pathological captures
		s.seen[ext] = struct{}{}
	}

	if !s.started {
		s.started = true
		s.firstArrival = sample.Arrival
		s.firstTS = h.Timestamp
		s.baseSeq = h.SeqNum
		s.highestSeq = h.SeqNum
		s.highestExt = ext
	} else if ext < s.highestExt {
		s.reordered++
	} else {
		s.highestSeq = h.SeqNum
		s.highestExt = ext
	}
	s.received++

	// RFC 3550 §A.8 interarrival jitter, computed directly in RTP timestamp
	// units using wall-clock arrival converted via ClockRate.
	if s.haveLast {
		dArrival := sample.Arrival.Sub(s.lastArrival).Seconds() * float64(s.ClockRate)
		dTimestamp := float64(int64(h.Timestamp) - int64(s.lastTS))
		d := math.Abs(dArrival - dTimestamp)
		s.jitter += (d - s.jitter) / 16
	}
	s.lastArrival = sample.Arrival
	s.lastTS = h.Timestamp
	s.haveLast = true
}

// extend converts a 16-bit sequence number into a monotonically increasing
// "extended" sequence using wrap detection (RFC 3550 §A.1, simplified).
func (s *Stream) extend(seq uint16) uint32 {
	if s.started && seq < s.highestSeq && s.highestSeq-seq > 0x8000 {
		s.cycles++
	} else if s.started && seq > s.highestSeq && seq-s.highestSeq > 0x8000 {
		s.cycles--
	}
	return uint32(s.cycles)<<16 | uint32(seq)
}

// Snapshot is the immutable statistics view.
type Snapshot struct {
	SSRC              uint32    `json:"ssrc"`
	PayloadType       int       `json:"payloadType"`
	ClockRate         int       `json:"clockRate"`
	ClockAssumed      bool      `json:"clockAssumed"` // true if ClockRate defaulted (no SDP match)
	Received          int       `json:"received"`
	Expected          int       `json:"expected"`
	Lost              int       `json:"lost"`
	LossPct           float64   `json:"lossPct"`
	Duplicates        int       `json:"duplicates"`
	Reordered         int       `json:"reordered"`
	JitterMs          float64   `json:"jitterMs"`
	ArrivalDurationMs float64   `json:"arrivalDurationMs"`
	RTPDurationMs     float64   `json:"rtpDurationMs"`
	ClockSkewMs       float64   `json:"clockSkewMs"`
	FirstSeen         time.Time `json:"-"`
	FirstTimestamp    uint32    `json:"-"`
	LastTimestamp     uint32    `json:"-"`
	LastSeen          time.Time `json:"-"`
}

// Snapshot computes the current statistics.
func (s *Stream) Snapshot() Snapshot {
	snap := Snapshot{
		SSRC: s.SSRC, PayloadType: s.firstPT, ClockRate: s.ClockRate,
		ClockAssumed: s.clockAssumed,
		Received:     s.received, Duplicates: s.duplicates, Reordered: s.reordered,
		JitterMs: round2(s.jitter / float64(s.ClockRate) * 1000),
		LastSeen: s.lastSeen,
	}
	if s.started {
		snap.FirstSeen = s.firstArrival
		snap.FirstTimestamp = s.firstTS
		snap.LastTimestamp = s.lastTS
		snap.ArrivalDurationMs = round2(s.lastSeen.Sub(s.firstArrival).Seconds() * 1000)
		rtpTicks := uint32(s.lastTS - s.firstTS) // uint32 subtraction handles timestamp wrap.
		snap.RTPDurationMs = round2(float64(rtpTicks) / float64(s.ClockRate) * 1000)
		snap.ClockSkewMs = round2(snap.ArrivalDurationMs - snap.RTPDurationMs)
		snap.Expected = int(s.highestExt-uint32(s.baseSeq)) + 1
		if snap.Expected < snap.Received {
			snap.Expected = snap.Received
		}
		snap.Lost = snap.Expected - snap.Received
		if snap.Lost < 0 {
			snap.Lost = 0
		}
		if snap.Expected > 0 {
			snap.LossPct = round2(float64(snap.Lost) / float64(snap.Expected) * 100)
		}
	}
	return snap
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// DTMFEvent is a decoded RFC 4733 telephone-event payload.
type DTMFEvent struct {
	Digit      string // 0-9, *, #, A-D
	EndOfEvent bool
	Volume     int
	Duration   uint16
}

var dtmfDigits = "0123456789*#ABCD"

// DecodeDTMFEvent decodes an RFC 4733 telephone-event payload (4 bytes).
// Returns ok=false if the payload is too short or the event code is unknown.
func DecodeDTMFEvent(payload []byte) (DTMFEvent, bool) {
	if len(payload) < 4 {
		return DTMFEvent{}, false
	}
	event := int(payload[0])
	if event >= len(dtmfDigits) {
		return DTMFEvent{}, false
	}
	return DTMFEvent{
		Digit:      string(dtmfDigits[event]),
		EndOfEvent: payload[1]&0x80 != 0,
		Volume:     int(payload[1] & 0x3f),
		Duration:   binary.BigEndian.Uint16(payload[2:4]),
	}, true
}
