// Package rtcp is a stateless RTCP (RFC 3550 §6) parser for Sender/Receiver
// Reports — prompt maestro §9 Fase 3 #15. RTCP is always sent as one or more
// packets concatenated in a single UDP datagram ("compound packet"), so
// ParseCompound walks the whole payload rather than parsing a single record.
package rtcp

import (
	"encoding/binary"
	"fmt"
)

// Packet types (RFC 3550 §12).
const (
	TypeSR   = 200
	TypeRR   = 201
	TypeSDES = 202
	TypeBYE  = 203
	TypeAPP  = 204
)

// ReportBlock is one reception report within an SR or RR (RFC 3550 §6.4.1).
type ReportBlock struct {
	SSRC           uint32  `json:"ssrc"`
	FractionLost   float64 `json:"fractionLostPct"` // 0-100, since the last report
	CumulativeLost int32   `json:"cumulativeLost"`
	HighestSeq     uint32  `json:"highestSeq"`
	JitterTicks    uint32  `json:"jitterTicks"` // RTP timestamp units; convert with the stream's clock rate
	LSR            uint32  `json:"lsr"`
	DLSR           uint32  `json:"dlsr"`
}

// Packet is one parsed RTCP record from a compound datagram.
type Packet struct {
	Type         int           `json:"type"`
	SSRC         uint32        `json:"ssrc"`
	NTPSeconds   uint32        `json:"ntpSeconds,omitempty"`   // SR only (NTP epoch, seconds)
	NTPFraction  uint32        `json:"ntpFraction,omitempty"`  // SR only (NTP fractional part)
	RTPTimestamp uint32        `json:"rtpTimestamp,omitempty"` // SR only
	PacketCount  uint32        `json:"packetCount,omitempty"`  // SR only
	OctetCount   uint32        `json:"octetCount,omitempty"`   // SR only
	Reports      []ReportBlock `json:"reports,omitempty"`
}

// ParseCompound decodes every RTCP sub-packet in a UDP payload. It stops and
// returns what it found so far if a length field would run past the buffer,
// rather than failing the whole compound packet on one bad record.
func ParseCompound(b []byte) ([]Packet, error) {
	var out []Packet
	for len(b) >= 4 {
		version := b[0] >> 6
		if version != 2 {
			break
		}
		rc := int(b[0] & 0x1f)
		pt := int(b[1])
		lengthWords := binary.BigEndian.Uint16(b[2:4])
		totalLen := (int(lengthWords) + 1) * 4
		if totalLen > len(b) || totalLen < 4 {
			break
		}
		body := b[4:totalLen]

		switch pt {
		case TypeSR:
			if p, ok := parseSR(body, rc); ok {
				out = append(out, p)
			}
		case TypeRR:
			if p, ok := parseRR(body, rc); ok {
				out = append(out, p)
			}
		case TypeBYE:
			if len(body) >= 4 {
				out = append(out, Packet{Type: TypeBYE, SSRC: binary.BigEndian.Uint32(body[:4])})
			}
		case TypeSDES, TypeAPP:
			out = append(out, Packet{Type: pt})
		}

		b = b[totalLen:]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no se encontraron paquetes RTCP válidos")
	}
	return out, nil
}

func parseSR(body []byte, rc int) (Packet, bool) {
	// Fixed SR part is 24 bytes: SSRC(4) + NTP seconds(4) + NTP fraction(4) +
	// RTP timestamp(4) + packet count(4) + octet count(4).
	if len(body) < 24 {
		return Packet{}, false
	}
	p := Packet{
		Type:         TypeSR,
		SSRC:         binary.BigEndian.Uint32(body[0:4]),
		NTPSeconds:   binary.BigEndian.Uint32(body[4:8]),
		NTPFraction:  binary.BigEndian.Uint32(body[8:12]),
		RTPTimestamp: binary.BigEndian.Uint32(body[12:16]),
		PacketCount:  binary.BigEndian.Uint32(body[16:20]),
		OctetCount:   binary.BigEndian.Uint32(body[20:24]),
	}
	p.Reports = parseReportBlocks(body[24:], rc)
	return p, true
}

func parseRR(body []byte, rc int) (Packet, bool) {
	if len(body) < 4 {
		return Packet{}, false
	}
	p := Packet{Type: TypeRR, SSRC: binary.BigEndian.Uint32(body[0:4])}
	p.Reports = parseReportBlocks(body[4:], rc)
	return p, true
}

func parseReportBlocks(body []byte, rc int) []ReportBlock {
	var blocks []ReportBlock
	for i := 0; i < rc; i++ {
		off := i * 24
		if off+24 > len(body) {
			break
		}
		blk := body[off : off+24]
		blocks = append(blocks, ReportBlock{
			SSRC:           binary.BigEndian.Uint32(blk[0:4]),
			FractionLost:   float64(blk[4]) / 256 * 100,
			CumulativeLost: signExtend24(blk[5:8]),
			HighestSeq:     binary.BigEndian.Uint32(blk[8:12]),
			JitterTicks:    binary.BigEndian.Uint32(blk[12:16]),
			LSR:            binary.BigEndian.Uint32(blk[16:20]),
			DLSR:           binary.BigEndian.Uint32(blk[20:24]),
		})
	}
	return blocks
}

// signExtend24 interprets 3 bytes as a 24-bit two's-complement integer.
func signExtend24(b []byte) int32 {
	v := int32(b[0])<<16 | int32(b[1])<<8 | int32(b[2])
	if v&0x800000 != 0 {
		v |= ^int32(0xFFFFFF) // sign-extend into the top byte
	}
	return v
}
