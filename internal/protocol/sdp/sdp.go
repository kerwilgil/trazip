// Package sdp is a stateless SDP (RFC 4566) parser used to read the media
// offer/answer carried in SIP INVITE/200 OK bodies (prompt maestro §9 Fase 3
// #14). It extracts codecs, media address/port, and direction so the VoIP
// correlator can match signaling against the RTP it actually observes.
package sdp

import (
	"strconv"
	"strings"
)

// Codec describes one negotiated/offered payload type.
type Codec struct {
	PayloadType int    `json:"payloadType"`
	Name        string `json:"name"`
	ClockRate   int    `json:"clockRate,omitempty"`
	Channels    int    `json:"channels,omitempty"`
	FMTP        string `json:"fmtp,omitempty"`
}

// Media is one m= section (typically "audio" for VoIP).
type Media struct {
	Type         string        `json:"type"` // audio | video | ...
	Port         int           `json:"port"`
	Proto        string        `json:"proto"` // RTP/AVP, RTP/SAVP, ...
	PayloadTypes []int         `json:"payloadTypes"`
	ConnAddr     string        `json:"connAddr,omitempty"`
	ConnFamily   string        `json:"connFamily,omitempty"` // IP4 | IP6
	Direction    string        `json:"direction"`            // sendrecv|sendonly|recvonly|inactive
	Codecs       map[int]Codec `json:"codecs,omitempty"`
	Candidates   []string      `json:"candidates,omitempty"` // raw ICE a=candidate lines
	PtimeMs      int           `json:"ptimeMs,omitempty"`
}

// SDP is a parsed session description.
type SDP struct {
	SessionConnAddr   string  `json:"sessionConnAddr,omitempty"`
	SessionConnFamily string  `json:"sessionConnFamily,omitempty"`
	Media             []Media `json:"media"`
}

// staticPayloadTypes is the RFC 3551 static assignment table, used when a
// media section has no explicit a=rtpmap for a given payload type.
var staticPayloadTypes = map[int]Codec{
	0:  {PayloadType: 0, Name: "PCMU", ClockRate: 8000},
	3:  {PayloadType: 3, Name: "GSM", ClockRate: 8000},
	4:  {PayloadType: 4, Name: "G723", ClockRate: 8000},
	5:  {PayloadType: 5, Name: "DVI4", ClockRate: 8000},
	6:  {PayloadType: 6, Name: "DVI4", ClockRate: 16000},
	7:  {PayloadType: 7, Name: "LPC", ClockRate: 8000},
	8:  {PayloadType: 8, Name: "PCMA", ClockRate: 8000},
	9:  {PayloadType: 9, Name: "G722", ClockRate: 8000},
	10: {PayloadType: 10, Name: "L16", ClockRate: 44100, Channels: 2},
	11: {PayloadType: 11, Name: "L16", ClockRate: 44100},
	12: {PayloadType: 12, Name: "QCELP", ClockRate: 8000},
	13: {PayloadType: 13, Name: "CN", ClockRate: 8000},
	15: {PayloadType: 15, Name: "G728", ClockRate: 8000},
	18: {PayloadType: 18, Name: "G729", ClockRate: 8000},
	31: {PayloadType: 31, Name: "H261", ClockRate: 90000},
	34: {PayloadType: 34, Name: "H263", ClockRate: 90000},
}

// StaticCodec returns the RFC 3551 well-known codec for a payload type, or a
// zero Codec if the type is dynamic (96-127) and unknown without an a=rtpmap.
func StaticCodec(pt int) (Codec, bool) {
	c, ok := staticPayloadTypes[pt]
	return c, ok
}

// Parse decodes an SDP body. It is defensive: malformed lines are skipped
// rather than aborting the whole parse, since VoIP traffic in the wild often
// carries vendor quirks.
func Parse(body []byte) *SDP {
	s := &SDP{}
	var cur *Media // nil = session level

	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		typ, val := line[0], strings.TrimSpace(line[2:])

		switch typ {
		case 'c':
			addr, fam := parseConn(val)
			if cur == nil {
				s.SessionConnAddr, s.SessionConnFamily = addr, fam
			} else {
				cur.ConnAddr, cur.ConnFamily = addr, fam
			}
		case 'm':
			if m := parseMediaLine(val); m != nil {
				m.ConnAddr, m.ConnFamily = s.SessionConnAddr, s.SessionConnFamily
				m.Direction = "sendrecv" // RFC 4566 default
				m.Codecs = make(map[int]Codec)
				s.Media = append(s.Media, *m)
				cur = &s.Media[len(s.Media)-1]
			}
		case 'a':
			applyAttribute(cur, val)
		}
	}

	// Fill in static codecs for payload types never covered by an a=rtpmap.
	for i := range s.Media {
		for _, pt := range s.Media[i].PayloadTypes {
			if _, ok := s.Media[i].Codecs[pt]; !ok {
				if c, ok := StaticCodec(pt); ok {
					s.Media[i].Codecs[pt] = c
				}
			}
		}
	}
	return s
}

func parseConn(val string) (addr, family string) {
	// "IN IP4 192.0.2.1" or "IN IP6 ::1"
	f := strings.Fields(val)
	if len(f) < 3 || f[0] != "IN" {
		return "", ""
	}
	addr = f[2]
	if slash := strings.IndexByte(addr, '/'); slash > 0 { // TTL/multicast suffix
		addr = addr[:slash]
	}
	return addr, f[1]
}

func parseMediaLine(val string) *Media {
	// "audio 49170 RTP/AVP 0 8 97"
	f := strings.Fields(val)
	if len(f) < 3 {
		return nil
	}
	port, err := strconv.Atoi(f[1])
	if err != nil {
		return nil
	}
	m := &Media{Type: f[0], Port: port, Proto: f[2]}
	for _, pt := range f[3:] {
		if n, err := strconv.Atoi(pt); err == nil {
			m.PayloadTypes = append(m.PayloadTypes, n)
		}
	}
	return m
}

func applyAttribute(m *Media, val string) {
	switch {
	case val == "sendrecv", val == "sendonly", val == "recvonly", val == "inactive":
		if m != nil {
			m.Direction = val
		}
	case strings.HasPrefix(val, "rtpmap:"):
		if m != nil {
			applyRTPMap(m, strings.TrimPrefix(val, "rtpmap:"))
		}
	case strings.HasPrefix(val, "fmtp:"):
		if m != nil {
			applyFMTP(m, strings.TrimPrefix(val, "fmtp:"))
		}
	case strings.HasPrefix(val, "candidate:"):
		if m != nil {
			m.Candidates = append(m.Candidates, val)
		}
	case strings.HasPrefix(val, "ptime:"):
		if m != nil {
			if n, err := strconv.Atoi(strings.TrimPrefix(val, "ptime:")); err == nil {
				m.PtimeMs = n
			}
		}
	}
}

func applyFMTP(m *Media, val string) {
	sp := strings.IndexAny(val, " \t")
	if sp <= 0 {
		return
	}
	pt, err := strconv.Atoi(val[:sp])
	if err != nil {
		return
	}
	c, ok := m.Codecs[pt]
	if !ok {
		c = Codec{PayloadType: pt}
	}
	c.FMTP = strings.TrimSpace(val[sp+1:])
	m.Codecs[pt] = c
}

// applyRTPMap parses "97 opus/48000/2" into a Codec keyed by payload type.
func applyRTPMap(m *Media, val string) {
	sp := strings.IndexByte(val, ' ')
	if sp <= 0 {
		return
	}
	pt, err := strconv.Atoi(val[:sp])
	if err != nil {
		return
	}
	spec := strings.Split(val[sp+1:], "/")
	c := Codec{PayloadType: pt, Name: spec[0]}
	if len(spec) >= 2 {
		if n, err := strconv.Atoi(spec[1]); err == nil {
			c.ClockRate = n
		}
	}
	if len(spec) >= 3 {
		if n, err := strconv.Atoi(spec[2]); err == nil {
			c.Channels = n
		}
	}
	m.Codecs[pt] = c
}
