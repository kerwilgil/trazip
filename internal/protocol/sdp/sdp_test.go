package sdp

import "testing"

const offer = "v=0\r\n" +
	"o=alice 2890844526 2890844526 IN IP4 atlanta.com\r\n" +
	"s=-\r\n" +
	"c=IN IP4 192.0.2.10\r\n" +
	"t=0 0\r\n" +
	"m=audio 49170 RTP/AVP 0 8 97\r\n" +
	"a=rtpmap:97 opus/48000/2\r\n" +
	"a=sendrecv\r\n" +
	"a=ptime:20\r\n" +
	"a=candidate:1 1 UDP 2130706431 192.0.2.10 49170 typ host\r\n"

func TestParseOffer(t *testing.T) {
	s := Parse([]byte(offer))
	if s.SessionConnAddr != "192.0.2.10" || s.SessionConnFamily != "IP4" {
		t.Errorf("session conn = %q/%q", s.SessionConnAddr, s.SessionConnFamily)
	}
	if len(s.Media) != 1 {
		t.Fatalf("expected 1 media section, got %d", len(s.Media))
	}
	m := s.Media[0]
	if m.Type != "audio" || m.Port != 49170 || m.Proto != "RTP/AVP" {
		t.Errorf("media line wrong: %+v", m)
	}
	if len(m.PayloadTypes) != 3 {
		t.Errorf("payload types = %v, want 3 entries", m.PayloadTypes)
	}
	if m.Direction != "sendrecv" {
		t.Errorf("direction = %q, want sendrecv", m.Direction)
	}
	if m.PtimeMs != 20 {
		t.Errorf("ptime = %d, want 20", m.PtimeMs)
	}
	if len(m.Candidates) != 1 {
		t.Errorf("expected 1 ICE candidate, got %d", len(m.Candidates))
	}

	// Dynamic payload type 97 came from a=rtpmap.
	if c, ok := m.Codecs[97]; !ok || c.Name != "opus" || c.ClockRate != 48000 || c.Channels != 2 {
		t.Errorf("codec 97 = %+v", c)
	}
	// Static payload types 0 (PCMU) and 8 (PCMA) filled from RFC 3551 table.
	if c, ok := m.Codecs[0]; !ok || c.Name != "PCMU" || c.ClockRate != 8000 {
		t.Errorf("codec 0 (static PCMU) = %+v", c)
	}
	if c, ok := m.Codecs[8]; !ok || c.Name != "PCMA" {
		t.Errorf("codec 8 (static PCMA) = %+v", c)
	}
}

func TestDirectionVariants(t *testing.T) {
	body := "v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 1000 RTP/AVP 0\r\na=sendonly\r\n" +
		"m=audio 2000 RTP/AVP 0\r\na=inactive\r\n"
	s := Parse([]byte(body))
	if len(s.Media) != 2 {
		t.Fatalf("expected 2 media sections, got %d", len(s.Media))
	}
	if s.Media[0].Direction != "sendonly" {
		t.Errorf("media0 direction = %q", s.Media[0].Direction)
	}
	if s.Media[1].Direction != "inactive" {
		t.Errorf("media1 direction = %q", s.Media[1].Direction)
	}
}

func TestMediaLevelConnOverride(t *testing.T) {
	body := "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 1000 RTP/AVP 0\r\nc=IN IP4 2.2.2.2\r\n"
	s := Parse([]byte(body))
	if s.SessionConnAddr != "1.1.1.1" {
		t.Errorf("session conn = %q", s.SessionConnAddr)
	}
	if s.Media[0].ConnAddr != "2.2.2.2" {
		t.Errorf("media conn override = %q, want 2.2.2.2", s.Media[0].ConnAddr)
	}
}

func TestParseRobustGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte("not sdp at all"), []byte("m=\r\nc=\r\na=\r\n")} {
		s := Parse(b) // must never panic
		if s == nil {
			t.Error("Parse should never return nil")
		}
	}
}
