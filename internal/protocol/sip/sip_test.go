package sip

import "testing"

const invite = "INVITE sip:bob@biloxi.com SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n" +
	"Max-Forwards: 70\r\n" +
	"To: Bob <sip:bob@biloxi.com>\r\n" +
	"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n" +
	"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
	"CSeq: 314159 INVITE\r\n" +
	"Contact: <sip:alice@pc33.atlanta.com>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 3\r\n" +
	"\r\n" +
	"v=0"

const okResponse = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n" +
	"To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n" +
	"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n" +
	"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
	"CSeq: 314159 INVITE\r\n" +
	"Contact: <sip:bob@192.0.2.4>\r\n" +
	"Content-Length: 0\r\n\r\n"

const challenge = "SIP/2.0 401 Unauthorized\r\n" +
	"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n" +
	"To: Bob <sip:bob@biloxi.com>;tag=xyz\r\n" +
	"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n" +
	"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
	"CSeq: 314159 INVITE\r\n" +
	"WWW-Authenticate: Digest realm=\"biloxi.com\", nonce=\"abc123\"\r\n" +
	"Content-Length: 0\r\n\r\n"

func TestParseInvite(t *testing.T) {
	m, err := Parse([]byte(invite))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.IsRequest || m.Method != "INVITE" {
		t.Errorf("method wrong: request=%v method=%q", m.IsRequest, m.Method)
	}
	if m.CallID != "a84b4c76e66710@pc33.atlanta.com" {
		t.Errorf("Call-ID = %q", m.CallID)
	}
	if m.FromTag != "1928301774" {
		t.Errorf("FromTag = %q", m.FromTag)
	}
	if m.ToTag != "" {
		t.Errorf("ToTag should be empty in initial INVITE, got %q", m.ToTag)
	}
	if m.CSeqNum != 314159 || m.CSeqMethod != "INVITE" {
		t.Errorf("CSeq wrong: %d %q", m.CSeqNum, m.CSeqMethod)
	}
	if m.ViaBranch != "z9hG4bK776asdhds" || m.ViaProto != "UDP" {
		t.Errorf("Via wrong: branch=%q proto=%q", m.ViaBranch, m.ViaProto)
	}
	if m.ContentType != "application/sdp" {
		t.Errorf("ContentType = %q", m.ContentType)
	}
	if string(m.Body) != "v=0" {
		t.Errorf("Body = %q, want v=0", string(m.Body))
	}
}

func TestParseOKResponse(t *testing.T) {
	m, err := Parse([]byte(okResponse))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.IsRequest || m.StatusCode != 200 || m.Reason != "OK" {
		t.Errorf("status wrong: request=%v code=%d reason=%q", m.IsRequest, m.StatusCode, m.Reason)
	}
	if m.Method != "INVITE" {
		t.Errorf("Method (from CSeq) = %q, want INVITE", m.Method)
	}
	if m.ToTag != "a6c85cf" {
		t.Errorf("ToTag = %q", m.ToTag)
	}
	if m.CallID != "a84b4c76e66710@pc33.atlanta.com" {
		t.Errorf("Call-ID mismatch with request: %q", m.CallID)
	}
}

func TestChallenge(t *testing.T) {
	m, err := Parse([]byte(challenge))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.Challenged {
		t.Error("expected Challenged=true")
	}
	if m.AuthRealm != "biloxi.com" {
		t.Errorf("AuthRealm = %q, want biloxi.com", m.AuthRealm)
	}
	if m.Authorized {
		t.Error("401 response should not set Authorized")
	}
}

func TestLooksLikeSIP(t *testing.T) {
	if !LooksLikeSIP([]byte(invite)) {
		t.Error("INVITE should look like SIP")
	}
	if !LooksLikeSIP([]byte(okResponse)) {
		t.Error("200 OK should look like SIP")
	}
	if LooksLikeSIP([]byte("GET / HTTP/1.1\r\n\r\n")) {
		t.Error("HTTP should not look like SIP")
	}
	if LooksLikeSIP(nil) || LooksLikeSIP([]byte{}) {
		t.Error("empty payload should not look like SIP")
	}
}

func TestParseRobustGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0x00, 0x01}, []byte("random junk\r\nmore junk")} {
		if _, err := Parse(b); err == nil {
			t.Errorf("Parse(%q) should error on non-SIP input", b)
		}
	}
}

func TestCompactHeaders(t *testing.T) {
	raw := "INVITE sip:bob@biloxi.com SIP/2.0\r\n" +
		"v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK1\r\n" +
		"t: Bob <sip:bob@biloxi.com>\r\n" +
		"f: Alice <sip:alice@atlanta.com>;tag=111\r\n" +
		"i: compact-call-id\r\n" +
		"CSeq: 1 INVITE\r\n\r\n"
	m, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.CallID != "compact-call-id" {
		t.Errorf("compact Call-ID (i:) not resolved: %q", m.CallID)
	}
	if m.FromTag != "111" {
		t.Errorf("compact From (f:) tag not resolved: %q", m.FromTag)
	}
	if m.ViaBranch != "z9hG4bK1" {
		t.Errorf("compact Via (v:) not resolved: %q", m.ViaBranch)
	}
}
