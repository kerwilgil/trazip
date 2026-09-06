package voip

import (
	"testing"

	"trazip/internal/protocol/sdp"
)

func TestAuditCallsFlagsPlainSIPAndRTP(t *testing.T) {
	r := AuditCalls([]Call{{CallID: "x", Timeline: []TimelineEvent{{Summary: "INVITE"}}, SDPOffer: &sdp.SDP{Media: []sdp.Media{{Type: "audio", Proto: "RTP/AVP"}}}}})
	if r.Medium < 2 || len(r.Findings) < 2 {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestAuditCallsRecognizesSecureMedia(t *testing.T) {
	r := AuditCalls([]Call{{CallID: "x", SDPOffer: &sdp.SDP{Media: []sdp.Media{{Type: "audio", Proto: "RTP/SAVP"}}}, Authenticated: true}})
	for _, f := range r.Findings {
		if f.Category == "unencrypted_rtp" {
			t.Fatalf("false finding: %+v", r)
		}
	}
}
