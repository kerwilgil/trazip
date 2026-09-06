package voip

import (
	"strings"
	"testing"

	"trazip/internal/protocol/rtp"
	"trazip/internal/protocol/sdp"
)

func audioSDP(connAddr string, port int, codecs map[int]sdp.Codec) *sdp.SDP {
	pts := make([]int, 0, len(codecs))
	for pt := range codecs {
		pts = append(pts, pt)
	}
	return &sdp.SDP{Media: []sdp.Media{{
		Type: "audio", Port: port, Proto: "RTP/AVP", ConnAddr: connAddr,
		PayloadTypes: pts, Codecs: codecs,
	}}}
}

func TestCompareMediaToRTPNoFindingsWhenEverythingMatches(t *testing.T) {
	c := &Call{
		SDPAnswer: audioSDP("192.0.2.10", 40000, map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}),
		Streams: []StreamInfo{
			{Src: "192.0.2.10:40000", Dst: "192.0.2.20:40002", PayloadType: 0, ClockRate: 8000, Stats: rtp.Snapshot{}},
		},
	}
	got := compareMediaToRTP(c)
	if len(got) != 0 {
		t.Errorf("expected no findings when SDP and RTP agree, got %+v", got)
	}
}

func TestCompareMediaToRTPFlagsAddressMismatch(t *testing.T) {
	// Only SDPAnswer captured (no offer) — every pair's Offer side is nil,
	// so classification can only ever succeed against the answer's address.
	// Neither Src nor Dst matches it at all, so classification fails and
	// this must surface as "can't associate", not a guessed direction.
	c := &Call{
		SDPAnswer: audioSDP("192.0.2.10", 40000, map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}),
		Streams: []StreamInfo{
			{Src: "198.51.100.9:40000", Dst: "198.51.100.9:40002", PayloadType: 0, ClockRate: 8000},
		},
	}
	got := compareMediaToRTP(c)
	if !anyFindingContains(got, "No se pudo asociar") {
		t.Errorf("expected an unclassifiable-stream finding, got %+v", got)
	}
}

func TestCompareMediaToRTPFlagsUnannouncedPayloadType(t *testing.T) {
	c := &Call{
		SDPAnswer: audioSDP("192.0.2.10", 40000, map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}),
		Streams: []StreamInfo{
			{Src: "192.0.2.10:40000", Dst: "192.0.2.20:40002", PayloadType: 8, ClockRate: 8000}, // PT 8 (PCMA) never negotiated
		},
	}
	got := compareMediaToRTP(c)
	if !anyFindingContains(got, "no aparece entre los anunciados") {
		t.Errorf("expected an unannounced-payload-type finding, got %+v", got)
	}
}

func TestCompareMediaToRTPFlagsClockRateMismatch(t *testing.T) {
	c := &Call{
		SDPAnswer: audioSDP("192.0.2.10", 40000, map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}),
		Streams: []StreamInfo{
			{Src: "192.0.2.10:40000", Dst: "192.0.2.20:40002", PayloadType: 0, ClockRate: 16000, Stats: rtp.Snapshot{ClockAssumed: false}},
		},
	}
	got := compareMediaToRTP(c)
	if !anyFindingContains(got, "Clock rate observado") {
		t.Errorf("expected a clock-rate-mismatch finding, got %+v", got)
	}
}

func TestCompareMediaToRTPFlagsAssumedClockAsInfoNotWarn(t *testing.T) {
	c := &Call{
		SDPAnswer: audioSDP("192.0.2.10", 40000, map[int]sdp.Codec{96: {PayloadType: 96, Name: "opus", ClockRate: 48000}}),
		Streams: []StreamInfo{
			{Src: "192.0.2.10:40000", Dst: "192.0.2.20:40002", PayloadType: 96, ClockRate: 8000, Stats: rtp.Snapshot{ClockAssumed: true}},
		},
	}
	got := compareMediaToRTP(c)
	found := false
	for _, f := range got {
		if strings.Contains(f.Summary, "no pudo confirmarse") {
			found = true
			if f.Level != "info" {
				t.Errorf("an assumed clock rate is a limitation, not a warning: level=%q", f.Level)
			}
		}
	}
	if !found {
		t.Errorf("expected an assumed-clock-rate finding, got %+v", got)
	}
}

func TestCompareMediaToRTPNilWithoutSDPOrStreams(t *testing.T) {
	if got := compareMediaToRTP(&Call{}); got != nil {
		t.Errorf("no SDP and no streams must yield no findings, got %+v", got)
	}
	c := &Call{SDPAnswer: audioSDP("192.0.2.10", 40000, nil)}
	if got := compareMediaToRTP(c); got != nil {
		t.Errorf("SDP without any matched stream must yield no findings, got %+v", got)
	}
}

func anyFindingContains(findings []MediaFinding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Summary, substr) {
			return true
		}
	}
	return false
}

// biCallOfferAnswer builds the offer/answer pair from the required
// bidirectional test scenario: caller media 10.0.0.1:4000 (offer), callee
// media 10.0.0.2:5000 (answer), both negotiating PCMU only.
func biCallOfferAnswer() (offer, answer *sdp.SDP) {
	codecs := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	return audioSDP("10.0.0.1", 4000, codecs), audioSDP("10.0.0.2", 5000, codecs)
}

func TestCompareMediaToRTPBidirectionalNoFindingsWhenBothLegsCorrect(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
			{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 0, ClockRate: 8000},
		},
	}
	if got := compareMediaToRTP(c); len(got) != 0 {
		t.Errorf("both legs match their negotiated destination — expected zero findings, got %+v", got)
	}
}

// TestCompareMediaToRTPBidirectionalFlagsWrongReturnDestination is the case
// the pre-direction-aware implementation missed entirely: the return leg's
// SOURCE (10.0.0.2:5000) exactly matches what the answer declared, so a
// naive "matches Src OR Dst" check calls it fine — but its DESTINATION is
// wrong, and only a direction-aware check (comparing this leg against the
// OFFER, since it heads toward the offerer) catches it.
func TestCompareMediaToRTPBidirectionalFlagsWrongReturnDestination(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
			{Src: "10.0.0.2:5000", Dst: "10.0.0.99:9999", PayloadType: 0, ClockRate: 8000},
		},
	}
	got := compareMediaToRTP(c)
	if !anyFindingContains(got, "10.0.0.99:9999") || !anyFindingContains(got, "10.0.0.1:4000") {
		t.Errorf("expected a finding naming the wrong observed destination (10.0.0.99:9999) against the OFFER's address (10.0.0.1:4000), got %+v", got)
	}
	for _, f := range got {
		if strings.Contains(f.Summary, "10.0.0.2:5000") && strings.Contains(f.Summary, "Destino RTP") {
			t.Errorf("must never compare the return leg against the ANSWER's address (10.0.0.2:5000) — that's the address it correctly came FROM, not where it should have gone: %q", f.Summary)
		}
	}
}

func TestCompareMediaToRTPFlagsPortMismatchWithCorrectIP(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
			{Src: "10.0.0.2:5000", Dst: "10.0.0.1:9999", PayloadType: 0, ClockRate: 8000}, // right IP, wrong port
		},
	}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "10.0.0.1:9999") {
		t.Errorf("expected a destination finding for the port-only mismatch, got %+v", got)
	}
}

func TestCompareMediaToRTPFlagsIPMismatchWithCorrectPort(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
			{Src: "10.0.0.2:5000", Dst: "10.0.0.55:4000", PayloadType: 0, ClockRate: 8000}, // right port, wrong IP
		},
	}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "10.0.0.55:4000") {
		t.Errorf("expected a destination finding for the IP-only mismatch, got %+v", got)
	}
}

func TestCompareMediaToRTPBidirectionalFlagsUnannouncedPayloadType(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
			{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 8, ClockRate: 8000}, // PT 8 never negotiated
		},
	}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "no aparece entre los anunciados") {
		t.Errorf("expected an unannounced-payload-type finding, got %+v", got)
	}
}

// TestCompareMediaToRTPUnclassifiableStreamYieldsInfoNotWrongGuess covers a
// stream whose addresses match neither the offer nor the answer at all
// (not even by IP) — classifyLeg must return "can't tell", and the result
// must be a single informational note, never a guessed direction paired
// with a confidently wrong address/port finding.
func TestCompareMediaToRTPUnclassifiableStreamYieldsInfoNotWrongGuess(t *testing.T) {
	offer, answer := biCallOfferAnswer()
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "203.0.113.5:1234", Dst: "203.0.113.6:5678", PayloadType: 0, ClockRate: 8000},
		},
	}
	got := compareMediaToRTP(c)
	if len(got) != 1 || got[0].Level != "info" {
		t.Fatalf("an unclassifiable stream must yield exactly one informational finding, not a guessed direction/address warning: %+v", got)
	}
	if !anyFindingContains(got, "No se pudo asociar") {
		t.Errorf("expected the 'cannot associate with a media section' finding, got %+v", got)
	}
}

// --- Independent audit, third gate ---

// Gate v0.7.3 (independent audit, gate of closure, item 1): destination is
// the primary evidence for CLASSIFICATION, but SDP never promises a sending
// address at all — only where a party wants to RECEIVE. A stream whose Src
// happens to match the OFFER's declared address but whose Dst ALSO equals it
// (never reaching the answerer at all) must classify via the destination —
// arriving AT the offerer — and produce NO finding at all about the source:
// there is no "origin SDP announced" to compare against, so the mismatch
// between Src and what a naive reading might expect is not an SDP violation,
// just an unremarkable fact about a passively observed capture.
func TestCompareMediaToRTPDestinationOverridesSourceMatch(t *testing.T) {
	offer, answer := biCallOfferAnswer() // offer 10.0.0.1:4000, answer 10.0.0.2:5000
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.1:4000", PayloadType: 0, ClockRate: 8000},
		},
	}
	got := compareMediaToRTP(c)
	if len(got) != 0 {
		t.Errorf("Dst matches the offer's address exactly (that's how direction was classified) — SDP makes no promise about Src at all, so this must produce zero findings, got %+v", got)
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 1): SDP does not
// promise a sending address — a stream's Src being completely different
// from anything negotiated (NAT, a different local interface, asymmetric
// RTP, an SBC) is fully compatible with a correct negotiation as long as the
// DESTINATION and codec are right. Must produce zero direction/port findings.
func TestCompareMediaToRTPSourceAddressDifferenceAloneIsNotAnSDPViolation(t *testing.T) {
	offer, answer := biCallOfferAnswer() // offer 10.0.0.1:4000, answer 10.0.0.2:5000
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			// Correct destination (matches the answer exactly, so this
			// classifies cleanly as Offerer->Answerer), but the source is a
			// totally unrelated address/port — e.g. NAT rewriting, or a
			// different local interface than the one SDP happened to name.
			{Src: "198.51.100.9:60000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
		},
	}
	if got := compareMediaToRTP(c); len(got) != 0 {
		t.Errorf("correct destination + correct codec, source is irrelevant to SDP validity — expected zero findings, got %+v", got)
	}
}

// Item 4: a session with audio AND video must never compare a video stream
// against the audio section (or vice versa) just because audio came first.
func TestCompareMediaToRTPMultiMediaAudioVideoNoCrossContamination(t *testing.T) {
	pcmu := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	h264 := map[int]sdp.Codec{97: {PayloadType: 97, Name: "H264", ClockRate: 90000}}
	offer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{0}, Codecs: pcmu},
		{Type: "video", Port: 4002, ConnAddr: "10.0.0.1", PayloadTypes: []int{97}, Codecs: h264},
	}}
	answer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 5000, ConnAddr: "10.0.0.2", PayloadTypes: []int{0}, Codecs: pcmu},
		{Type: "video", Port: 5002, ConnAddr: "10.0.0.2", PayloadTypes: []int{97}, Codecs: h264},
	}}
	streams := []StreamInfo{
		{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
		{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 0, ClockRate: 8000},
		{Src: "10.0.0.1:4002", Dst: "10.0.0.2:5002", PayloadType: 97, ClockRate: 90000},
		{Src: "10.0.0.2:5002", Dst: "10.0.0.1:4002", PayloadType: 97, ClockRate: 90000},
	}
	if got := compareMediaToRTP(&Call{SDPOffer: offer, SDPAnswer: answer, Streams: streams}); len(got) != 0 {
		t.Errorf("all four legs match their own negotiated section — expected zero findings, got %+v", got)
	}

	// Break ONLY the video return leg's destination.
	streams[3].Dst = "10.0.0.99:9999"
	got := compareMediaToRTP(&Call{SDPOffer: offer, SDPAnswer: answer, Streams: streams})
	if !anyFindingContains(got, "10.0.0.99:9999") || !anyFindingContains(got, "10.0.0.1:4002") {
		t.Errorf("expected a finding naming the broken video destination against the video offer port 4002, got %+v", got)
	}
	if anyFindingContains(got, "4000") || anyFindingContains(got, "5000") {
		t.Errorf("the audio pair (ports 4000/5000) must never appear in a finding about the broken VIDEO leg: %+v", got)
	}
}

// Item 4: two m=audio sections must not collapse onto "the first audio".
func TestCompareMediaToRTPTwoAudioSectionsDoNotCollapseToFirst(t *testing.T) {
	pcmu := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	g729 := map[int]sdp.Codec{18: {PayloadType: 18, Name: "G729", ClockRate: 8000}}
	offer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{0}, Codecs: pcmu},
		{Type: "audio", Port: 4010, ConnAddr: "10.0.0.1", PayloadTypes: []int{18}, Codecs: g729},
	}}
	answer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 5000, ConnAddr: "10.0.0.2", PayloadTypes: []int{0}, Codecs: pcmu},
		{Type: "audio", Port: 5010, ConnAddr: "10.0.0.2", PayloadTypes: []int{18}, Codecs: g729},
	}}
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.2:5010", Dst: "10.0.0.1:4010", PayloadType: 18, ClockRate: 8000}, // the SECOND section
		},
	}
	if got := compareMediaToRTP(c); len(got) != 0 {
		t.Errorf("stream correctly matches the second audio section (index 1), must not be compared against the first: %+v", got)
	}
}

// Item 14, CASO 1: a codec present in the offer but never accepted by the
// answer must be flagged, even though its raw PT number "exists" in the
// offer.
func TestCompareMediaToRTPCodecRejectedByAnswerIsFlagged(t *testing.T) {
	offer := audioSDP("10.0.0.1", 4000, map[int]sdp.Codec{
		0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000},
		8: {PayloadType: 8, Name: "PCMA", ClockRate: 8000},
	})
	answer := audioSDP("10.0.0.2", 5000, map[int]sdp.Codec{
		0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}, // PCMA (PT8) not accepted
	})
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 8, ClockRate: 8000},
		},
	}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "no quedó aceptado en la negociación") {
		t.Errorf("PCMA (PT8) exists in the offer but was never accepted by the answer — expected a rejected-codec finding, got %+v", got)
	}
}

// Item 14, CASO 2: offer and answer can legitimately use DIFFERENT payload
// type numbers for the identical negotiated codec.
func TestCompareMediaToRTPDifferentPTNumbersSameCodecIsValid(t *testing.T) {
	offer := audioSDP("10.0.0.1", 4000, map[int]sdp.Codec{96: {PayloadType: 96, Name: "opus", ClockRate: 48000, Channels: 2}})
	answer := audioSDP("10.0.0.2", 5000, map[int]sdp.Codec{110: {PayloadType: 110, Name: "opus", ClockRate: 48000, Channels: 2}})
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 110, ClockRate: 48000}, // offerer sends using the ANSWER's PT number
			{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 96, ClockRate: 48000},  // answerer sends using the OFFER's PT number
		},
	}
	if got := compareMediaToRTP(c); len(got) != 0 {
		t.Errorf("both streams use a PT number that resolves to opus on the OTHER side, and opus is accepted by both — expected zero findings, got %+v", got)
	}
}

// Item 14, CASO 3: the SAME raw PT number can mean different codecs on each
// side — identity (name/clockRate/channels) must be checked, not just "the
// PT number exists somewhere".
func TestCompareMediaToRTPSamePTDifferentCodecIdentityIsFlagged(t *testing.T) {
	offer := audioSDP("10.0.0.1", 4000, map[int]sdp.Codec{110: {PayloadType: 110, Name: "opus", ClockRate: 48000, Channels: 2}})
	answer := audioSDP("10.0.0.2", 5000, map[int]sdp.Codec{110: {PayloadType: 110, Name: "speex", ClockRate: 16000}})
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 110, ClockRate: 48000},
		},
	}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "no quedó aceptado en la negociación") {
		t.Errorf("PT110 is opus/48000 on the offer but speex/16000 on the answer — different identity, must be flagged, got %+v", got)
	}
}

// Item 14, CASO 4: audio and video reusing the same dynamic PT number must
// each validate against their OWN media section, never the other's.
func TestCompareMediaToRTPSamePTReusedAcrossAudioVideoValidatesPerSection(t *testing.T) {
	audioCodec := map[int]sdp.Codec{97: {PayloadType: 97, Name: "PCMU", ClockRate: 8000}}
	videoCodec := map[int]sdp.Codec{97: {PayloadType: 97, Name: "H264", ClockRate: 90000}}
	offer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{97}, Codecs: audioCodec},
		{Type: "video", Port: 4002, ConnAddr: "10.0.0.1", PayloadTypes: []int{97}, Codecs: videoCodec},
	}}
	answer := &sdp.SDP{Media: []sdp.Media{
		{Type: "audio", Port: 5000, ConnAddr: "10.0.0.2", PayloadTypes: []int{97}, Codecs: audioCodec},
		{Type: "video", Port: 5002, ConnAddr: "10.0.0.2", PayloadTypes: []int{97}, Codecs: videoCodec},
	}}
	c := &Call{
		SDPOffer:  offer,
		SDPAnswer: answer,
		Streams: []StreamInfo{
			{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 97, ClockRate: 8000},
			{Src: "10.0.0.1:4002", Dst: "10.0.0.2:5002", PayloadType: 97, ClockRate: 90000},
		},
	}
	if got := compareMediaToRTP(c); len(got) != 0 {
		t.Errorf("each stream matches its own section's PT97 identity — expected zero findings, got %+v", got)
	}
}

// Item 15: sendonly/recvonly restricts which direction is negotiated.
func TestCompareMediaToRTPSendonlyRecvonlyRestrictsAllowedDirection(t *testing.T) {
	codecs := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	offer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{0}, Codecs: codecs, Direction: "sendonly"}}}
	answer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 5000, ConnAddr: "10.0.0.2", PayloadTypes: []int{0}, Codecs: codecs, Direction: "recvonly"}}}

	okStreams := []StreamInfo{{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000}}
	if got := compareMediaToRTP(&Call{SDPOffer: offer, SDPAnswer: answer, Streams: okStreams}); anyFindingContains(got, "no habilitó") {
		t.Errorf("offerer(sendonly)->answerer(recvonly) is exactly the negotiated direction, must not be flagged: %+v", got)
	}

	badStreams := []StreamInfo{{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 0, ClockRate: 8000}}
	got := compareMediaToRTP(&Call{SDPOffer: offer, SDPAnswer: answer, Streams: badStreams})
	if !anyFindingContains(got, "no habilitó") {
		t.Errorf("answerer(recvonly) sending back is NOT what the negotiation allowed, expected a finding, got %+v", got)
	}
}

// Item 15: media marked inactive on both sides, but RTP observed anyway.
func TestCompareMediaToRTPInactiveMediaWithObservedRTPIsFlagged(t *testing.T) {
	codecs := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	offer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{0}, Codecs: codecs, Direction: "inactive"}}}
	answer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 5000, ConnAddr: "10.0.0.2", PayloadTypes: []int{0}, Codecs: codecs, Direction: "inactive"}}}
	c := &Call{SDPOffer: offer, SDPAnswer: answer, Streams: []StreamInfo{
		{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
	}}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "no habilitó") {
		t.Errorf("media marked inactive on both sides but RTP was observed anyway — expected a finding, got %+v", got)
	}
}

// Item 15: the answer rejecting a media section (port 0) but RTP still
// observed for it.
func TestCompareMediaToRTPRejectedMediaPortZeroWithObservedRTPIsFlagged(t *testing.T) {
	codecs := map[int]sdp.Codec{0: {PayloadType: 0, Name: "PCMU", ClockRate: 8000}}
	offer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 4000, ConnAddr: "10.0.0.1", PayloadTypes: []int{0}, Codecs: codecs}}}
	answer := &sdp.SDP{Media: []sdp.Media{{Type: "audio", Port: 0, ConnAddr: "10.0.0.2", PayloadTypes: []int{0}, Codecs: codecs}}} // rejected
	c := &Call{SDPOffer: offer, SDPAnswer: answer, Streams: []StreamInfo{
		{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000},
	}}
	if got := compareMediaToRTP(c); !anyFindingContains(got, "no habilitó") {
		t.Errorf("RTP observed for media the answer rejected (port 0) — expected a direction-not-enabled finding, got %+v", got)
	}
}
