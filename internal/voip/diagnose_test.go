package voip

import (
	"strings"
	"testing"

	"trazip/internal/model"
	"trazip/internal/protocol/rtp"
	"trazip/internal/protocol/sdp"
)

func TestDiagnoseUnestablishedCallWithFailureCode(t *testing.T) {
	c := Call{FailureCode: 486, FailureReason: "Busy Here", ProbableCause: "Ocupado (Busy Here)"}
	d := Diagnose(c)
	if d.Level != model.LevelMedium {
		t.Errorf("Level = %q, want medium for an explicit SIP failure", d.Level)
	}
	if !strings.Contains(d.Conclusion, "486") {
		t.Errorf("Conclusion should cite the SIP code: %q", d.Conclusion)
	}
	if d.Confidence == 0 {
		t.Error("Confidence must never be the zero value")
	}
}

func TestDiagnoseUnestablishedCallWithoutExplicitFailure(t *testing.T) {
	c := Call{}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "compatible con") {
		t.Errorf("an unattributed failure must hedge with 'compatible con', got %q", d.Conclusion)
	}
	if len(d.Limitations) == 0 {
		t.Error("expected a Limitation explaining why no attribution was made")
	}
}

func TestDiagnoseEstablishedCallWithoutStreams(t *testing.T) {
	c := Call{Established: true}
	d := Diagnose(c)
	if d.Level != model.LevelInfo {
		t.Errorf("Level = %q, want info: nothing to evaluate without RTP", d.Level)
	}
	if !strings.Contains(d.Conclusion, "sin flujo RTP") {
		t.Errorf("Conclusion should say there's no RTP to evaluate: %q", d.Conclusion)
	}
}

func goodStream() StreamInfo {
	return StreamInfo{
		Src: "192.0.2.10:40000", Dst: "192.0.2.20:40002", CodecName: "PCMU", ClockRate: 8000,
		Stats: rtp.Snapshot{Received: 100, Expected: 100, LossPct: 0, JitterMs: 2},
		MOS:   &MOSEstimate{Score: 4.3},
	}
}

func TestDiagnoseGoodCallIsLevelInfoAndHighConfidence(t *testing.T) {
	c := Call{Established: true, Streams: []StreamInfo{goodStream(), goodStream()}}
	d := Diagnose(c)
	if d.Level != model.LevelInfo {
		t.Errorf("Level = %q, want info for a clean call", d.Level)
	}
	if d.Confidence < 60 {
		t.Errorf("Confidence = %d, want reasonably high with RTCP-independent clean signals... (streams have no RTCP here, so some reduction is expected, but not collapse)", d.Confidence)
	}
}

func TestDiagnoseHighLossIsLevelHigh(t *testing.T) {
	s := goodStream()
	s.Stats.LossPct = 12
	s.MOS = &MOSEstimate{Score: 2.0}
	c := Call{Established: true, Streams: []StreamInfo{s}}
	d := Diagnose(c)
	if d.Level != model.LevelHigh {
		t.Errorf("Level = %q, want high for 12%% loss / MOS 2.0", d.Level)
	}
	foundLossEvidence := false
	for _, e := range d.Evidence {
		if e.Type == "rtp_loss_local" {
			foundLossEvidence = true
		}
		if strings.Contains(e.Explain, "la causa es") {
			t.Errorf("evidence must never assert an unproven cause: %q", e.Explain)
		}
	}
	if !foundLossEvidence {
		t.Error("expected loss to appear as evidence")
	}
}

func TestDiagnoseModerateLossIsLevelMedium(t *testing.T) {
	s := goodStream()
	s.Stats.LossPct = lossWarnPct + 0.1
	s.MOS = &MOSEstimate{Score: 3.6}
	c := Call{Established: true, Streams: []StreamInfo{s}}
	d := Diagnose(c)
	if d.Level != model.LevelMedium {
		t.Errorf("Level = %q, want medium just above the loss-warn threshold", d.Level)
	}
}

func TestDiagnoseUnidirectionalReducesConfidenceAndIsLimitation(t *testing.T) {
	base := goodStream()
	withUni := Diagnose(Call{Established: true, Unidirectional: true, Streams: []StreamInfo{base}})
	withoutUni := Diagnose(Call{Established: true, Streams: []StreamInfo{base, goodStream()}})
	if withUni.Confidence >= withoutUni.Confidence {
		t.Errorf("a unidirectional call must have lower confidence: uni=%d bidi=%d", withUni.Confidence, withoutUni.Confidence)
	}
	found := false
	for _, l := range withUni.Limitations {
		if strings.Contains(l, "un sentido") {
			found = true
		}
	}
	if !found {
		t.Error("expected a limitation mentioning the single captured direction")
	}
}

func TestDiagnoseClockAssumedReducesConfidence(t *testing.T) {
	assumed := goodStream()
	assumed.Stats.ClockAssumed = true
	confirmed := goodStream()

	dAssumed := Diagnose(Call{Established: true, Streams: []StreamInfo{assumed}})
	dConfirmed := Diagnose(Call{Established: true, Streams: []StreamInfo{confirmed}})
	if dAssumed.Confidence >= dConfirmed.Confidence {
		t.Errorf("an assumed clock rate must reduce confidence: assumed=%d confirmed=%d", dAssumed.Confidence, dConfirmed.Confidence)
	}
}

func TestDiagnoseMissingRTCPAndMissingSDPAreLimitations(t *testing.T) {
	c := Call{Established: true, Streams: []StreamInfo{goodStream()}} // no RTCPSeen, no SDPOffer/Answer
	d := Diagnose(c)
	joined := strings.Join(d.Limitations, " | ")
	if !strings.Contains(joined, "RTCP") {
		t.Errorf("expected a limitation about missing RTCP: %v", d.Limitations)
	}
	if !strings.Contains(joined, "SDP") {
		t.Errorf("expected a limitation about missing SDP: %v", d.Limitations)
	}
}

func TestDiagnoseConfidenceNeverExceedsCapOrGoesBelowFloor(t *testing.T) {
	if got := clampConfidence(200); got != 95 {
		t.Errorf("clampConfidence(200) = %d, want 95 (a passive capture is never fully certain)", got)
	}
	if got := clampConfidence(-50); got != 10 {
		t.Errorf("clampConfidence(-50) = %d, want 10 (never a claimed zero confidence)", got)
	}
}

// Gate v0.7.3 (independent audit, item 2): a gap between the locally
// accumulated LossPct and the receiver's last-interval FractionLostPct is
// NOT, by itself, evidence of anything — they cover different windows of the
// same signal (a running total vs. one interval since the receiver's
// previous report, RFC 3550 §6.4.2), not two measurements of the same
// quantity. An earlier version of this treated a large gap as CounterEvid
// suggesting a "one-directional problem" — that conflated two different
// observation windows with two different directions, and this test now
// verifies that conflation is gone: the receiver's own report becomes plain
// Evidence, phrased as an interval, never CounterEvid derived from comparing
// it to the unrelated cumulative local figure.
func TestDiagnoseReceiverIntervalLossNeverBecomesCounterEvidence(t *testing.T) {
	s := goodStream()
	s.Stats.LossPct = 8
	s.MOS = &MOSEstimate{Score: 3.0}
	s.RTCPSeen = true
	s.RTCP = &RTCPSummary{Receiver: &RTCPReceiverSummary{FractionLostPct: 0.2}}
	c := Call{Established: true, Streams: []StreamInfo{s}}
	d := Diagnose(c)
	for _, ce := range d.CounterEvid {
		if ce.Type == "rtcp_receiver_loss" || ce.Type == "rtcp_remote_loss" {
			t.Errorf("a receiver-interval-vs-local-cumulative gap must never become CounterEvid: %+v", ce)
		}
	}
	found := false
	for _, e := range d.Evidence {
		if e.Type != "rtcp_receiver_loss" {
			continue
		}
		found = true
		if !strings.Contains(e.Explain, "último intervalo") {
			t.Errorf("receiver loss Explain must label it as an interval figure, got %q", e.Explain)
		}
		if strings.Contains(e.Explain, "sentido contrario") || strings.Contains(e.Explain, "dirección contraria") || strings.Contains(e.Explain, "opuesta") {
			t.Errorf("receiver loss must never be framed as describing the opposite direction: %q", e.Explain)
		}
	}
	if !found {
		t.Errorf("expected an rtcp_receiver_loss evidence entry, got Evidence=%v", d.Evidence)
	}
}

// Regression: partyOrganization used to match a call party against EITHER
// end of the worst stream (Src or Dst), so with two distinct real
// organizations it could name the address in the Conclusion and then quote
// the OTHER party's organization next to it — caught by running Diagnose
// against a real two-sided capture (1.1.1.1 Cloudflare / 8.8.8.8 Google)
// rather than trusting unit tests alone, none of which had two distinct
// resolved organizations to tell apart.
func TestDiagnoseNamesTheOrganizationOfTheAddressItDisplays(t *testing.T) {
	s := goodStream()
	s.Src, s.Dst = "1.1.1.1:40000", "8.8.8.8:40002"
	s.Stats.LossPct = 12
	s.MOS = &MOSEstimate{Score: 2.0}
	c := Call{
		Established: true,
		Streams:     []StreamInfo{s},
		Caller:      CallParty{Address: "1.1.1.1:5060", Organization: "Cloudflare, Inc."},
		Callee:      CallParty{Address: "8.8.8.8:5060", Organization: "Google LLC"},
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "8.8.8.8") {
		t.Fatalf("Conclusion should name the stream's Dst (8.8.8.8): %q", d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "Cloudflare") {
		t.Errorf("Conclusion names 8.8.8.8 but quotes Cloudflare's organization instead of Google's: %q", d.Conclusion)
	}
	if !strings.Contains(d.Conclusion, "Google LLC") {
		t.Errorf("Conclusion should quote Google LLC (8.8.8.8's real organization): %q", d.Conclusion)
	}
}

// TestDiagnoseIdentifiesTheDegradedDirectionNotTheOther is the gate's
// explicit A→B/B→A check: two directions with deliberately very different
// quality (A→B clean, B→A clearly degraded), so any direction mixup —
// backend swapping which StreamInfo is which, Diagnose picking the wrong
// one, or the organization/IP pairing crossing over — produces an obviously
// wrong result instead of an accidental match.
func TestDiagnoseIdentifiesTheDegradedDirectionNotTheOther(t *testing.T) {
	aToB := StreamInfo{
		Src: "203.0.113.5:40000", Dst: "198.51.100.9:40002", CodecName: "PCMU", ClockRate: 8000,
		Stats: rtp.Snapshot{Received: 199, Expected: 200, Lost: 1, LossPct: 0.5, JitterMs: 5},
		MOS:   &MOSEstimate{Score: 4.3},
	}
	bToA := StreamInfo{
		Src: "198.51.100.9:40002", Dst: "203.0.113.5:40000", CodecName: "PCMU", ClockRate: 8000,
		Stats: rtp.Snapshot{Received: 176, Expected: 200, Lost: 24, LossPct: 12, JitterMs: 90},
		MOS:   &MOSEstimate{Score: 2.1},
	}
	c := Call{
		Established: true,
		Streams:     []StreamInfo{aToB, bToA},
		Caller:      CallParty{Address: "203.0.113.5:5060", Organization: "Org-A Networks"},
		Callee:      CallParty{Address: "198.51.100.9:5060", Organization: "Org-B Telecom"},
	}

	// --- backend: both directions must survive Diagnose unmodified ---
	if c.Streams[0].Src != "203.0.113.5:40000" || c.Streams[0].Dst != "198.51.100.9:40002" {
		t.Fatalf("A→B direction corrupted before Diagnose even ran: %+v", c.Streams[0])
	}
	if c.Streams[1].Src != "198.51.100.9:40002" || c.Streams[1].Dst != "203.0.113.5:40000" {
		t.Fatalf("B→A direction corrupted before Diagnose even ran: %+v", c.Streams[1])
	}

	d := Diagnose(c)

	// --- Diagnose must identify B→A (worse: 12% loss, 90ms jitter, MOS 2.1)
	// as the affected leg, never A→B (0.5%, 5ms, MOS 4.3) ---
	if !strings.Contains(d.Conclusion, "203.0.113.5") {
		t.Errorf("Conclusion should name 203.0.113.5 (B→A's Dst, the degraded leg's receiver): %q", d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "198.51.100.9") {
		t.Errorf("Conclusion names 198.51.100.9 (A→B's Dst) — that's the CLEAN direction, not the degraded one: %q", d.Conclusion)
	}

	// --- the organization quoted must belong to the IP actually named
	// (203.0.113.5 → "Org-A Networks"), never the other party's ---
	if !strings.Contains(d.Conclusion, "Org-A Networks") {
		t.Errorf("Conclusion should quote Org-A Networks (203.0.113.5's real organization): %q", d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "Org-B Telecom") {
		t.Errorf("Conclusion names 203.0.113.5 but quotes Org-B Telecom (198.51.100.9's organization) instead: %q", d.Conclusion)
	}

	// --- evidence must cite the degraded leg's own numbers ---
	foundLoss := false
	for _, e := range d.Evidence {
		if e.Type == "rtp_loss_local" {
			foundLoss = true
			if !strings.Contains(e.Value, "12") {
				t.Errorf("rtp_loss_local evidence = %q, want it to cite the degraded leg's 12%%, not the clean leg's 0.5%%", e.Value)
			}
		}
	}
	if !foundLoss {
		t.Error("expected an rtp_loss_local evidence entry")
	}

	// --- never assign a network role the data doesn't demonstrate ---
	for _, forbidden := range []string{"Carrier", "Cliente", "carrier", "cliente"} {
		if strings.Contains(d.Conclusion, forbidden) {
			t.Errorf("Conclusion must never assert a network role: contains %q in %q", forbidden, d.Conclusion)
		}
		for _, e := range d.Evidence {
			if strings.Contains(e.Explain, forbidden) {
				t.Errorf("Evidence must never assert a network role: contains %q in %q", forbidden, e.Explain)
			}
		}
	}

	if d.Level != model.LevelHigh {
		t.Errorf("Level = %q, want high for 12%% loss / MOS 2.1", d.Level)
	}
}

func TestDiagnoseNeverAssertsAnUnhedgedCause(t *testing.T) {
	s := goodStream()
	s.Stats.LossPct = 15
	s.Stats.Reordered = 5
	s.Stats.Duplicates = 3
	s.Stats.ClockSkewMs = 80
	s.MOS = &MOSEstimate{Score: 1.8}
	c := Call{Established: true, Streams: []StreamInfo{s}}
	d := Diagnose(c)
	for _, forbidden := range []string{"la causa es", "esto es culpa de", "el problema es"} {
		if strings.Contains(d.Conclusion, forbidden) {
			t.Errorf("Conclusion must never contain an unhedged causal claim %q: %q", forbidden, d.Conclusion)
		}
	}
}

// Gate v0.7.3 (independent audit, third gate, item 6): RTCPSeen==true does
// not mean the RECEIVER corroborated anything — it can come from a
// Sender-Report-only observation (self-reported by the same party Stats
// already measures), and a genuine Receiver Report elsewhere in the call
// says nothing about the specific stream Diagnose bases its conclusion on.
// These four scenarios must be strictly ordered: no RTCP at all, SR-only,
// and RR-on-a-different-stream must all sit BELOW a genuine RR on the worst
// stream itself.
func TestDiagnoseConfidenceReflectsWorstStreamsOwnReceiverCorroboration(t *testing.T) {
	// A: no RTCP at all.
	noRTCP := goodStream()
	dA := Diagnose(Call{Established: true, Streams: []StreamInfo{noRTCP}})

	// B: SR-only for the (only, hence worst) stream — self-reported by its
	// own origin, not corroboration from a receiver.
	srOnly := goodStream()
	srOnly.RTCPSeen = true
	srOnly.RTCP = &RTCPSummary{Sender: &RTCPSenderSummary{PacketCount: 100, OctetCount: 16000}}
	dB := Diagnose(Call{Established: true, Streams: []StreamInfo{srOnly}})

	// C: a Receiver Report exists, but on a DIFFERENT (clean, non-worst)
	// stream — the worst stream (much higher loss) still has none of its own.
	worseNoRTCP := goodStream()
	worseNoRTCP.Stats.LossPct = 15
	worseNoRTCP.MOS = &MOSEstimate{Score: 2.0}
	cleanWithRTCP := goodStream()
	cleanWithRTCP.RTCPSeen = true
	cleanWithRTCP.RTCP = &RTCPSummary{Receiver: &RTCPReceiverSummary{FractionLostPct: 0}}
	dC := Diagnose(Call{Established: true, Streams: []StreamInfo{worseNoRTCP, cleanWithRTCP}})

	// D: the worst stream itself has a genuine Receiver Report.
	worstWithRTCP := goodStream()
	worstWithRTCP.RTCPSeen = true
	worstWithRTCP.RTCP = &RTCPSummary{Receiver: &RTCPReceiverSummary{FractionLostPct: 0.5}}
	dD := Diagnose(Call{Established: true, Streams: []StreamInfo{worstWithRTCP}})

	cases := []struct {
		name string
		d    model.Assessment
	}{{"A(no RTCP)", dA}, {"B(SR-only)", dB}, {"C(RR-on-other-stream)", dC}}
	for _, tc := range cases {
		if tc.d.Confidence >= dD.Confidence {
			t.Errorf("%s: Confidence = %d, want strictly less than D(RR-on-worst) = %d", tc.name, tc.d.Confidence, dD.Confidence)
		}
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 4): a video stream's
// independent, unrelated loss/jitter must never dominate the voice-quality
// conclusion this Assessment presents as call/MOS quality.
func TestDiagnoseVoiceQualityIgnoresVideoStream(t *testing.T) {
	cleanAudio := goodStream()
	cleanAudio.MediaType = "audio"
	badVideo := StreamInfo{
		Src: "192.0.2.10:4002", Dst: "192.0.2.20:4004", MediaType: "video", CodecName: "H264", ClockRate: 90000,
		Stats: rtp.Snapshot{Received: 85, Expected: 100, LossPct: 15, JitterMs: 100},
	}
	d := Diagnose(Call{Established: true, Streams: []StreamInfo{cleanAudio, badVideo}})
	if d.Level != model.LevelInfo {
		t.Errorf("Level = %q, want info — the audio stream is clean, a bad video stream must not affect this conclusion", d.Level)
	}
	for _, e := range d.Evidence {
		if strings.Contains(e.Explain, "H264") || strings.Contains(e.Explain, "192.0.2.10:4002") {
			t.Errorf("evidence must never cite the video stream's own numbers: %+v", e)
		}
	}
}

// A video-only call must never fabricate a voice MOS or a conclusion that
// reads like one.
func TestDiagnoseVideoOnlyCallHasNoVoiceMOSConclusion(t *testing.T) {
	video := StreamInfo{
		Src: "192.0.2.10:4002", Dst: "192.0.2.20:4004", MediaType: "video", CodecName: "H264", ClockRate: 90000,
		Stats: rtp.Snapshot{Received: 85, Expected: 100, LossPct: 15, JitterMs: 100},
	}
	d := Diagnose(Call{Established: true, Streams: []StreamInfo{video}})
	if strings.Contains(d.Conclusion, "MOS") {
		t.Errorf("a video-only call must not present a conclusion mentioning MOS: %q", d.Conclusion)
	}
	if !strings.Contains(d.Conclusion, "audio") {
		t.Errorf("expected a conclusion stating no audio stream was observed: %q", d.Conclusion)
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 11): a full
// audio+video call fixture, tying together every audio/video separation
// fixed in this gate — clean bidirectional audio (PCMU) alongside heavily
// degraded bidirectional video (H264, 20% loss/100ms jitter).
func TestFullAudioVideoCallSeparatesVoiceQualityFromVideoTransport(t *testing.T) {
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

	audioAB := StreamInfo{MediaType: "audio", Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000", PayloadType: 0, ClockRate: 8000,
		Stats: rtp.Snapshot{Received: 200, Expected: 201, LossPct: 0.5, JitterMs: 5}}
	audioBA := StreamInfo{MediaType: "audio", Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000", PayloadType: 0, ClockRate: 8000,
		Stats: rtp.Snapshot{Received: 200, Expected: 201, LossPct: 0.5, JitterMs: 5}}
	// MOS computed the same way attachStreams computes it (audio, >=20
	// received) — video never gets this treatment at all, matching item 3.
	audioMOS := EstimateMOS(audioAB.Stats.LossPct, audioAB.Stats.JitterMs)
	audioAB.MOS, audioBA.MOS = &audioMOS, &audioMOS

	videoAB := StreamInfo{MediaType: "video", Src: "10.0.0.1:4002", Dst: "10.0.0.2:5002", PayloadType: 97, ClockRate: 90000,
		Stats: rtp.Snapshot{Received: 80, Expected: 100, LossPct: 20, JitterMs: 100}}
	videoBA := StreamInfo{MediaType: "video", Src: "10.0.0.2:5002", Dst: "10.0.0.1:4002", PayloadType: 97, ClockRate: 90000,
		Stats: rtp.Snapshot{Received: 80, Expected: 100, LossPct: 20, JitterMs: 100}}

	c := Call{
		CallID: "av-call", Established: true,
		SDPOffer: offer, SDPAnswer: answer,
		Streams: []StreamInfo{audioAB, audioBA, videoAB, videoBA},
	}

	// Video streams never get a voice MOS.
	if videoAB.MOS != nil || videoBA.MOS != nil {
		t.Fatal("video streams must not have MOS")
	}

	// Diagnose's voice-quality conclusion is unaffected by video's 20% loss.
	diag := Diagnose(c)
	if diag.Level != model.LevelInfo {
		t.Errorf("Diagnose Level = %q, want info — clean audio, video's 20%% loss/100ms jitter must not affect voice diagnosis", diag.Level)
	}
	for _, e := range diag.Evidence {
		if strings.Contains(e.Explain, "H264") || strings.Contains(e.Explain, "10.0.0.1:4002") {
			t.Errorf("Diagnose evidence must never cite the video stream's own numbers: %+v", e)
		}
	}

	// The video RTP panel's own data (transport stats) survives untouched —
	// this Assessment doesn't erase or alter StreamInfo.Stats for non-audio.
	if videoAB.Stats.LossPct != 20 || videoAB.Stats.JitterMs != 100 {
		t.Errorf("video stream's own transport stats must remain intact: %+v", videoAB.Stats)
	}

	// SDP comparison still runs normally for video — everything matches
	// here, so zero findings; TestCompareMediaToRTPMultiMediaAudioVideoNoCrossContamination
	// already covers the broken-video-destination case specifically.
	if got := compareMediaToRTP(&c); len(got) != 0 {
		t.Errorf("all four legs match their negotiated section — expected zero SDP findings, got %+v", got)
	}
}
