package voip

import (
	"context"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// FINAL AUDIT REMEDIATION — media metadata must be per call + per m= section,
// and the ingest ceilings must be provable against the production code path.
// ─────────────────────────────────────────────────────────────────────────────

// P1-1: one Call-ID, two audio m= sections — a clear RTP/AVP line and a
// separate RTP/SAVPF line. SAVPF must NOT block the clear AVP media, and the
// SAVPF stream must never reach a decoder.
func TestE2EMixedAvpSavpfSameCallID(t *testing.T) {
	var decoderCalls int
	orig := decoderForStream
	decoderForStream = func(s StreamInfo) (audioDecoder, error) { decoderCalls++; return orig(s) }
	defer func() { decoderForStream = orig }()

	var pkts []e2ePkt
	for i := 0; i < 15; i++ {
		at := 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond
		pkts = append(pkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: 0xC1EA0,
			payload: g711Payload(0xFF, 160), at: at})
		pkts = append(pkts, e2ePkt{fromCaller: true, onSecond: true, seq: uint16(i), ts: uint32(i) * 160, pt: 96, ssrc: 0x5EC00,
			payload: g711Payload(0x00, 160), at: at})
	}
	path := writeE2EPCAP(t, []e2eCall{{
		callID: "mixed@x", callerIP: "10.4.0.1", calleeIP: "10.4.0.2",
		callerPort: 5000, calleePort: 5002, proto: "RTP/AVP",
		rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 0,
		second: &e2eMedia{callerPort: 6000, calleePort: 6002, proto: "RTP/SAVPF", pts: "96",
			rtpmap: []string{"a=rtpmap:96 PCMU/8000"}},
		pkts: pkts,
	}})
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalCalls != 1 {
		t.Fatalf("calls=%d, want 1", r.TotalCalls)
	}
	call := r.Calls[0]
	var clear, enc *StreamInfo
	for i := range call.Streams {
		switch call.Streams[i].SSRC {
		case 0xC1EA0:
			clear = &call.Streams[i]
		case 0x5EC00:
			enc = &call.Streams[i]
		}
	}
	if clear == nil || enc == nil {
		t.Fatalf("expected both streams on one Call-ID: %+v", call.Streams)
	}
	if clear.AudioStatus != AudioStatusReconstructable {
		t.Fatalf("clear AVP stream audioStatus=%q, want reconstructable (SAVPF sibling must not poison it)", clear.AudioStatus)
	}
	if enc.AudioStatus != AudioStatusEncryptedUnavailable && enc.AudioStatus != AudioStatusSRTPDetected {
		t.Fatalf("SAVPF stream audioStatus=%q, want encrypted", enc.AudioStatus)
	}
	before := decoderCalls
	res, err := ReconstructCallAudio(context.Background(), path, call, AudioModeMono)
	if err != nil {
		t.Fatalf("mixed call must still reconstruct the clear leg: %v", err)
	}
	if decoderCalls-before != 1 {
		t.Fatalf("decoder calls=%d, want 1 (clear leg only)", decoderCalls-before)
	}
	if len(decodeWAVData(t, res.WAV)) != 15*160 {
		t.Fatalf("clear leg samples=%d, want %d", len(decodeWAVData(t, res.WAV)), 15*160)
	}
}

// SAVPF end-to-end from PCAP (not code-path inspection): the sole audio m=
// section is RTP/SAVPF -> encrypted, never decoded, no PCM, controlled error.
func TestE2EDedicatedSAVPF(t *testing.T) {
	var decoderCalls int
	orig := decoderForStream
	decoderForStream = func(s StreamInfo) (audioDecoder, error) { decoderCalls++; return orig(s) }
	defer func() { decoderForStream = orig }()

	var pkts []e2ePkt
	for i := 0; i < 15; i++ {
		pkts = append(pkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 96, ssrc: 0x5A19F,
			payload: g711Payload(0x00, 160), at: 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond})
	}
	path := writeE2EPCAP(t, []e2eCall{{
		callID: "savpf@x", callerIP: "10.5.0.1", calleeIP: "10.5.0.2", callerPort: 7000, calleePort: 7002,
		proto: "RTP/SAVPF", rtpmap: []string{"a=rtpmap:96 PCMU/8000"}, pts: "96", ptime: 20, base: 0, pkts: pkts,
	}})
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := r.Calls[0].Streams
	if len(st) != 1 {
		t.Fatalf("streams=%d", len(st))
	}
	if st[0].AudioStatus != AudioStatusEncryptedUnavailable && st[0].AudioStatus != AudioStatusSRTPDetected {
		t.Fatalf("SAVPF audioStatus=%q, want encrypted", st[0].AudioStatus)
	}
	if _, err := ReconstructCallAudio(context.Background(), path, r.Calls[0], AudioModeMono); err == nil {
		t.Fatal("SAVPF: expected a controlled encrypted/not-reconstructible error")
	}
	if decoderCalls != 0 {
		t.Fatalf("SAVPF decoder calls=%d, want 0", decoderCalls)
	}
}

// P1-2: two calls reuse the same src/dst IPs, the same media ports, the same
// dynamic PT 96 AND the same SSRC, but negotiate DIFFERENT codecs. Metadata
// is resolved from each call's own SDP -> no bleed either way. Looped so a
// regression that leaned on Go's randomized map order fails deterministically.
func TestE2ECallAwareCodecSameEndpointDynamicPT(t *testing.T) {
	const ssrc = 0x96969696
	var aPkts []e2ePkt
	for i := 0; i < 20; i++ {
		aPkts = append(aPkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 80, pt: 96, ssrc: ssrc,
			payload: make([]byte, 10), at: 1100*time.Millisecond + time.Duration(i)*10*time.Millisecond})
	}
	var bPkts []e2ePkt
	for i := 0; i < 20; i++ {
		bPkts = append(bPkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 96, ssrc: ssrc,
			payload: g711Payload(0x11, 160), at: 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond})
	}
	calls := []e2eCall{
		{callID: "codec-A@x", callerIP: "10.10.0.1", calleeIP: "10.10.0.2", callerPort: 7777, calleePort: 7778,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:96 G729/8000"}, pts: "96", ptime: 10, base: 0, pkts: aPkts},
		{callID: "codec-B@x", callerIP: "10.10.0.1", calleeIP: "10.10.0.2", callerPort: 7777, calleePort: 7778,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:96 PCMU/8000"}, pts: "96", ptime: 20, base: 10 * time.Minute, pkts: bPkts},
	}
	for iter := 0; iter < 8; iter++ {
		path := writeE2EPCAP(t, calls)
		r, err := Analyze(context.Background(), path, nil)
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]Call{}
		for _, c := range r.Calls {
			byID[c.CallID] = c
		}
		a, okA := byID["codec-A@x"]
		b, okB := byID["codec-B@x"]
		if !okA || !okB {
			t.Fatalf("iter %d: calls not both correlated", iter)
		}
		if got := streamByCodec(a, "G729"); got == nil || got.ClockRate != 8000 {
			t.Fatalf("iter %d: call A codec=%+v, want G729/8000", iter, a.Streams)
		}
		if got := streamByCodec(b, "PCMU"); got == nil || got.ClockRate != 8000 {
			t.Fatalf("iter %d: call B codec=%+v, want PCMU/8000", iter, b.Streams)
		}
		if streamByCodec(a, "PCMU") != nil {
			t.Fatalf("iter %d: call A leaked PCMU from call B", iter)
		}
		if streamByCodec(b, "G729") != nil {
			t.Fatalf("iter %d: call B leaked G729 from call A", iter)
		}
		res, err := ReconstructCallAudio(context.Background(), path, b, AudioModeMono)
		if err != nil {
			t.Fatalf("iter %d: call B reconstruct: %v", iter, err)
		}
		for i, v := range decodeWAVData(t, res.WAV) {
			if v != ulaw2linear(0x11) {
				t.Fatalf("iter %d: call B sample[%d]=%d, not PCMU(0x11)", iter, i, v)
			}
		}
		resA, err := ReconstructCallAudio(context.Background(), path, a, AudioModeMono)
		if err != nil {
			t.Fatalf("iter %d: call A reconstruct: %v", iter, err)
		}
		if got := len(decodeWAVData(t, resA.WAV)); got != 20*80 {
			t.Fatalf("iter %d: call A samples=%d, want %d (G.729)", iter, got, 20*80)
		}
	}
}
