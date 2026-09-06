package voip

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
	"trazip/internal/protocol/rtp"
	"trazip/internal/protocol/sdp"
)

func TestPCMADecodeSilenceAndWAVStereo(t *testing.T) {
	pcm, err := (pcmaDecoder{}).Decode([]byte{0xd5, 0x55})
	if err != nil || len(pcm) != 2 || pcm[0] == 0 {
		t.Fatalf("PCMA decode=%v, %v", pcm, err)
	}
	if pcm[0] != 8 || pcm[1] != -8 {
		t.Fatalf("A-law vectors=%v, want [8 -8]", pcm)
	}
	wav := WriteWAVChannels(8000, 2, []int16{1, 2, 3, 4})
	if got := binary.LittleEndian.Uint16(wav[22:24]); got != 2 {
		t.Fatalf("channels=%d", got)
	}
	if got := binary.LittleEndian.Uint32(wav[28:32]); got != 32000 {
		t.Fatalf("byte rate=%d", got)
	}
	if got := binary.LittleEndian.Uint32(wav[40:44]); got != 8 {
		t.Fatalf("data=%d", got)
	}
}

// TestPCMUE2EGoldenFixture recorre la captura sintética existente completa:
// PCAP -> SIP/SDP -> RTP -> correlación -> reconstrucción -> WAV.
func TestPCMUE2EGoldenFixture(t *testing.T) {
	path := writeCallPCAP(t)
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalCalls != 1 || len(r.Calls) != 1 {
		t.Fatalf("calls=%d", r.TotalCalls)
	}
	c := r.Calls[0]
	if c.CallID != "test-call-1@192.168.1.10" {
		t.Fatalf("call-id=%q", c.CallID)
	}
	var stream *StreamInfo
	for i := range c.Streams {
		if c.Streams[i].CodecName == "PCMU" && c.Streams[i].PayloadType == 0 && c.Streams[i].SSRC == 0xA11CE {
			stream = &c.Streams[i]
			break
		}
	}
	if stream == nil {
		t.Fatalf("PCMU stream not correlated: %+v", c.Streams)
	}
	if stream.Stats.Received != 38 {
		t.Fatalf("packets=%d", stream.Stats.Received)
	}
	if stream.FirstSeen.IsZero() || stream.LastSeen.IsZero() || !stream.LastSeen.After(stream.FirstSeen) {
		t.Fatal("stream window invalid")
	}
	wav, filled, err := ExportStreamAudio(context.Background(), path, stream.SSRC, stream.Src)
	if err != nil {
		t.Fatal(err)
	}
	if filled != 320 {
		t.Fatalf("filled=%d", filled)
	}
	if len(wav) < 44 || !bytes.Equal(wav[:4], []byte("RIFF")) || !bytes.Equal(wav[8:12], []byte("WAVE")) {
		t.Fatal("invalid WAV")
	}
	if binary.LittleEndian.Uint16(wav[22:24]) != 1 || binary.LittleEndian.Uint32(wav[24:28]) != 8000 || binary.LittleEndian.Uint16(wav[34:36]) != 16 {
		t.Fatal("invalid WAV PCM format")
	}
	if got := binary.LittleEndian.Uint32(wav[40:44]); got != 40*160*2 {
		t.Fatalf("wav samples=%d", got/2)
	}
}

func TestCallForMediaSeparatesSSRCReuse(t *testing.T) {
	t0 := time.Now()
	calls := map[string]*Call{
		"A": {CallID: "A", startedAt: t0, endedAt: t0.Add(time.Minute)},
		"B": {CallID: "B", startedAt: t0.Add(2 * time.Minute), endedAt: t0.Add(3 * time.Minute)},
	}
	idx := map[string][]string{"10.0.0.2:4000": {"A", "B"}}
	if got := callForMedia(idx, calls, "10.0.0.1:5000", "10.0.0.2:4000", t0.Add(time.Second)); got != "A" {
		t.Fatalf("call A=%q", got)
	}
	if got := callForMedia(idx, calls, "10.0.0.1:5000", "10.0.0.2:4000", t0.Add(2*time.Minute+time.Second)); got != "B" {
		t.Fatalf("call B=%q", got)
	}
}

func TestExtendedSequenceMultipleWraps(t *testing.T) {
	var s sequenceTracker
	seqs := []uint16{65534, 65535, 0, 1}
	for i, v := range seqs {
		if got := s.extend(v); got != uint64(65534+i) {
			t.Fatalf("wrap %d=%d", v, got)
		}
	}
	for i := 0; i < 131072; i++ {
		s.extend(uint16(i))
	}
	if s.highest < 131072 {
		t.Fatalf("multiple wraps highest=%d", s.highest)
	}
}

func TestResourceLimitsAreExplicit(t *testing.T) {
	if maxAudioPackets < 1 || maxEncodedAudioBytes < 1 || maxOutputWAVBytes < maxAudioSamples*2 {
		t.Fatal("resource limits invalid")
	}
}

func TestPreviewPrecheckAndMixTimelineLimit(t *testing.T) {
	if err := PreviewAllowed(Call{Streams: []StreamInfo{{Stats: rtp.Snapshot{RTPDurationMs: 10000000}}}}, 1, 8<<20); err == nil {
		t.Fatal("preview over limit accepted")
	}
}

func TestG729FrameShapes(t *testing.T) {
	d, err := newG729Decoder()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decode(make([]byte, 20)); err != nil {
		t.Fatalf("G729 ptime 20: %v", err)
	}
	if _, err := d.Decode([]byte{0, 0}); err == nil {
		t.Fatal("SID/CNG debe rechazarse")
	}
	if _, err := d.Decode([]byte{1}); err == nil {
		t.Fatal("frame incompleto debe rechazarse")
	}
}

func TestG729MalformedMatrix(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte{0}, []byte{0, 0}, make([]byte, 9), make([]byte, 11), make([]byte, 19), make([]byte, 21), make([]byte, 1025), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}} {
		d, err := newG729Decoder()
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Decode(payload)
		if len(payload)%10 != 0 || len(payload) == 0 {
			if err == nil {
				t.Fatalf("payload %d accepted", len(payload))
			}
		}
	}
	for _, n := range []int{10, 20} {
		d, _ := newG729Decoder()
		if _, err := d.Decode(make([]byte, n)); err != nil {
			t.Fatalf("valid shape %d: %v", n, err)
		}
	}
}

func TestMixMonoStereoAlignment(t *testing.T) {
	a := audioTrack{samples: []int16{100, 100}}
	b := audioTrack{samples: []int16{200, 200}}
	mono := mixMono(a.samples, b.samples)
	if mono[0] != 300 {
		t.Fatalf("mono=%d", mono[0])
	}
}

func TestAudioStatusSRTPAndG729AnnexB(t *testing.T) {
	c := &Call{SDPOffer: mustSDP("v=0\nm=audio 4000 RTP/SAVP 18\na=rtpmap:18 G729/8000\n")}
	rm := resolvedMedia{codecName: "G729", mediaType: "audio", proto: "RTP/SAVP"}
	if got, _ := streamAudioStatus(rm, c); got != AudioStatusEncryptedUnavailable {
		t.Fatalf("SRTP=%s", got)
	}
	c = &Call{SDPOffer: mustSDP("v=0\nm=audio 4000 RTP/AVP 18\na=rtpmap:18 G729/8000\na=fmtp:18 annexb=yes\n")}
	rm = resolvedMedia{codecName: "G729", mediaType: "audio", proto: "RTP/AVP", fmtp: "annexb=yes"}
	if got, _ := streamAudioStatus(rm, c); got != AudioStatusUnsupportedG729AnnexB {
		t.Fatalf("annexb=%s", got)
	}
}

func TestDynamicG729SDPAndPtime(t *testing.T) {
	desc := mustSDP("v=0\nm=audio 4000 RTP/AVP 96\na=rtpmap:96 G729/8000\na=fmtp:96 annexb=no\na=ptime:20\n")
	if got := desc.Media[0].Codecs[96].Name; got != "G729" {
		t.Fatalf("rtpmap dinámico=%q", got)
	}
	if got := desc.Media[0].PtimeMs; got != 20 {
		t.Fatalf("ptime=%d", got)
	}
	rm := resolvedMedia{codecName: "G729", mediaType: "audio", proto: "RTP/AVP", fmtp: "annexb=no", ptimeMs: 20}
	if status, _ := streamAudioStatus(rm, &Call{SDPOffer: desc}); status != AudioStatusReconstructable {
		t.Fatalf("status=%s", status)
	}
}

func mustSDP(raw string) *sdp.SDP { return sdp.Parse([]byte(raw)) }

func TestReconstructRejectsEncryptedBeforeDecoder(t *testing.T) {
	_, err := reconstructStream(context.Background(), "missing.pcap", StreamInfo{AudioStatus: AudioStatusEncryptedUnavailable})
	if err == nil {
		t.Fatal("SRTP debe bloquear antes de abrir/decodificar")
	}
}
