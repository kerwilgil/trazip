package voip

import "testing"

// Exact ingest-ceiling boundaries, proven against the SAME helper
// reconstructStream calls (acceptEncodedFrame) — never a copy of the condition.
func TestAcceptEncodedFrameExactBoundaries(t *testing.T) {
	if !acceptEncodedFrame(maxAudioPackets-1, 0, 160) {
		t.Fatalf("packet MAX (%d) must be accepted", maxAudioPackets)
	}
	if acceptEncodedFrame(maxAudioPackets, 0, 160) {
		t.Fatalf("packet MAX+1 (%d) must be rejected", maxAudioPackets+1)
	}
	if !acceptEncodedFrame(0, maxEncodedAudioBytes-160, 160) {
		t.Fatal("payload MAX (exactly maxEncodedAudioBytes total) must be accepted")
	}
	if acceptEncodedFrame(0, maxEncodedAudioBytes-160, 161) {
		t.Fatal("payload MAX+1 (one byte over) must be rejected")
	}
	if acceptEncodedFrame(maxAudioPackets+1000000, 0, 1) {
		t.Fatal("far past packet ceiling must stay rejected")
	}
	if acceptEncodedFrame(0, maxEncodedAudioBytes, 1) {
		t.Fatal("already at byte ceiling: any further payload rejected")
	}
}
