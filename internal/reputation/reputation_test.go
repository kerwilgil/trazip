package reputation

import (
	"net/netip"
	"testing"
)

func TestAssessOfflineCleanPublicAddress(t *testing.T) {
	addr := netip.MustParseAddr("1.1.1.1")
	score := AssessOffline(addr)
	if score.Value != 100 {
		t.Errorf("Value = %d, want 100 for a plain public address", score.Value)
	}
	if score.Level != levelClean {
		t.Errorf("Level = %q, want %q", score.Level, levelClean)
	}
	if len(score.Signals) != 0 {
		t.Errorf("Signals = %+v, want none for a clean public address", score.Signals)
	}
}

func TestAssessOfflineBogonHeavilyPenalized(t *testing.T) {
	// 0.0.0.0 is "this network" — a bogon per classify.isBogon.
	addr := netip.MustParseAddr("0.0.0.0")
	score := AssessOffline(addr)
	if score.Level != levelHighRisk {
		t.Errorf("Level = %q, want %q for a bogon address", score.Level, levelHighRisk)
	}
	found := false
	for _, s := range score.Signals {
		if s.Label == "bogon" {
			found = true
			if s.Delta >= 0 {
				t.Errorf("bogon signal Delta = %d, want negative", s.Delta)
			}
		}
	}
	if !found {
		t.Error("expected a bogon signal")
	}
}

func TestAssessOfflineDocumentationOnlyAddress(t *testing.T) {
	// All three IPv4 TEST-NET ranges are classified as documentation AND
	// bogon simultaneously in classify.go; 2001:db8::/32 is IPv6-only
	// documentation (isBogon only checks IPv4), so it's the one address
	// that isolates the documentation signal alone.
	addr := netip.MustParseAddr("2001:db8::1")
	score := AssessOffline(addr)
	if score.Value != 100-15 {
		t.Errorf("Value = %d, want %d (documentation weight only)", score.Value, 100-15)
	}
	if score.Level != levelClean { // 85 still clears the >=80 "limpio" threshold
		t.Errorf("Level = %q, want %q", score.Level, levelClean)
	}
	if len(score.Signals) != 1 {
		t.Fatalf("Signals = %+v, want exactly the documentation signal", score.Signals)
	}
}

func TestAssessOfflineStacksMultipleSignals(t *testing.T) {
	// 192.0.2.0/24 (TEST-NET-1) matches both isDocumentation and isBogon
	// independently in classify.Classify — both signals must stack.
	addr := netip.MustParseAddr("192.0.2.1")
	score := AssessOffline(addr)
	if score.Value != 100-15-70 {
		t.Errorf("Value = %d, want %d (documentation + bogon stacked)", score.Value, 100-15-70)
	}
	if len(score.Signals) != 2 {
		t.Fatalf("Signals = %+v, want 2 entries (documentation + bogon)", score.Signals)
	}
}

func TestAssessOfflineScoreNeverNegative(t *testing.T) {
	addr := netip.MustParseAddr("0.0.0.0")
	score := AssessOffline(addr)
	if score.Value < 0 {
		t.Errorf("Value = %d, must never go below 0", score.Value)
	}
}

func TestLevelFromValueThresholds(t *testing.T) {
	cases := map[int]string{
		100: levelClean,
		80:  levelClean,
		79:  levelSuspicious,
		40:  levelSuspicious,
		39:  levelHighRisk,
		0:   levelHighRisk,
	}
	for v, want := range cases {
		if got := levelFromValue(v); got != want {
			t.Errorf("levelFromValue(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestWithAdapterSignalAdjustsScore(t *testing.T) {
	base := AssessOffline(netip.MustParseAddr("1.1.1.1"))
	adjusted := WithAdapterSignal(base, Signal{Source: "ipquery.io", Label: "known-abuse", Confidence: "media"}, 25)
	if adjusted.Value != 75 {
		t.Errorf("Value = %d, want 75 after a -25 adapter signal", adjusted.Value)
	}
	if len(adjusted.Signals) != 1 {
		t.Fatalf("Signals = %+v, want 1 entry", adjusted.Signals)
	}
	if adjusted.Signals[0].Delta != -25 {
		t.Errorf("Signal.Delta = %d, want -25", adjusted.Signals[0].Delta)
	}
	if adjusted.Level != levelSuspicious {
		t.Errorf("Level = %q, want %q", adjusted.Level, levelSuspicious)
	}
	// The original Score must not be mutated (Signals slice append safety).
	if len(base.Signals) != 0 {
		t.Errorf("base.Signals mutated: %+v", base.Signals)
	}
}

func TestWithAdapterSignalClampsToZero(t *testing.T) {
	base := Score{Value: 10}
	adjusted := WithAdapterSignal(base, Signal{Label: "x"}, 50)
	if adjusted.Value != 0 {
		t.Errorf("Value = %d, want clamped to 0", adjusted.Value)
	}
}
