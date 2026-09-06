package voip

import "testing"

func TestEstimateMOSZeroImpairment(t *testing.T) {
	m := EstimateMOS(0, 0)
	// Published reference: R=93.2 (zero impairment) → MOS ≈ 4.4 (E-model baseline).
	if m.Score < 4.3 || m.Score > 4.5 {
		t.Errorf("MOS at 0%% loss/jitter = %v, want ~4.4", m.Score)
	}
	if len(m.Limitations) == 0 {
		t.Error("limitations must always be documented")
	}
}

func TestEstimateMOSHighLoss(t *testing.T) {
	m := EstimateMOS(20, 0)
	if m.Score > 2.0 {
		t.Errorf("MOS at 20%% loss = %v, want a poor score (<2.0)", m.Score)
	}
}

func TestEstimateMOSMonotonicWithLoss(t *testing.T) {
	prev := EstimateMOS(0, 0).Score
	for _, loss := range []float64{1, 5, 10, 20, 40} {
		cur := EstimateMOS(loss, 0).Score
		if cur > prev {
			t.Errorf("MOS should not increase as loss grows: loss=%v got %v after %v", loss, cur, prev)
		}
		prev = cur
	}
}

func TestEstimateMOSJitterPenalty(t *testing.T) {
	low := EstimateMOS(0, 10).Score
	high := EstimateMOS(0, 100).Score
	if high >= low {
		t.Errorf("high jitter (100ms) MOS=%v should be lower than low jitter (10ms) MOS=%v", high, low)
	}
}

func TestEstimateMOSBounds(t *testing.T) {
	m := EstimateMOS(100, 500)
	if m.Score < 1 || m.Score > 4.5 {
		t.Errorf("MOS out of bounds: %v", m.Score)
	}
	m2 := EstimateMOS(-5, -5) // defensive: never panic on invalid input
	if m2.Score < 1 || m2.Score > 4.5 {
		t.Errorf("MOS with negative input out of bounds: %v", m2.Score)
	}
}
