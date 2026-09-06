package ping

import (
	"math"
	"testing"
	"time"
)

func approx(a, b, eps float64) bool { return math.Abs(a-b) <= eps }

func TestStatsBasic(t *testing.T) {
	var s Stats
	// 4 sent, 3 received: 10ms, 20ms, 30ms; one loss.
	s.MarkSent()
	s.AddReply(10 * time.Millisecond)
	s.MarkSent()
	s.AddReply(20 * time.Millisecond)
	s.MarkSent()
	s.AddReply(30 * time.Millisecond)
	s.MarkSent() // lost

	snap := s.Snapshot()
	if snap.Sent != 4 || snap.Recv != 3 || snap.Lost != 1 {
		t.Fatalf("counts wrong: %+v", snap)
	}
	if !approx(snap.LossPct, 25, 0.01) {
		t.Errorf("lossPct = %v, want 25", snap.LossPct)
	}
	if !approx(snap.MinMs, 10, 0.01) || !approx(snap.MaxMs, 30, 0.01) || !approx(snap.AvgMs, 20, 0.01) {
		t.Errorf("min/avg/max wrong: %+v", snap)
	}
	// population stddev of [10,20,30] = sqrt(200/3) ≈ 8.165
	if !approx(snap.StdDevMs, 8.16, 0.05) {
		t.Errorf("stdDev = %v, want ≈8.16", snap.StdDevMs)
	}
	// jitter = mean(|20-10|, |30-20|) = 10
	if !approx(snap.JitterMs, 10, 0.01) {
		t.Errorf("jitter = %v, want 10", snap.JitterMs)
	}
	if !approx(snap.LastMs, 30, 0.01) {
		t.Errorf("last = %v, want 30", snap.LastMs)
	}
}

func TestStatsAllLost(t *testing.T) {
	var s Stats
	for i := 0; i < 3; i++ {
		s.MarkSent()
	}
	snap := s.Snapshot()
	if snap.Sent != 3 || snap.Recv != 0 || snap.Lost != 3 {
		t.Fatalf("counts wrong: %+v", snap)
	}
	if !approx(snap.LossPct, 100, 0.01) {
		t.Errorf("lossPct = %v, want 100", snap.LossPct)
	}
	if snap.AvgMs != 0 || snap.MinMs != 0 || snap.MaxMs != 0 {
		t.Errorf("no samples should give zero stats: %+v", snap)
	}
}

func TestStatsSingleSample(t *testing.T) {
	var s Stats
	s.MarkSent()
	s.AddReply(15 * time.Millisecond)
	snap := s.Snapshot()
	if !approx(snap.AvgMs, 15, 0.01) || !approx(snap.MinMs, 15, 0.01) || !approx(snap.MaxMs, 15, 0.01) {
		t.Errorf("single sample stats wrong: %+v", snap)
	}
	if snap.StdDevMs != 0 || snap.JitterMs != 0 {
		t.Errorf("single sample stddev/jitter should be 0: %+v", snap)
	}
}
