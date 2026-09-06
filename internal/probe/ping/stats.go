package ping

import (
	"math"
	"time"
)

// Stats is a streaming accumulator for ping round-trip times. It computes min,
// avg, max, standard deviation (Welford) and jitter (mean absolute difference of
// consecutive RTTs) without retaining every sample.
type Stats struct {
	sent int
	recv int

	minMs  float64
	maxMs  float64
	lastMs float64

	n    int // number of received samples
	mean float64
	m2   float64 // Welford sum of squares of differences

	hasPrev bool
	prevMs  float64
	jitSum  float64
	jitN    int
}

// MarkSent records that a probe was transmitted.
func (s *Stats) MarkSent() { s.sent++ }

// AddReply records a successful round-trip time.
func (s *Stats) AddReply(rtt time.Duration) {
	x := float64(rtt) / float64(time.Millisecond)
	s.recv++
	if s.n == 0 || x < s.minMs {
		s.minMs = x
	}
	if s.n == 0 || x > s.maxMs {
		s.maxMs = x
	}
	s.n++
	d := x - s.mean
	s.mean += d / float64(s.n)
	s.m2 += d * (x - s.mean)

	if s.hasPrev {
		s.jitSum += math.Abs(x - s.prevMs)
		s.jitN++
	}
	s.prevMs = x
	s.hasPrev = true
	s.lastMs = x
}

// Snapshot is an immutable view of the accumulated statistics (all times in ms).
type Snapshot struct {
	Sent     int     `json:"sent"`
	Recv     int     `json:"recv"`
	Lost     int     `json:"lost"`
	LossPct  float64 `json:"lossPct"`
	MinMs    float64 `json:"minMs"`
	AvgMs    float64 `json:"avgMs"`
	MaxMs    float64 `json:"maxMs"`
	StdDevMs float64 `json:"stdDevMs"`
	JitterMs float64 `json:"jitterMs"`
	LastMs   float64 `json:"lastMs"`
}

// Snapshot computes the current statistics.
func (s *Stats) Snapshot() Snapshot {
	snap := Snapshot{
		Sent:   s.sent,
		Recv:   s.recv,
		Lost:   s.sent - s.recv,
		LastMs: round2(s.lastMs),
	}
	if s.sent > 0 {
		snap.LossPct = round2(float64(s.sent-s.recv) / float64(s.sent) * 100)
	}
	if s.n > 0 {
		snap.MinMs = round2(s.minMs)
		snap.MaxMs = round2(s.maxMs)
		snap.AvgMs = round2(s.mean)
	}
	if s.n > 1 {
		snap.StdDevMs = round2(math.Sqrt(s.m2 / float64(s.n)))
	}
	if s.jitN > 0 {
		snap.JitterMs = round2(s.jitSum / float64(s.jitN))
	}
	return snap
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
