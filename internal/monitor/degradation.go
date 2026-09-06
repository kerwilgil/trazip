package monitor

import "fmt"

// baselineWindow is how many recent OK samples the rolling baseline
// averages over — short enough to track real conditions, long enough that a
// single slow reply doesn't skew it.
const baselineWindow = 20

// baseline tracks a simple rolling average RTT plus consecutive-loss count,
// used to flag degradation without needing a full statistics package.
type baseline struct {
	samples         []float64
	consecutiveLoss int
}

func newBaseline() *baseline {
	return &baseline{}
}

func (b *baseline) add(rttMs float64) {
	b.samples = append(b.samples, rttMs)
	if len(b.samples) > baselineWindow {
		b.samples = b.samples[len(b.samples)-baselineWindow:]
	}
	b.consecutiveLoss = 0
}

func (b *baseline) avg() float64 {
	if len(b.samples) == 0 {
		return 0
	}
	var sum float64
	for _, v := range b.samples {
		sum += v
	}
	return sum / float64(len(b.samples))
}

const (
	latencyDegradeFactor = 2.0 // current RTT vs baseline avg
	lossDegradeStreak    = 3   // consecutive losses before flagging
)

// evaluateDegradation compares one new sample against the current baseline
// and consecutive-loss streak, returning an event when the state actually
// changes (entering or leaving degradation) — never one event per tick
// while steadily degraded, since that would just be noise.
func evaluateDegradation(b *baseline, s Sample, wasDegraded bool) (*DegradationEvent, bool) {
	if !s.OK {
		b.consecutiveLoss++
		if !wasDegraded && b.consecutiveLoss >= lossDegradeStreak {
			return &DegradationEvent{
				Time:   s.Time,
				Kind:   "loss",
				Detail: fmt.Sprintf("%d pérdidas consecutivas", b.consecutiveLoss),
			}, true
		}
		return nil, wasDegraded || b.consecutiveLoss >= lossDegradeStreak
	}

	avg := b.avg()
	hasBaseline := len(b.samples) >= 5
	isSpike := hasBaseline && s.RTTms > avg*latencyDegradeFactor && s.RTTms > avg+20

	if isSpike {
		if !wasDegraded {
			return &DegradationEvent{
				Time:   s.Time,
				Kind:   "latency",
				Detail: fmt.Sprintf("%.1f ms vs. línea base %.1f ms", s.RTTms, avg),
			}, true
		}
		return nil, true
	}

	if wasDegraded {
		return &DegradationEvent{
			Time:   s.Time,
			Kind:   "recovery",
			Detail: fmt.Sprintf("recuperado: %.1f ms", s.RTTms),
		}, false
	}
	return nil, false
}
