package monitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTargetIDsCannotEscapeHistoryDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "monitor")
	m := newManagerAt(dir)
	sentinel := filepath.Join(root, "sentinel.json")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveTarget("../sentinel"); err == nil {
		t.Fatal("expected traversal-shaped id to be rejected")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel outside store was touched: %v", err)
	}
}

func TestAddListRemoveTarget(t *testing.T) {
	m := newManagerAt(t.TempDir())

	tg, err := m.AddTarget(Target{Label: "Google DNS", Address: "8.8.8.8"})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}
	if tg.ID == "" {
		t.Fatal("expected a generated ID")
	}
	if tg.IntervalMs != 5000 || tg.RetentionHours != 24 || tg.Mode != ModePing {
		t.Errorf("defaults not applied: %+v", tg)
	}

	list := m.ListTargets()
	if len(list) != 1 || list[0].ID != tg.ID {
		t.Fatalf("ListTargets = %+v, want the one target just added", list)
	}

	if err := m.RemoveTarget(tg.ID); err != nil {
		t.Fatalf("RemoveTarget: %v", err)
	}
	if len(m.ListTargets()) != 0 {
		t.Error("expected no targets after RemoveTarget")
	}
}

func TestAddTargetRequiresAddress(t *testing.T) {
	m := newManagerAt(t.TempDir())
	if _, err := m.AddTarget(Target{Label: "sin dirección"}); err == nil {
		t.Error("expected an error for an empty address")
	}
}

func TestTargetsSurviveManagerRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := newManagerAt(dir)
	tg, _ := m1.AddTarget(Target{Label: "x", Address: "1.1.1.1"})

	m2 := newManagerAt(dir) // simulates reopening the app
	list := m2.ListTargets()
	if len(list) != 1 || list[0].ID != tg.ID {
		t.Fatalf("target did not survive reload: %+v", list)
	}
}

func TestPingMonitorAgainstLoopback(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, err := m.AddTarget(Target{Label: "loopback", Address: "127.0.0.1", IntervalMs: 150, RetentionHours: 1})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}

	samples := make(chan Sample, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, tg.ID, func(s Sample) { samples <- s }, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsRunning(tg.ID) {
		t.Error("IsRunning should be true right after Start")
	}

	select {
	case s := <-samples:
		if !s.OK {
			t.Errorf("expected an OK sample pinging loopback, got %+v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the first sample")
	}

	m.Stop(tg.ID)
	// Stop is asynchronous (cancels the context); give the goroutine a beat
	// to observe cancellation and flush before asserting.
	deadline := time.Now().Add(2 * time.Second)
	for m.IsRunning(tg.ID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.IsRunning(tg.ID) {
		t.Error("expected the monitor to stop")
	}

	h, err := m.History(tg.ID, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h.Samples) == 0 {
		t.Error("expected at least one sample persisted to disk")
	}
}

func TestStartRejectsDoubleStart(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "127.0.0.1", IntervalMs: 200})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx, tg.ID, nil, nil); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer func() {
		m.Stop(tg.ID)
		deadline := time.Now().Add(2 * time.Second)
		for m.IsRunning(tg.ID) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if m.IsRunning(tg.ID) {
			t.Error("monitor did not stop before test cleanup")
		}
	}()

	if err := m.Start(ctx, tg.ID, nil, nil); err == nil {
		t.Error("expected an error starting an already-running monitor")
	}
}

func TestStartUnknownTarget(t *testing.T) {
	m := newManagerAt(t.TempDir())
	if err := m.Start(context.Background(), "nope", nil, nil); err == nil {
		t.Error("expected an error starting an unregistered target")
	}
}

func TestPruneRetention(t *testing.T) {
	now := time.Now()
	h := History{
		Target: Target{RetentionHours: 1},
		Samples: []Sample{
			{Time: now.Add(-2 * time.Hour).Format(time.RFC3339), OK: true, RTTms: 10},
			{Time: now.Add(-30 * time.Minute).Format(time.RFC3339), OK: true, RTTms: 12},
		},
		Events: []DegradationEvent{
			{Time: now.Add(-2 * time.Hour).Format(time.RFC3339), Kind: "loss"},
			{Time: now.Add(-10 * time.Minute).Format(time.RFC3339), Kind: "recovery"},
		},
	}
	pruneRetention(&h)
	if len(h.Samples) != 1 || h.Samples[0].RTTms != 12 {
		t.Errorf("Samples after prune = %+v, want only the recent one", h.Samples)
	}
	if len(h.Events) != 1 || h.Events[0].Kind != "recovery" {
		t.Errorf("Events after prune = %+v, want only the recent one", h.Events)
	}
}

func TestCompareWindows(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})

	now := time.Now()
	h := History{Target: tg}
	// Previous window (60-30 min ago): stable ~20ms.
	for i := 0; i < 5; i++ {
		h.Samples = append(h.Samples, Sample{Time: now.Add(-time.Duration(45-i) * time.Minute).Format(time.RFC3339), OK: true, RTTms: 20})
	}
	// Recent window (last 30 min): degraded ~80ms with one loss.
	for i := 0; i < 4; i++ {
		h.Samples = append(h.Samples, Sample{Time: now.Add(-time.Duration(20-i*5) * time.Minute).Format(time.RFC3339), OK: true, RTTms: 80})
	}
	h.Samples = append(h.Samples, Sample{Time: now.Add(-1 * time.Minute).Format(time.RFC3339), OK: false, LossPct: 100})

	if err := writeHistory(m.targetPath(tg.ID), h); err != nil {
		t.Fatal(err)
	}

	cmp, err := m.CompareWindows(tg.ID, 30*time.Minute)
	if err != nil {
		t.Fatalf("CompareWindows: %v", err)
	}
	if cmp.Recent.AvgRTTms <= cmp.Previous.AvgRTTms {
		t.Errorf("expected recent window to be slower: recent=%+v previous=%+v", cmp.Recent, cmp.Previous)
	}
	if cmp.DeltaAvgRTTms <= 0 {
		t.Errorf("DeltaAvgRTTms = %f, want positive (recent slower)", cmp.DeltaAvgRTTms)
	}
	if cmp.Recent.LossPct <= 0 {
		t.Errorf("expected the recent window to show the one loss, got %+v", cmp.Recent)
	}
}

func TestPinBaselineComputesWindowStats(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})

	now := time.Now()
	h := History{Target: tg}
	// A quiet window from 3h to 2h ago: stable ~15ms, no loss. Kept strictly
	// inside (windowFrom, windowTo) — PinBaseline's bounds are exclusive.
	for i := 0; i < 6; i++ {
		h.Samples = append(h.Samples, Sample{Time: now.Add(-time.Duration(175-i*10) * time.Minute).Format(time.RFC3339), OK: true, RTTms: 15})
	}
	if err := writeHistory(m.targetPath(tg.ID), h); err != nil {
		t.Fatal(err)
	}

	profile, err := m.PinBaseline(tg.ID, 2*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("PinBaseline: %v", err)
	}
	if profile.Samples != 6 {
		t.Errorf("Samples = %d, want 6", profile.Samples)
	}
	if profile.AvgRTTms != 15 {
		t.Errorf("AvgRTTms = %f, want 15", profile.AvgRTTms)
	}
	if profile.LossPct != 0 {
		t.Errorf("LossPct = %f, want 0", profile.LossPct)
	}

	// Must persist.
	h2, err := readHistory(m.targetPath(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	if h2.Baseline == nil || h2.Baseline.AvgRTTms != 15 {
		t.Fatalf("Baseline did not persist: %+v", h2.Baseline)
	}
}

func TestPinBaselineErrorsOnEmptyWindow(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})
	if _, err := m.PinBaseline(tg.ID, 0, time.Hour); err == nil {
		t.Error("expected an error pinning a baseline with no samples in the window")
	}
}

func TestClearBaseline(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})

	now := time.Now()
	h := History{Target: tg, Samples: []Sample{{Time: now.Add(-time.Minute).Format(time.RFC3339), OK: true, RTTms: 10}}}
	writeHistory(m.targetPath(tg.ID), h)
	if _, err := m.PinBaseline(tg.ID, 0, time.Hour); err != nil {
		t.Fatalf("PinBaseline: %v", err)
	}

	if err := m.ClearBaseline(tg.ID); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	h2, _ := readHistory(m.targetPath(tg.ID))
	if h2.Baseline != nil {
		t.Errorf("expected Baseline to be nil after ClearBaseline, got %+v", h2.Baseline)
	}
}

func TestCompareToBaselineDetectsDrift(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})

	now := time.Now()
	h := History{Target: tg}
	// Quiet reference window (3h-2h ago): ~15ms. Kept strictly inside
	// (windowFrom, windowTo) — PinBaseline's bounds are exclusive.
	for i := 0; i < 5; i++ {
		h.Samples = append(h.Samples, Sample{Time: now.Add(-time.Duration(175-i*10) * time.Minute).Format(time.RFC3339), OK: true, RTTms: 15})
	}
	if err := writeHistory(m.targetPath(tg.ID), h); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PinBaseline(tg.ID, 2*time.Hour, time.Hour); err != nil {
		t.Fatalf("PinBaseline: %v", err)
	}

	// Now append recent, degraded samples (last hour): ~90ms.
	h2, _ := readHistory(m.targetPath(tg.ID))
	for i := 0; i < 4; i++ {
		h2.Samples = append(h2.Samples, Sample{Time: now.Add(-time.Duration(30-i*5) * time.Minute).Format(time.RFC3339), OK: true, RTTms: 90})
	}
	if err := writeHistory(m.targetPath(tg.ID), h2); err != nil {
		t.Fatal(err)
	}

	cmp, err := m.CompareToBaseline(tg.ID)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if cmp.Baseline.AvgRTTms != 15 {
		t.Errorf("Baseline.AvgRTTms = %f, want 15", cmp.Baseline.AvgRTTms)
	}
	if cmp.Current.AvgRTTms <= 15 {
		t.Errorf("Current.AvgRTTms = %f, want > 15 (degraded)", cmp.Current.AvgRTTms)
	}
	if cmp.DeltaAvgRTTms <= 0 {
		t.Errorf("DeltaAvgRTTms = %f, want positive (current worse than baseline)", cmp.DeltaAvgRTTms)
	}
}

func TestCompareToBaselineErrorsWithoutPin(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Address: "1.1.1.1"})
	if _, err := m.CompareToBaseline(tg.ID); err == nil {
		t.Error("expected an error comparing against an unpinned baseline")
	}
}

func TestEvaluateDegradationLatencySpikeAndRecovery(t *testing.T) {
	b := newBaseline()
	for i := 0; i < 10; i++ {
		b.add(20)
	}

	spike := Sample{Time: time.Now().Format(time.RFC3339), OK: true, RTTms: 200}
	ev, degraded := evaluateDegradation(b, spike, false)
	if ev == nil || ev.Kind != "latency" {
		t.Fatalf("expected a latency degradation event, got %+v", ev)
	}
	if !degraded {
		t.Error("expected degraded=true after a latency spike")
	}

	// Still spiking: no repeated event, but still degraded.
	ev2, degraded2 := evaluateDegradation(b, spike, true)
	if ev2 != nil {
		t.Errorf("expected no repeat event while still degraded, got %+v", ev2)
	}
	if !degraded2 {
		t.Error("expected degraded to remain true")
	}

	normal := Sample{Time: time.Now().Format(time.RFC3339), OK: true, RTTms: 21}
	ev3, degraded3 := evaluateDegradation(b, normal, true)
	if ev3 == nil || ev3.Kind != "recovery" {
		t.Fatalf("expected a recovery event, got %+v", ev3)
	}
	if degraded3 {
		t.Error("expected degraded=false after recovery")
	}
}

func TestEvaluateDegradationLossStreak(t *testing.T) {
	b := newBaseline()
	lost := Sample{Time: time.Now().Format(time.RFC3339), OK: false}

	var lastEvent *DegradationEvent
	degraded := false
	for i := 0; i < lossDegradeStreak; i++ {
		lastEvent, degraded = evaluateDegradation(b, lost, degraded)
	}
	if lastEvent == nil || lastEvent.Kind != "loss" {
		t.Fatalf("expected a loss event after %d consecutive losses, got %+v", lossDegradeStreak, lastEvent)
	}
	if !degraded {
		t.Error("expected degraded=true after the loss streak")
	}
}

func TestEvaluateDegradationNoBaselineNoFalsePositive(t *testing.T) {
	b := newBaseline() // empty baseline: nothing to compare against yet
	s := Sample{Time: time.Now().Format(time.RFC3339), OK: true, RTTms: 500}
	ev, degraded := evaluateDegradation(b, s, false)
	if ev != nil || degraded {
		t.Errorf("a single sample with no baseline must never be flagged as degraded, got ev=%+v degraded=%v", ev, degraded)
	}
}
