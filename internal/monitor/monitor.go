// Package monitor implements the historical monitor (prompt maestro §9 Fase
// 5, módulo 25): continuous Ping/MTR against one or more targets, with
// configurable retention, degradation events, window comparison and
// per-hop/per-target history — reusing the existing Ping/MTR engines rather
// than re-implementing probing (prompt maestro §5.2 "no reescribir
// protocolos sin necesidad").
//
// History persists as one JSON file per target under the user's config
// directory (os.UserConfigDir()/TRAZIP/monitor), the same convention
// internal/intel/geoupdate already uses — never inside the read-only
// install directory, and never a database dependency for what is, in
// practice, a bounded, append-mostly time series.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"trazip/internal/paths"
	"trazip/internal/probe/mtr"
	"trazip/internal/probe/ping"
)

type Mode string

const (
	ModePing Mode = "ping"
	ModeMTR  Mode = "mtr"
)

// Target is one monitored destination.
type Target struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Address        string `json:"address"`
	Mode           Mode   `json:"mode"`
	IntervalMs     int    `json:"intervalMs"`
	RetentionHours int    `json:"retentionHours"`
	CreatedAt      string `json:"createdAt"` // RFC3339
}

func (t *Target) withDefaults() {
	if t.IntervalMs <= 0 {
		t.IntervalMs = 5000
	}
	if t.RetentionHours <= 0 {
		t.RetentionHours = 24
	}
	if t.Mode != ModeMTR {
		t.Mode = ModePing
	}
}

// Sample is one measurement point. HopCount/Hops are only set for MTR mode.
type Sample struct {
	Time     string  `json:"time"` // RFC3339
	OK       bool    `json:"ok"`
	RTTms    float64 `json:"rttMs"`
	LossPct  float64 `json:"lossPct"`
	HopCount int     `json:"hopCount,omitempty"`
	Hops     []Hop   `json:"hops,omitempty"`
}

// Hop is one MTR hop's stats at the moment of this sample.
type Hop struct {
	TTL     int     `json:"ttl"`
	Addr    string  `json:"addr,omitempty"`
	Host    string  `json:"host,omitempty"`
	LossPct float64 `json:"lossPct"`
	AvgMs   float64 `json:"avgMs"`
}

// DegradationEvent flags a notable change relative to the rolling baseline —
// never a silent statistic; every entry explains itself. Also carries
// confirmed route changes (Phase D) — the same Events timeline, not a
// second one, per the master plan's own instruction not to fork the
// timeline model.
type DegradationEvent struct {
	Time   string `json:"time"` // RFC3339
	Kind   string `json:"kind"` // "loss" | "latency" | "recovery" | "route_change"
	Detail string `json:"detail"`
	// RouteChange is non-nil only when Kind == "route_change" — the full
	// structured before/after this Detail string summarizes. Backward
	// compatible: every existing reader of Kind/Detail (report.go's table,
	// any code that only cares about the older three kinds) keeps working
	// unchanged; RouteChange is additive.
	RouteChange *RouteChange `json:"routeChange,omitempty"`
}

// History is one target's full persisted record.
type History struct {
	Target   Target             `json:"target"`
	Samples  []Sample           `json:"samples"`
	Events   []DegradationEvent `json:"events"`
	Baseline *BaselineProfile   `json:"baseline,omitempty"`
}

// BaselineProfile is a fixed reference window the user pinned as "this is
// what normal looks like" — deliberately separate from the rolling baseline
// in degradation.go (last 20 OK samples), which drifts upward under
// sustained load and silently absorbs it as the new normal. A pinned
// baseline stays put until the user re-pins or clears it, so comparing
// against it can surface degradation that a rolling average would miss.
type BaselineProfile struct {
	PinnedAt   string  `json:"pinnedAt"`   // RFC3339, when it was pinned
	WindowFrom string  `json:"windowFrom"` // RFC3339
	WindowTo   string  `json:"windowTo"`   // RFC3339
	Samples    int     `json:"samples"`
	AvgRTTms   float64 `json:"avgRttMs"`
	LossPct    float64 `json:"lossPct"`
}

// BaselineComparison contrasts a pinned BaselineProfile against a recent
// window of live samples.
type BaselineComparison struct {
	Baseline      BaselineProfile `json:"baseline"`
	Current       WindowStats     `json:"current"`
	DeltaAvgRTTms float64         `json:"deltaAvgRttMs"`
	DeltaLossPct  float64         `json:"deltaLossPct"`
}

// WindowStats summarizes one time window of samples.
type WindowStats struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Samples  int     `json:"samples"`
	LossPct  float64 `json:"lossPct"`
	AvgRTTms float64 `json:"avgRttMs"`
	MaxRTTms float64 `json:"maxRttMs"`
	MinRTTms float64 `json:"minRttMs"`
}

// WindowComparison contrasts two windows of the same target's history —
// e.g. "last hour" vs "the hour before" — never asserting causation, just
// the delta.
type WindowComparison struct {
	TargetID      string      `json:"targetId"`
	Recent        WindowStats `json:"recent"`
	Previous      WindowStats `json:"previous"`
	DeltaAvgRTTms float64     `json:"deltaAvgRttMs"`
	DeltaLossPct  float64     `json:"deltaLossPct"`
}

type runningMonitor struct {
	cancel context.CancelFunc
}

// Manager owns the on-disk history store and the set of currently-running
// monitors. Safe for concurrent use.
type Manager struct {
	dir string

	mu      sync.Mutex
	running map[string]*runningMonitor
	targets map[string]Target
}

// NewManager opens (or creates) the monitor store directory.
func NewManager() *Manager {
	return newManagerAt(monitorDir())
}

// newManagerAt is the shared constructor; tests point it at a temp dir so
// they never touch the real user config directory.
func newManagerAt(dir string) *Manager {
	os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	m := &Manager{dir: dir, running: map[string]*runningMonitor{}, targets: map[string]Target{}}
	m.loadTargetsFromDisk()
	return m
}

func monitorDir() string {
	return paths.Sub("monitor")
}

func (m *Manager) targetPath(id string) string {
	if _, err := uuid.Parse(id); err != nil {
		return filepath.Join(m.dir, ".invalid-id")
	}
	return filepath.Join(m.dir, id+".json")
}

func (m *Manager) loadTargetsFromDisk() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		h, err := readHistory(filepath.Join(m.dir, e.Name()))
		if err != nil {
			continue
		}
		m.targets[h.Target.ID] = h.Target
	}
}

func readHistory(path string) (History, error) {
	var h History
	body, err := os.ReadFile(path)
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(body, &h); err != nil {
		return h, err
	}
	return h, nil
}

func writeHistory(path string, h History) error {
	body, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddTarget registers a new monitored target and persists an empty history
// for it immediately, so it survives even if Start is never called.
func (m *Manager) AddTarget(t Target) (Target, error) {
	if t.Address == "" {
		return Target{}, fmt.Errorf("dirección requerida")
	}
	t.withDefaults()
	t.ID = uuid.NewString()
	t.CreatedAt = time.Now().Format(time.RFC3339)

	m.mu.Lock()
	m.targets[t.ID] = t
	m.mu.Unlock()

	path := m.targetPath(t.ID)
	if err := writeHistory(path, History{Target: t}); err != nil {
		return Target{}, err
	}
	return t, nil
}

// ListTargets returns every registered target, whether running or not.
func (m *Manager) ListTargets() []Target {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Target, 0, len(m.targets))
	for _, t := range m.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// RemoveTarget stops the monitor if running and deletes its stored history.
func (m *Manager) RemoveTarget(id string) error {
	m.Stop(id)
	m.mu.Lock()
	if _, ok := m.targets[id]; !ok {
		m.mu.Unlock()
		return fmt.Errorf("target no encontrado: %s", id)
	}
	delete(m.targets, id)
	m.mu.Unlock()
	path := m.targetPath(id)
	return os.Remove(path)
}

// IsRunning reports whether id currently has an active monitor goroutine.
func (m *Manager) IsRunning(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.running[id]
	return ok
}

// Start launches continuous probing for target id until ctx is cancelled or
// Stop is called. onSample/onEvent stream live updates to the caller (e.g.
// Wails events); samples are also flushed to disk periodically.
func (m *Manager) Start(parent context.Context, id string, onSample func(Sample), onEvent func(DegradationEvent)) error {
	m.mu.Lock()
	t, ok := m.targets[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("target no encontrado: %s", id)
	}
	if _, running := m.running[id]; running {
		m.mu.Unlock()
		return fmt.Errorf("ya hay un monitor corriendo para este target")
	}
	ctx, cancel := context.WithCancel(parent)
	m.running[id] = &runningMonitor{cancel: cancel}
	m.mu.Unlock()

	go m.run(ctx, t, onSample, onEvent)
	return nil
}

// Stop requests cancellation of a running monitor for id, if any, and
// returns immediately — it does NOT wait for the goroutine to actually
// exit. The map entry is removed by run()'s own deferred cleanup only
// after its final flush completes, so IsRunning stays true (correctly)
// until the flush is done; deleting it here instead would let a caller
// observe IsRunning()==false and read stale history before the last
// sample was written to disk (a real race caught by
// TestPingMonitorAgainstLoopback).
func (m *Manager) Stop(id string) {
	m.mu.Lock()
	r, ok := m.running[id]
	m.mu.Unlock()
	if ok {
		r.cancel()
	}
}

// StopAll cancels every running monitor — used on app shutdown so no probing
// continues after the window closes.
func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.running))
	for id := range m.running {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Stop(id)
	}
}

func (m *Manager) run(ctx context.Context, t Target, onSample func(Sample), onEvent func(DegradationEvent)) {
	defer func() {
		m.mu.Lock()
		delete(m.running, t.ID)
		m.mu.Unlock()
	}()

	path := m.targetPath(t.ID)
	h, err := readHistory(path)
	if err != nil {
		h = History{Target: t}
	}
	baseline := newBaseline()
	for _, s := range h.Samples {
		if s.OK {
			baseline.add(s.RTTms)
		}
	}
	routes := newRouteTracker()
	routes.seed(h.Samples)

	dirty := 0
	flush := func() {
		pruneRetention(&h)
		if err := writeHistory(path, h); err == nil {
			dirty = 0
		}
	}
	defer flush()

	ticker := time.NewTicker(time.Duration(t.IntervalMs) * time.Millisecond)
	defer ticker.Stop()

	degraded := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var s Sample
			if t.Mode == ModeMTR {
				s = sampleMTR(ctx, t)
			} else {
				s = samplePing(ctx, t)
			}
			if ctx.Err() != nil {
				return
			}

			ev, nowDegraded := evaluateDegradation(baseline, s, degraded)
			degraded = nowDegraded
			if s.OK {
				baseline.add(s.RTTms)
			}

			h.Samples = append(h.Samples, s)
			if ev != nil {
				h.Events = append(h.Events, *ev)
				if onEvent != nil {
					onEvent(*ev)
				}
			}
			if rc := routes.observe(t.ID, s, h.Events); rc != nil {
				revt := DegradationEvent{
					Time: rc.DetectedAt, Kind: "route_change",
					Detail:      fmt.Sprintf("Ruta cambió desde el salto %d", rc.FirstChangedTTL),
					RouteChange: rc,
				}
				h.Events = append(h.Events, revt)
				if onEvent != nil {
					onEvent(revt)
				}
			}
			if onSample != nil {
				onSample(s)
			}

			dirty++
			if dirty >= 5 {
				flush()
			}
		}
	}
}

func samplePing(ctx context.Context, t Target) Sample {
	now := time.Now()
	addr, err := ping.Resolve(ctx, t.Address, "")
	if err != nil {
		return Sample{Time: now.Format(time.RFC3339), OK: false, LossPct: 100}
	}
	// One-shot single probe via the ping engine's Run with Count=1.
	var reply ping.Reply
	_, _, err = ping.Run(ctx, ping.Config{Target: addr.String(), Count: 1, Timeout: 2 * time.Second}, func(r ping.Reply, _ ping.Snapshot) {
		reply = r
	})
	if err != nil || !reply.OK {
		return Sample{Time: now.Format(time.RFC3339), OK: false, LossPct: 100}
	}
	return Sample{Time: now.Format(time.RFC3339), OK: true, RTTms: reply.RTTms, LossPct: 0}
}

func sampleMTR(ctx context.Context, t Target) Sample {
	now := time.Now()
	rctx, cancel := context.WithTimeout(ctx, time.Duration(t.IntervalMs)*time.Millisecond+3*time.Second)
	defer cancel()

	var last []mtr.HopStat
	_, err := mtr.Run(rctx, mtr.Config{Target: t.Address, MaxHops: 30, Timeout: 1500 * time.Millisecond, RoundInterval: 500 * time.Millisecond}, func(hops []mtr.HopStat) {
		last = hops
		cancel() // one round is enough for a monitor tick
	})
	if err != nil && len(last) == 0 {
		return Sample{Time: now.Format(time.RFC3339), OK: false, LossPct: 100}
	}

	var reached *mtr.HopStat
	var sumLoss, sumRTT float64
	for i := range last {
		sumLoss += last[i].LossPct
		if last[i].Addr != "" {
			sumRTT = last[i].AvgMs
		}
		if last[i].Reached {
			reached = &last[i]
			break
		}
	}
	avgLoss := 0.0
	if len(last) > 0 {
		avgLoss = sumLoss / float64(len(last))
	}
	s := Sample{Time: now.Format(time.RFC3339), OK: reached != nil, LossPct: round2(avgLoss), HopCount: len(last)}
	if reached != nil {
		s.RTTms = reached.AvgMs
	} else {
		s.RTTms = sumRTT
	}
	for _, hp := range last {
		s.Hops = append(s.Hops, Hop{TTL: hp.TTL, Addr: hp.Addr, Host: hp.Hostname, LossPct: hp.LossPct, AvgMs: hp.AvgMs})
	}
	return s
}

func pruneRetention(h *History) {
	if h.Target.RetentionHours <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(h.Target.RetentionHours) * time.Hour)
	kept := h.Samples[:0]
	for _, s := range h.Samples {
		ts, err := time.Parse(time.RFC3339, s.Time)
		if err != nil || ts.After(cutoff) {
			kept = append(kept, s)
		}
	}
	h.Samples = kept

	keptEv := h.Events[:0]
	for _, e := range h.Events {
		ts, err := time.Parse(time.RFC3339, e.Time)
		if err != nil || ts.After(cutoff) {
			keptEv = append(keptEv, e)
		}
	}
	h.Events = keptEv
}

// History returns the persisted history for id, optionally trimmed to the
// last `since` duration (0 = everything on disk).
func (m *Manager) History(id string, since time.Duration) (History, error) {
	path := m.targetPath(id)
	h, err := readHistory(path)
	if err != nil {
		return History{}, fmt.Errorf("no se encontró historial para %s: %w", id, err)
	}
	if since <= 0 {
		return h, nil
	}
	cutoff := time.Now().Add(-since)
	var out History
	out.Target = h.Target
	for _, s := range h.Samples {
		if ts, err := time.Parse(time.RFC3339, s.Time); err == nil && ts.After(cutoff) {
			out.Samples = append(out.Samples, s)
		}
	}
	for _, e := range h.Events {
		if ts, err := time.Parse(time.RFC3339, e.Time); err == nil && ts.After(cutoff) {
			out.Events = append(out.Events, e)
		}
	}
	return out, nil
}

// CompareWindows contrasts the most recent `window` of samples against the
// window immediately before it (module 25 "comparación de ventanas").
func (m *Manager) CompareWindows(id string, window time.Duration) (WindowComparison, error) {
	path := m.targetPath(id)
	h, err := readHistory(path)
	if err != nil {
		return WindowComparison{}, fmt.Errorf("no se encontró historial para %s: %w", id, err)
	}
	now := time.Now()
	recentFrom := now.Add(-window)
	prevFrom := now.Add(-2 * window)

	var recent, previous []Sample
	for _, s := range h.Samples {
		ts, err := time.Parse(time.RFC3339, s.Time)
		if err != nil {
			continue
		}
		if ts.After(recentFrom) {
			recent = append(recent, s)
		} else if ts.After(prevFrom) {
			previous = append(previous, s)
		}
	}

	rs := statsFor(recent, recentFrom, now)
	ps := statsFor(previous, prevFrom, recentFrom)
	return WindowComparison{
		TargetID:      id,
		Recent:        rs,
		Previous:      ps,
		DeltaAvgRTTms: round2(rs.AvgRTTms - ps.AvgRTTms),
		DeltaLossPct:  round2(rs.LossPct - ps.LossPct),
	}, nil
}

// PinBaseline computes stats over a historical window (ending sinceMs ago,
// spanning windowMs before that) and stores them as the target's fixed
// reference profile, replacing any previous one. Unlike the rolling
// baseline used for live degradation events, this profile does not move on
// its own — it stays put until PinBaseline or ClearBaseline is called
// again, so it can catch degradation the rolling average would absorb as
// "the new normal".
func (m *Manager) PinBaseline(id string, since, window time.Duration) (BaselineProfile, error) {
	path := m.targetPath(id)
	h, err := readHistory(path)
	if err != nil {
		return BaselineProfile{}, fmt.Errorf("no se encontró historial para %s: %w", id, err)
	}
	now := time.Now()
	windowTo := now.Add(-since)
	windowFrom := windowTo.Add(-window)

	var inWindow []Sample
	for _, s := range h.Samples {
		ts, err := time.Parse(time.RFC3339, s.Time)
		if err != nil {
			continue
		}
		if ts.After(windowFrom) && ts.Before(windowTo) {
			inWindow = append(inWindow, s)
		}
	}
	if len(inWindow) == 0 {
		return BaselineProfile{}, fmt.Errorf("no hay muestras en esa ventana para fijar un perfil base")
	}

	ws := statsFor(inWindow, windowFrom, windowTo)
	profile := BaselineProfile{
		PinnedAt:   now.Format(time.RFC3339),
		WindowFrom: windowFrom.Format(time.RFC3339),
		WindowTo:   windowTo.Format(time.RFC3339),
		Samples:    ws.Samples,
		AvgRTTms:   ws.AvgRTTms,
		LossPct:    ws.LossPct,
	}
	h.Baseline = &profile
	if err := writeHistory(path, h); err != nil {
		return BaselineProfile{}, err
	}
	return profile, nil
}

// ClearBaseline removes a target's pinned baseline, if any.
func (m *Manager) ClearBaseline(id string) error {
	path := m.targetPath(id)
	h, err := readHistory(path)
	if err != nil {
		return fmt.Errorf("no se encontró historial para %s: %w", id, err)
	}
	h.Baseline = nil
	return writeHistory(path, h)
}

// CompareToBaseline contrasts the target's pinned baseline against its most
// recent hour of samples. It is computed on demand (not streamed) so it
// never touches the hot sampling loop in run().
func (m *Manager) CompareToBaseline(id string) (BaselineComparison, error) {
	path := m.targetPath(id)
	h, err := readHistory(path)
	if err != nil {
		return BaselineComparison{}, fmt.Errorf("no se encontró historial para %s: %w", id, err)
	}
	if h.Baseline == nil {
		return BaselineComparison{}, fmt.Errorf("este target no tiene un perfil base fijado")
	}
	now := time.Now()
	recentFrom := now.Add(-time.Hour)
	var recent []Sample
	for _, s := range h.Samples {
		ts, err := time.Parse(time.RFC3339, s.Time)
		if err == nil && ts.After(recentFrom) {
			recent = append(recent, s)
		}
	}
	cur := statsFor(recent, recentFrom, now)
	return BaselineComparison{
		Baseline:      *h.Baseline,
		Current:       cur,
		DeltaAvgRTTms: round2(cur.AvgRTTms - h.Baseline.AvgRTTms),
		DeltaLossPct:  round2(cur.LossPct - h.Baseline.LossPct),
	}, nil
}

func statsFor(samples []Sample, from, to time.Time) WindowStats {
	ws := WindowStats{From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Samples: len(samples)}
	if len(samples) == 0 {
		return ws
	}
	var lossCount int
	var sum, min, max float64
	first := true
	for _, s := range samples {
		if !s.OK {
			lossCount++
			continue
		}
		if first {
			min, max = s.RTTms, s.RTTms
			first = false
		}
		if s.RTTms < min {
			min = s.RTTms
		}
		if s.RTTms > max {
			max = s.RTTms
		}
		sum += s.RTTms
	}
	okCount := len(samples) - lossCount
	ws.LossPct = round2(float64(lossCount) / float64(len(samples)) * 100)
	if okCount > 0 {
		ws.AvgRTTms = round2(sum / float64(okCount))
		ws.MinRTTms = round2(min)
		ws.MaxRTTms = round2(max)
	}
	return ws
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
