// Package quality tracks VoIP call quality (jitter, packet loss, MOS) over
// time, grouped by a user-defined "línea" (destination/trunk). It closes a
// gap in internal/voip: every analysis there is a one-shot correlation of a
// single capture with no persisted history, so there was no way to know
// whether today's calls are worse than what's normal for a given
// destination. Storage mirrors internal/monitor's conventions (one JSON
// file per target under the user's config dir, atomic writes) but this
// package has no probing loop of its own — ingestion is passive, driven by
// whatever VoIP analyses the app already runs (see App.StartVoIPAnalysis).
package quality

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"trazip/internal/paths"
	"trazip/internal/voip"
)

// Target is one "línea" (VoIP destination/trunk) the user wants tracked.
// Match is a case-insensitive substring compared against each Call's
// From/To to decide whether it belongs to this line — VoIP calls carry no
// normalized line/trunk identifier (raw SIP URIs only), so this is a
// deliberately simple, user-controlled grouping key rather than an attempt
// at automatic SIP trunk detection.
type Target struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Match     string `json:"match"`
	CreatedAt string `json:"createdAt"` // RFC3339
}

// Sample is one call's aggregate quality, attributed to a Target.
type Sample struct {
	Time        string  `json:"time"` // RFC3339
	CallID      string  `json:"callId"`
	From        string  `json:"from,omitempty"`
	To          string  `json:"to,omitempty"`
	Established bool    `json:"established"`
	AvgJitterMs float64 `json:"avgJitterMs"`
	AvgLossPct  float64 `json:"avgLossPct"`
	MOS         float64 `json:"mos,omitempty"` // 0 = no stream had enough packets for an estimate
}

// History is one target's full persisted record.
type History struct {
	Target  Target   `json:"target"`
	Samples []Sample `json:"samples"`
}

// WindowStats summarizes one time window of samples.
type WindowStats struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	Samples     int     `json:"samples"`
	AvgJitterMs float64 `json:"avgJitterMs"`
	AvgLossPct  float64 `json:"avgLossPct"`
	AvgMOS      float64 `json:"avgMos"`
}

// WindowComparison contrasts two windows of the same target's history —
// e.g. "last hour" vs "the hour before".
type WindowComparison struct {
	TargetID      string      `json:"targetId"`
	Recent        WindowStats `json:"recent"`
	Previous      WindowStats `json:"previous"`
	DeltaJitterMs float64     `json:"deltaJitterMs"`
	DeltaLossPct  float64     `json:"deltaLossPct"`
	DeltaMOS      float64     `json:"deltaMos"`
}

// Manager owns the on-disk history store. Safe for concurrent use.
type Manager struct {
	dir string

	mu      sync.Mutex
	targets map[string]Target
}

// NewManager opens (or creates) the quality store directory.
func NewManager() *Manager {
	return newManagerAt(qualityDir())
}

// newManagerAt is the shared constructor; tests point it at a temp dir so
// they never touch the real user config directory.
func newManagerAt(dir string) *Manager {
	os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	m := &Manager{dir: dir, targets: map[string]Target{}}
	m.loadTargetsFromDisk()
	return m
}

func qualityDir() string {
	return paths.Sub("voipquality")
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

// AddTarget registers a new tracked line and persists an empty history for
// it immediately, so it survives even before any call matches it.
func (m *Manager) AddTarget(t Target) (Target, error) {
	if strings.TrimSpace(t.Label) == "" {
		return Target{}, fmt.Errorf("etiqueta requerida")
	}
	if strings.TrimSpace(t.Match) == "" {
		return Target{}, fmt.Errorf("patrón de coincidencia requerido")
	}
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

// ListTargets returns every registered line.
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

// RemoveTarget deletes a tracked line and its stored history.
func (m *Manager) RemoveTarget(id string) error {
	m.mu.Lock()
	if _, ok := m.targets[id]; !ok {
		m.mu.Unlock()
		return fmt.Errorf("línea no encontrada: %s", id)
	}
	delete(m.targets, id)
	m.mu.Unlock()
	path := m.targetPath(id)
	return os.Remove(path)
}

// IngestResult attributes every call in result to whichever registered
// targets it matches (by substring against From/To), appending one Sample
// per match and persisting immediately. Called after every VoIP analysis,
// whether or not anyone is looking at the Histórico panel, so history
// accumulates passively over time.
func (m *Manager) IngestResult(result voip.Result) {
	m.mu.Lock()
	targets := make([]Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	m.mu.Unlock()
	if len(targets) == 0 {
		return
	}

	now := time.Now().Format(time.RFC3339)
	for _, t := range targets {
		var samples []Sample
		for _, call := range result.Calls {
			if !callMatches(call, t.Match) {
				continue
			}
			if sample, ok := sampleFromCall(call, now); ok {
				samples = append(samples, sample)
			}
		}
		if len(samples) == 0 {
			continue
		}
		path := m.targetPath(t.ID)
		h, err := readHistory(path)
		if err != nil {
			h = History{Target: t}
		}
		h.Samples = append(h.Samples, samples...)
		_ = writeHistory(path, h)
	}
}

func callMatches(c voip.Call, match string) bool {
	needle := strings.ToLower(match)
	return strings.Contains(strings.ToLower(c.From), needle) || strings.Contains(strings.ToLower(c.To), needle)
}

// sampleFromCall builds a voice-quality Sample from a call, or (Sample{},
// false) when the call has streams but NONE of them are audio (a video-only
// call, for instance) — there is no voice signal to sample at all in that
// case, and 0ms jitter/0% loss/no MOS would misrepresent "no audio observed"
// as "perfect audio", which IngestResult would otherwise persist and the
// Histórico panel would show as a real sample. A call with NO streams at all
// (failed call, no RTP captured) is unaffected by this — same pre-existing
// behavior as before, out of scope for this fix.
func sampleFromCall(c voip.Call, at string) (Sample, bool) {
	s := Sample{
		Time:        at,
		CallID:      c.CallID,
		From:        c.From,
		To:          c.To,
		Established: c.Established,
	}
	var jitterSum, lossSum, mosSum float64
	var audioN, mosN int
	for _, st := range c.Streams {
		// Quality history is a voice-quality metric (jitter/packet loss/MOS,
		// surfaced as "VoIP call quality") — a video stream's independent
		// numbers must not dilute the voice average. MediaType == "" (older
		// in-memory data predating this field, or no SDP captured) is
		// treated as audio, matching the same leniency EstimateMOS's own
		// gate and Diagnose's worstStream selection already use.
		if st.MediaType != "" && st.MediaType != "audio" {
			continue
		}
		jitterSum += st.Stats.JitterMs
		lossSum += st.Stats.LossPct
		audioN++
		if st.MOS != nil {
			mosSum += st.MOS.Score
			mosN++
		}
	}
	if len(c.Streams) > 0 && audioN == 0 {
		return Sample{}, false
	}
	if audioN > 0 {
		s.AvgJitterMs = round2(jitterSum / float64(audioN))
		s.AvgLossPct = round2(lossSum / float64(audioN))
	}
	if mosN > 0 {
		s.MOS = round2(mosSum / float64(mosN))
	}
	return s, true
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
	out := History{Target: h.Target}
	for _, s := range h.Samples {
		if ts, err := time.Parse(time.RFC3339, s.Time); err == nil && ts.After(cutoff) {
			out.Samples = append(out.Samples, s)
		}
	}
	return out, nil
}

// CompareWindows contrasts the most recent `window` of samples against the
// window immediately before it.
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
		DeltaJitterMs: round2(rs.AvgJitterMs - ps.AvgJitterMs),
		DeltaLossPct:  round2(rs.AvgLossPct - ps.AvgLossPct),
		DeltaMOS:      round2(rs.AvgMOS - ps.AvgMOS),
	}, nil
}

func statsFor(samples []Sample, from, to time.Time) WindowStats {
	ws := WindowStats{From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Samples: len(samples)}
	if len(samples) == 0 {
		return ws
	}
	var jitterSum, lossSum, mosSum float64
	var mosN int
	for _, s := range samples {
		jitterSum += s.AvgJitterMs
		lossSum += s.AvgLossPct
		if s.MOS > 0 {
			mosSum += s.MOS
			mosN++
		}
	}
	ws.AvgJitterMs = round2(jitterSum / float64(len(samples)))
	ws.AvgLossPct = round2(lossSum / float64(len(samples)))
	if mosN > 0 {
		ws.AvgMOS = round2(mosSum / float64(mosN))
	}
	return ws
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
