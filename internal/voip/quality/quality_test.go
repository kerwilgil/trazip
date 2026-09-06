package quality

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"trazip/internal/protocol/rtp"
	"trazip/internal/voip"
)

func TestTargetIDsCannotEscapeHistoryDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "quality")
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

func callWithQuality(callID, from, to string, established bool, jitterMs, lossPct, mos float64) voip.Call {
	return voip.Call{
		CallID:      callID,
		From:        from,
		To:          to,
		Established: established,
		Streams: []voip.StreamInfo{
			{
				Stats: rtp.Snapshot{JitterMs: jitterMs, LossPct: lossPct},
				MOS:   &voip.MOSEstimate{Score: mos, Formula: "test"},
			},
		},
	}
}

func TestAddListRemoveTarget(t *testing.T) {
	m := newManagerAt(t.TempDir())

	tg, err := m.AddTarget(Target{Label: "Oficina Panamá", Match: "sip.oficina.pa"})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}
	if tg.ID == "" {
		t.Fatal("expected a generated ID")
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

func TestAddTargetRequiresLabelAndMatch(t *testing.T) {
	m := newManagerAt(t.TempDir())
	if _, err := m.AddTarget(Target{Match: "x"}); err == nil {
		t.Error("expected an error for an empty label")
	}
	if _, err := m.AddTarget(Target{Label: "x"}); err == nil {
		t.Error("expected an error for an empty match pattern")
	}
}

func TestTargetsSurviveManagerRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := newManagerAt(dir)
	tg, _ := m1.AddTarget(Target{Label: "x", Match: "sip.x.com"})

	m2 := newManagerAt(dir) // simulates reopening the app
	list := m2.ListTargets()
	if len(list) != 1 || list[0].ID != tg.ID {
		t.Fatalf("target did not survive reload: %+v", list)
	}
}

func TestIngestResultMatchesBySubstring(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, err := m.AddTarget(Target{Label: "Clientes", Match: "sip.miclientes.com"})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}

	result := voip.Result{Calls: []voip.Call{
		callWithQuality("call-1", "sip:alice@sip.miclientes.com", "sip:bob@other.net", true, 12, 0.5, 4.1),
		callWithQuality("call-2", "sip:carol@unrelated.net", "sip:dave@unrelated.net", true, 5, 0, 4.4),
	}}
	m.IngestResult(result)

	h, err := m.History(tg.ID, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h.Samples) != 1 {
		t.Fatalf("expected exactly 1 matching sample, got %d: %+v", len(h.Samples), h.Samples)
	}
	if h.Samples[0].CallID != "call-1" {
		t.Errorf("CallID = %q, want call-1", h.Samples[0].CallID)
	}
	if h.Samples[0].AvgJitterMs != 12 || h.Samples[0].AvgLossPct != 0.5 || h.Samples[0].MOS != 4.1 {
		t.Errorf("sample quality wrong: %+v", h.Samples[0])
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 5): quality history
// is surfaced as "VoIP call quality" (jitter/packet loss/MOS) — a video
// stream's independent, unrelated numbers must not dilute the voice average.
func TestIngestResultAveragesAudioOnlyIgnoringVideo(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, err := m.AddTarget(Target{Label: "Clientes", Match: "sip.miclientes.com"})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}

	call := voip.Call{
		CallID: "call-1", From: "sip:alice@sip.miclientes.com", To: "sip:bob@other.net", Established: true,
		Streams: []voip.StreamInfo{
			{MediaType: "audio", Stats: rtp.Snapshot{JitterMs: 5, LossPct: 0.5}, MOS: &voip.MOSEstimate{Score: 4.2}},
			{MediaType: "video", Stats: rtp.Snapshot{JitterMs: 100, LossPct: 20}}, // no MOS -- video never gets one
		},
	}
	m.IngestResult(voip.Result{Calls: []voip.Call{call}})

	h, err := m.History(tg.ID, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h.Samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(h.Samples))
	}
	s := h.Samples[0]
	if s.AvgJitterMs != 5 || s.AvgLossPct != 0.5 || s.MOS != 4.2 {
		t.Errorf("sample averaged in the video stream's numbers: %+v, want audio-only (jitter=5, loss=0.5, mos=4.2)", s)
	}
}

// Gate v0.7.3 (last fix before merge): a call whose streams exist but are
// ALL explicitly non-audio (a video-only call) must not create a Quality
// History sample at all — there is no voice signal to sample, and
// 0ms/0%/no-MOS would misrepresent "no audio observed" as "perfect audio".
func TestIngestResultVideoOnlyDoesNotCreateVoiceQualitySample(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, err := m.AddTarget(Target{Label: "Clientes", Match: "sip.miclientes.com"})
	if err != nil {
		t.Fatalf("AddTarget: %v", err)
	}

	call := voip.Call{
		CallID: "call-1", From: "sip:alice@sip.miclientes.com", To: "sip:bob@other.net", Established: true,
		Streams: []voip.StreamInfo{
			{MediaType: "video", Stats: rtp.Snapshot{JitterMs: 100, LossPct: 20}},
		},
	}
	m.IngestResult(voip.Result{Calls: []voip.Call{call}})

	h, err := m.History(tg.ID, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h.Samples) != 0 {
		t.Errorf("a video-only call must not create a voice quality sample, got %d samples: %+v", len(h.Samples), h.Samples)
	}
}

func TestIngestResultNoMatchesWritesNothing(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "Clientes", Match: "sip.miclientes.com"})

	m.IngestResult(voip.Result{Calls: []voip.Call{
		callWithQuality("call-1", "sip:x@unrelated.net", "sip:y@unrelated.net", true, 1, 0, 4.5),
	}})

	h, err := m.History(tg.ID, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(h.Samples) != 0 {
		t.Errorf("expected no samples for a non-matching call, got %d", len(h.Samples))
	}
}

func TestIngestResultNoTargetsIsNoop(t *testing.T) {
	m := newManagerAt(t.TempDir())
	// Must not panic with zero registered targets.
	m.IngestResult(voip.Result{Calls: []voip.Call{
		callWithQuality("call-1", "sip:x@x.com", "sip:y@y.com", true, 1, 0, 4.5),
	}})
}

func TestHistorySinceFiltersOldSamples(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Match: "line.test"})

	path := m.targetPath(tg.ID)
	h, _ := readHistory(path)
	h.Samples = []Sample{
		{Time: time.Now().Add(-2 * time.Hour).Format(time.RFC3339), CallID: "old"},
		{Time: time.Now().Format(time.RFC3339), CallID: "new"},
	}
	if err := writeHistory(path, h); err != nil {
		t.Fatal(err)
	}

	recent, err := m.History(tg.ID, time.Hour)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(recent.Samples) != 1 || recent.Samples[0].CallID != "new" {
		t.Fatalf("expected only the recent sample, got %+v", recent.Samples)
	}
}

func TestCompareWindowsDetectsDegradation(t *testing.T) {
	m := newManagerAt(t.TempDir())
	tg, _ := m.AddTarget(Target{Label: "x", Match: "line.test"})

	now := time.Now()
	path := m.targetPath(tg.ID)
	h, _ := readHistory(path)
	// Previous window (2h-1h ago): good quality. Recent window (last 1h): degraded.
	h.Samples = []Sample{
		{Time: now.Add(-90 * time.Minute).Format(time.RFC3339), AvgJitterMs: 5, AvgLossPct: 0.1, MOS: 4.4},
		{Time: now.Add(-30 * time.Minute).Format(time.RFC3339), AvgJitterMs: 40, AvgLossPct: 3.0, MOS: 3.0},
	}
	if err := writeHistory(path, h); err != nil {
		t.Fatal(err)
	}

	cmp, err := m.CompareWindows(tg.ID, time.Hour)
	if err != nil {
		t.Fatalf("CompareWindows: %v", err)
	}
	if cmp.Recent.Samples != 1 || cmp.Previous.Samples != 1 {
		t.Fatalf("window split wrong: recent=%+v previous=%+v", cmp.Recent, cmp.Previous)
	}
	if cmp.DeltaJitterMs <= 0 {
		t.Errorf("expected positive jitter delta (recent worse), got %f", cmp.DeltaJitterMs)
	}
	if cmp.DeltaMOS >= 0 {
		t.Errorf("expected negative MOS delta (recent worse), got %f", cmp.DeltaMOS)
	}
}
