package lab

import (
	"context"
	"os"
	"testing"
)

func TestListReturnsRegisteredScenarios(t *testing.T) {
	scenarios := List()
	if len(scenarios) < 2 {
		t.Fatalf("expected at least 2 scenarios, got %d", len(scenarios))
	}
	for _, s := range scenarios {
		if s.ID == "" || s.Title == "" || s.Description == "" {
			t.Errorf("scenario missing required fields: %+v", s)
		}
		if len(s.Objectives) == 0 {
			t.Errorf("scenario %s has no objectives", s.ID)
		}
		if len(s.Expected) == 0 {
			t.Errorf("scenario %s has no expected facts", s.ID)
		}
	}
}

func TestGetUnknownScenario(t *testing.T) {
	if _, ok := Get("no-existe"); ok {
		t.Error("expected Get to report false for an unregistered scenario")
	}
}

func TestWritePCAPIsDeterministic(t *testing.T) {
	s, ok := Get("voip-rtp-loss")
	if !ok {
		t.Fatal("voip-rtp-loss scenario not registered")
	}
	dir1, dir2 := t.TempDir(), t.TempDir()
	path1, err := s.WritePCAP(dir1)
	if err != nil {
		t.Fatalf("WritePCAP (1): %v", err)
	}
	path2, err := s.WritePCAP(dir2)
	if err != nil {
		t.Fatalf("WritePCAP (2): %v", err)
	}

	data1 := mustRead(t, path1)
	data2 := mustRead(t, path2)
	if len(data1) == 0 {
		t.Fatal("generated PCAP is empty")
	}
	if string(data1) != string(data2) {
		t.Error("WritePCAP must be deterministic: two runs produced different bytes")
	}
}

func TestVoIPLossScenarioMatchesExpected(t *testing.T) {
	s, ok := Get("voip-rtp-loss")
	if !ok {
		t.Fatal("voip-rtp-loss scenario not registered")
	}
	res, err := s.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Err != "" {
		t.Fatalf("Run reported an analysis error: %s", res.Err)
	}
	if !res.AllMatch {
		t.Errorf("expected every fact to match for the scenario's own reference capture: %+v vs %+v (matches=%v)", res.Expected, res.Actual, res.Matches)
	}
}

func TestFlowBasicsScenarioMatchesExpected(t *testing.T) {
	s, ok := Get("flow-basics")
	if !ok {
		t.Fatal("flow-basics scenario not registered")
	}
	res, err := s.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Err != "" {
		t.Fatalf("Run reported an analysis error: %s", res.Err)
	}
	if !res.AllMatch {
		t.Errorf("expected every fact to match for the scenario's own reference capture: %+v vs %+v (matches=%v)", res.Expected, res.Actual, res.Matches)
	}
}

func TestPurpleScanDetectionScenarioMatchesExpected(t *testing.T) {
	s, ok := Get("purple-scan-detection")
	if !ok {
		t.Fatal("purple-scan-detection scenario not registered")
	}
	res, err := s.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Err != "" {
		t.Fatalf("Run reported an analysis error: %s", res.Err)
	}
	if !res.AllMatch {
		t.Errorf("expected every fact to match: %+v vs %+v (matches=%v)", res.Expected, res.Actual, res.Matches)
	}
	if res.Score != 100 || res.Status != "pass" || res.Passed != res.Total {
		t.Fatalf("scorecard incorrect: %+v", res)
	}
}

func TestToReportBuildsComparisonTable(t *testing.T) {
	s, _ := Get("flow-basics")
	res, err := s.Run(context.Background(), t.TempDir())
	if err != nil || res.Err != "" {
		t.Fatalf("Run: %v / %s", err, res.Err)
	}
	rep := ToReport(s, res, "0.1.0-dev")
	if rep.Title == "" || len(rep.Sections) < 2 {
		t.Fatalf("expected a populated report, got %+v", rep)
	}
	found := false
	for _, sec := range rep.Sections {
		if sec.Title == "Comparación esperado vs. obtenido" {
			found = true
			if len(sec.Tables) != 1 || len(sec.Tables[0].Rows) != len(res.Expected) {
				t.Errorf("comparison table shape unexpected: %+v", sec.Tables)
			}
		}
	}
	if !found {
		t.Error("expected a comparison section in the report")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}
