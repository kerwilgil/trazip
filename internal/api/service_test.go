package api

import (
	"context"
	"testing"

	"trazip/internal/flow"
	"trazip/internal/lab"
	"trazip/internal/model"
)

func TestEndpointsFromFlowsProducesObservedEvidence(t *testing.T) {
	s := NewService()
	rows := s.endpointsFromFlows([]flow.Flow{{
		AAddr: "192.0.2.1", BAddr: "198.51.100.2", Packets: 4, Bytes: 512,
		Start: "2026-07-14T10:00:00Z", End: "2026-07-14T10:00:01Z",
	}})
	if len(rows) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(rows))
	}
	for _, row := range rows {
		if len(row.Evidence) != 1 || row.Evidence[0].Provenance != string(model.ProvObserved) || row.Evidence[0].Confidence != 100 {
			t.Fatalf("endpoint lacks observed evidence: %+v", row)
		}
	}
}

func TestAnalyzePcapIncludesPassiveScanDetection(t *testing.T) {
	scenario, ok := lab.Get("purple-scan-detection")
	if !ok {
		t.Fatal("purple scan scenario not registered")
	}
	run, err := scenario.Run(context.Background(), t.TempDir())
	if err != nil || run.Err != "" {
		t.Fatalf("scenario run: %v / %s", err, run.Err)
	}
	res, err := NewService().AnalyzePcap(run.PcapPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.ScanDetection.Vertical != 1 || res.ScanDetection.Horizontal != 1 || len(res.ScanDetection.Findings) != 2 {
		t.Fatalf("scan detection missing from PCAP result: %+v", res.ScanDetection)
	}
}

func TestPassiveOSINTOfflineDoesNotResolveDomain(t *testing.T) {
	r, err := NewService().PassiveOSINT("example.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.External || len(r.Addresses) != 0 || r.QueriedAt != "" || r.DataSent != "" {
		t.Fatalf("offline result leaked external work: %+v", r)
	}
}
