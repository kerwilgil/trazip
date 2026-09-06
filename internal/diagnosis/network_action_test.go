package diagnosis

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestOfflineModeHasZeroNetworkActions is the Phase B.1 fix #5 contract
// test: ModeOffline must guarantee NetworkOut == false AND NetworkActions
// empty, across the whole report and every individual stage — not just the
// convenience bool.
func TestOfflineModeHasZeroNetworkActions(t *testing.T) {
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, "1.1.1.1", ModeOffline)
	if err != nil {
		t.Fatalf("DiagnoseTarget returned error: %v", err)
	}
	if report.NetworkOut {
		t.Error("NetworkOut = true in ModeOffline")
	}
	if len(report.NetworkActions) != 0 {
		t.Errorf("report.NetworkActions = %+v, want empty in ModeOffline", report.NetworkActions)
	}
	for _, s := range report.Stages {
		if len(s.NetworkActions) != 0 {
			t.Errorf("stage %q NetworkActions = %+v, want empty in ModeOffline", s.ID, s.NetworkActions)
		}
	}
}

// TestReachabilityRecordsNetworkActionForLoopback confirms the stage
// actually populates NetworkActions when it decides to probe — using
// loopback (127.0.0.1) rather than a real internet host so this stays fast
// and deterministic without depending on external network reachability
// (unlike the target's actual response, which this test doesn't assert on).
func TestReachabilityRecordsNetworkActionForLoopback(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	// A short deadline is fine here: the assertions only check that
	// NetworkActions was recorded pre-emptively before ping.Run even
	// starts, not that any reply actually arrived — see runReachability.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	s := runReachability(ctx, true, ip, ModeStandard)
	if len(s.NetworkActions) != 1 {
		t.Fatalf("NetworkActions = %+v, want exactly one entry", s.NetworkActions)
	}
	a := s.NetworkActions[0]
	if a.StageID != StageIDReachability || a.Kind != "icmp" || a.Subject != "127.0.0.1" || a.DestinationClass != DestTarget {
		t.Errorf("NetworkAction = %+v, unexpected shape", a)
	}
	if a.QueriedAt == "" {
		t.Error("QueriedAt must never be empty for an action that actually ran")
	}
	if a.DataSent == "" {
		t.Error("DataSent must describe what was disclosed, never be empty")
	}
}

// TestNetActionNeverCarriesLongOrSensitiveData is a structural guard on the
// shared netAction() constructor every stage funnels through: DataSent must
// stay a short category description, never response bodies, PCAP data, or
// anything resembling a credential.
func TestNetActionNeverCarriesLongOrSensitiveData(t *testing.T) {
	samples := []NetworkAction{
		netAction(StageIDResolution, "dns", "example.com", DestSystemResolver, "hostname"),
		netAction(StageIDReachability, "icmp", "1.1.1.1", DestTarget, "IP objetivo + eco ICMP"),
		netAction(StageIDRoute, "traceroute", "1.1.1.1", DestTargetPath, "IP objetivo + sondas"),
		netAction(StageIDOwnership, "rdap", "1.1.1.1", DestRIR, "IP pública"),
		netAction(StageIDRoutingSecurity, "bgp", "1.1.1.0/24 AS13335", DestRIPEstat, "prefijo/ASN"),
		netAction(StageIDTLS, "tls", "example.com", DestTarget, "hostname/SNI"),
		netAction(StageIDHTTP, "http", "https://example.com/", DestTarget, "URL/hostname"),
	}
	for _, a := range samples {
		if len(a.DataSent) > 80 {
			t.Errorf("DataSent looks too long to be a short disclosure category: %q", a.DataSent)
		}
	}
}

// TestAggregateNetworkDisclosureFlattensStages confirms
// DiagnosticReport.NetworkActions is the flattened union of every stage's
// own list (and NetworkOut is true iff any stage's own is) — driven with
// hand-built stages, deterministic, no live network.
func TestAggregateNetworkDisclosureFlattensStages(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, NetworkOut: true, NetworkActions: []NetworkAction{netAction(StageIDResolution, "dns", "example.com", DestSystemResolver, "hostname")}},
		{ID: StageIDReachability, NetworkOut: true, NetworkActions: []NetworkAction{netAction(StageIDReachability, "icmp", "1.1.1.1", DestTarget, "IP objetivo + eco ICMP")}},
		{ID: StageIDReputation}, // offline-only, no network action
	}
	networkOut, actions := aggregateNetworkDisclosure(stages)
	if !networkOut {
		t.Error("NetworkOut should be true when at least one stage's own is")
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want exactly 2 (one per stage that actually sent something)", actions)
	}
}

// TestAggregateNetworkDisclosureAllSkippedIsEmpty is the ModeOffline shape:
// every stage skipped, nothing aggregated.
func TestAggregateNetworkDisclosureAllSkippedIsEmpty(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageSkipped},
		{ID: StageIDReachability, Status: StageSkipped},
	}
	networkOut, actions := aggregateNetworkDisclosure(stages)
	if networkOut || len(actions) != 0 {
		t.Errorf("networkOut=%v actions=%+v, want false/empty when nothing ran", networkOut, actions)
	}
}
