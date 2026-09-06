package api

import (
	"context"
	"strings"

	"trazip/internal/diagnosis"
)

// RunDiagnose is TRAZIP V1's correlated diagnosis pipeline (Diagnose 2.0)
// for a target that may be an IP, hostname, or URL — the coordinated
// replacement for QuickDiagnose's DNS-only resolution, now correlating DNS,
// reachability, route, ownership, routing security, TLS, HTTP and
// reputation into one evidence-based conclusion (TRAZIP V1 MASTER
// IMPLEMENTATION, "PHASE B — QUICK DIAGNOSE 2.0").
//
// Deliberately NOT a *Service method: Standard/Full modes send active
// probes (ping, traceroute, RDAP, BGP, TLS, HTTP) off the host, and TRAZIP's
// scope/authorization model requires those to go through
// session.Manager.BeginActive — the same gate StartPing/StartTrace/StartMTR
// already enforce — never bypassable via a plain, uncancellable Wails
// binding that skips it entirely. A *Service method here would have been
// exactly that bypass (caught in Phase B.1 review: Service.DiagnoseTarget
// used to exist and let JS run Standard/Full with context.Background(),
// no scope declared, no way to cancel). App.StartDiagnose (package main) is
// the ONLY entry point the GUI uses; this stays a package-level function
// purely so that cancellable path — and any future CLI built the same way
// — can share one implementation (same reasoning as RunVoIPAnalysis's own
// doc comment).
func RunDiagnose(ctx context.Context, input, mode string, s *Service) (diagnosis.DiagnosticReport, error) {
	m := diagnosis.Mode(strings.TrimSpace(mode))
	switch m {
	case diagnosis.ModeOffline, diagnosis.ModeStandard, diagnosis.ModeFull:
	default:
		m = diagnosis.ModeStandard
	}
	deps := diagnosis.Dependencies{
		Geo:        s.geo,
		NetClass:   s.netClass,
		RDAP:       s.rdapClient,
		BGP:        s.bgpClient,
		ThreatFeed: s.threatFeed,
	}
	return diagnosis.DiagnoseTarget(ctx, deps, input, m)
}
