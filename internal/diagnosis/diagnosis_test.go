package diagnosis

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// TestDiagnoseTargetOfflineDirectIP drives the full pipeline end to end —
// deterministic and network-free (ModeOffline, direct IP: only Reputation's
// offline scorer touches the address, and that's a local computation, never
// a probe) — so it is safe under `go test -count=20`.
func TestDiagnoseTargetOfflineDirectIP(t *testing.T) {
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, "1.1.1.1", ModeOffline)
	if err != nil {
		t.Fatalf("DiagnoseTarget returned error: %v", err)
	}
	if report.Kind != "ip" {
		t.Errorf("Kind = %q, want ip", report.Kind)
	}
	if report.NetworkOut {
		t.Error("NetworkOut = true in ModeOffline — offline mode must never touch the network")
	}
	if len(report.Stages) != 8 {
		t.Fatalf("got %d stages, want 8 (one entry per stage, even skipped ones)", len(report.Stages))
	}
	for _, s := range report.Stages {
		if s.NetworkOut {
			t.Errorf("stage %q reported NetworkOut in ModeOffline", s.ID)
		}
	}
	resolution := report.Stages[0]
	if resolution.ID != StageIDResolution || resolution.Status != StageOK {
		t.Errorf("first stage = %+v, want Resolution/OK for a direct IP target even offline", resolution)
	}
}

func TestDiagnoseTargetEmptyInput(t *testing.T) {
	_, err := DiagnoseTarget(context.Background(), Dependencies{}, "   ", ModeOffline)
	if err == nil {
		t.Error("expected an error for empty input")
	}
}

// V1 hardening finding #1 (privacy): a URL with embedded userinfo must be
// rejected fail-closed, before any stage runs, and the credential must
// never surface anywhere in the error or the returned report.

// A. Credentialed URL is rejected, and the password never appears in the error.
func TestDiagnoseTargetRejectsURLCredentials(t *testing.T) {
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, "https://alice:s3cr3t@example.com/private", ModeOffline)
	if err == nil {
		t.Fatal("expected an error for a URL with embedded credentials")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error leaks the password: %q", err.Error())
	}
	if strings.Contains(err.Error(), "alice") {
		t.Errorf("error leaks the username: %q", err.Error())
	}
	body, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}
	if strings.Contains(string(body), "s3cr3t") {
		t.Errorf("serialized report leaks the password: %s", body)
	}
	if report.Target != "" {
		t.Errorf("report.Target = %q, want cleared on rejection", report.Target)
	}
}

// B. The rejection happens before any stage runs / any network output —
// checked under ModeStandard (which would otherwise dispatch DNS/ping/
// TLS/HTTP/RDAP/BGP) to prove this isn't just an artifact of ModeOffline.
func TestDiagnoseTargetRejectsURLCredentialsBeforeNetworkOutput(t *testing.T) {
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, "https://alice:s3cr3t@example.com/private", ModeStandard)
	if err == nil {
		t.Fatal("expected an error for a URL with embedded credentials")
	}
	if len(report.Stages) != 0 {
		t.Errorf("Stages = %d, want 0 — no stage should ever have run", len(report.Stages))
	}
	if report.NetworkOut {
		t.Error("NetworkOut = true — rejection must happen before any network output")
	}
	if len(report.NetworkActions) != 0 {
		t.Errorf("NetworkActions = %v, want empty", report.NetworkActions)
	}
}

// C. A normal URL with no userinfo is unaffected.
func TestDiagnoseTargetNormalURLStillAccepted(t *testing.T) {
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, "https://example.com/path", ModeOffline)
	if err != nil {
		t.Fatalf("DiagnoseTarget: %v", err)
	}
	if report.Kind != "url" {
		t.Errorf("Kind = %q, want url", report.Kind)
	}
	if report.Target != "https://example.com/path" {
		t.Errorf("Target = %q, want the original URL preserved", report.Target)
	}
}

func TestHasURLUserinfo(t *testing.T) {
	cases := map[string]bool{
		"https://alice:s3cr3t@example.com/private": true,
		"https://alice@example.com/private":        true,
		// Malformed later in the URL (an invalid percent-escape in the
		// path) must NOT be read as "no credentials here" — the
		// credential-bearing authority is well-formed even though
		// net/url.Parse itself would fail on the rest of the string (V1
		// URL-privacy micro-hardening: fail closed, not merely when
		// net/url happens to accept the whole input).
		"https://alice:s3cr3t@example.com/%ZZ": true,
		// Surrounding whitespace must not defeat detection.
		"  https://alice:s3cr3t@example.com/path  ": true,
		// A bare "@" with no username is still userinfo-shaped.
		"https://@example.com/path": true,
		"https://example.com/path":  false,
		// "@" appearing only in the path or query, after the authority,
		// is not userinfo and must never be misread as such.
		"https://example.com/user@domain":    false,
		"https://example.com/?email=a@b.com": false,
		"example.com":                        false,
		"":                                   false,
		"not a url at all":                   false,
	}
	for input, want := range cases {
		if got := HasURLUserinfo(input); got != want {
			t.Errorf("HasURLUserinfo(%q) = %v, want %v", input, got, want)
		}
	}
}

// V1 URL-privacy micro-hardening: a URL whose authority is credential-
// shaped but whose REST is malformed (an invalid percent-escape in the
// path) used to slip past the old HasURLUserinfo, because it only trusted
// url.Parse succeeding. These pin down the fail-closed fix.

// A. Malformed credential URL under ModeStandard: rejected before any
// stage/network work, and the credential never surfaces anywhere.
func TestDiagnoseTargetRejectsMalformedCredentialURL(t *testing.T) {
	const input = "https://alice:s3cr3t@example.com/%ZZ"
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, input, ModeStandard)
	if err == nil {
		t.Fatal("expected an error for a malformed URL with embedded credentials")
	}
	if report.Target != "" {
		t.Errorf("report.Target = %q, want cleared on rejection", report.Target)
	}
	if len(report.Stages) != 0 {
		t.Errorf("Stages = %d, want 0 — no stage should ever have run", len(report.Stages))
	}
	if report.NetworkOut {
		t.Error("NetworkOut = true — rejection must happen before any network output")
	}
	if len(report.NetworkActions) != 0 {
		t.Errorf("NetworkActions = %v, want empty", report.NetworkActions)
	}
	for _, secret := range []string{"alice", "s3cr3t"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks %q: %q", secret, err.Error())
		}
	}
	body, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}
	for _, secret := range []string{"alice", "s3cr3t"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("serialized report leaks %q: %s", secret, body)
		}
	}
}

// B. Same malformed credential URL under ModeOffline: also rejected — never
// silently proceeds as if it were an ordinary target (Stages stays empty,
// no Resolution ever runs against the raw credential-bearing string as a
// literal hostname).
func TestDiagnoseTargetRejectsMalformedCredentialURLOffline(t *testing.T) {
	const input = "https://alice:s3cr3t@example.com/%ZZ"
	report, err := DiagnoseTarget(context.Background(), Dependencies{}, input, ModeOffline)
	if err == nil {
		t.Fatal("expected an error for a malformed URL with embedded credentials in ModeOffline")
	}
	if report.Target != "" {
		t.Errorf("report.Target = %q, want cleared on rejection", report.Target)
	}
	if len(report.Stages) != 0 {
		t.Errorf("Stages = %d, want 0 — must not silently fall through and resolve the credential-bearing string as a host", len(report.Stages))
	}
}

func TestDiagnoseTargetRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// ModeOffline never blocks on I/O, but this still exercises that a
	// pre-cancelled context doesn't panic or hang the pipeline.
	report, err := DiagnoseTarget(ctx, Dependencies{}, "1.1.1.1", ModeOffline)
	if err != nil {
		t.Fatalf("DiagnoseTarget with a cancelled context returned error: %v", err)
	}
	if report.Kind != "ip" {
		t.Errorf("Kind = %q, want ip", report.Kind)
	}
}

// --- Stage-level tests restricted to fully deterministic, network-free
// branches (Offline mode / no IP / nil dependencies) — anything that
// actually dials out belongs to manual smoke testing, not an automated
// suite meant to run under -count=20 without a live network. ---

func TestRunResolutionOfflineHostSkips(t *testing.T) {
	s, addrs := runResolution(context.Background(), resolvedTarget{kind: "host", host: "example.com"}, ModeOffline)
	if s.Status != StageSkipped || addrs != nil {
		t.Errorf("runResolution offline = %+v, addrs=%v; want Skipped/nil", s, addrs)
	}
	if s.NetworkOut {
		t.Error("Resolution must not report NetworkOut when it skipped itself offline")
	}
}

func TestRunReachabilityNoIPSkips(t *testing.T) {
	s := runReachability(context.Background(), false, netip.Addr{}, ModeStandard)
	if s.Status != StageSkipped {
		t.Errorf("Status = %q, want skipped without an IP", s.Status)
	}
}

func TestRunReachabilityOfflineSkips(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	s := runReachability(context.Background(), true, ip, ModeOffline)
	if s.Status != StageSkipped || s.NetworkOut {
		t.Errorf("runReachability offline = %+v, want Skipped with no network output", s)
	}
}

func TestRunRouteOfflineSkips(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	s := runRoute(context.Background(), true, ip, ModeOffline)
	if s.Status != StageSkipped || s.NetworkOut {
		t.Errorf("runRoute offline = %+v, want Skipped with no network output", s)
	}
}

func TestRunWebPairOfflineSkipsBoth(t *testing.T) {
	tlsStage, httpStage := runWebPair(context.Background(), Dependencies{}, resolvedTarget{kind: "host", host: "example.com"}, ModeOffline)
	if tlsStage.Status != StageSkipped || tlsStage.NetworkOut {
		t.Errorf("TLS offline = %+v, want Skipped with no network output", tlsStage)
	}
	if httpStage.Status != StageSkipped || httpStage.NetworkOut {
		t.Errorf("HTTP offline = %+v, want Skipped with no network output", httpStage)
	}
}

func TestRunTLSDirectIPSkips(t *testing.T) {
	s := runTLS(context.Background(), resolvedTarget{kind: "ip", host: "1.1.1.1", isDirect: true})
	if s.Status != StageSkipped {
		t.Errorf("Status = %q, want skipped for a direct-IP target (no SNI to test)", s.Status)
	}
}

func TestRunRoutingSecurityOfflineSkips(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	s := runRoutingSecurity(context.Background(), Dependencies{}, true, ip, ModeOffline)
	if s.Status != StageSkipped || s.NetworkOut {
		t.Errorf("runRoutingSecurity offline = %+v, want Skipped with no network output", s)
	}
}

func TestRunRoutingSecurityPrivateAddrSkips(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	s := runRoutingSecurity(context.Background(), Dependencies{}, true, ip, ModeStandard)
	if s.Status != StageSkipped {
		t.Errorf("Status = %q, want skipped for a private address", s.Status)
	}
}

func TestRunOwnershipNoIPSkips(t *testing.T) {
	s := runOwnership(context.Background(), Dependencies{}, false, netip.Addr{}, ModeStandard)
	if s.Status != StageSkipped {
		t.Errorf("Status = %q, want skipped without an IP", s.Status)
	}
}

func TestRunOwnershipOfflineNoRDAPQuery(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	s := runOwnership(context.Background(), Dependencies{}, true, ip, ModeOffline)
	if s.NetworkOut {
		t.Error("Ownership must not touch the network in ModeOffline")
	}
	if len(s.Limitations) == 0 {
		t.Error("expected a limitation noting RDAP was not queried offline")
	}
}

// runReputation is offline-only by construction (reputation.AssessOffline +
// locally-downloaded threat lists) — safe to test in every Mode.
func TestRunReputationCleanAddrIsOK(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	s := runReputation(Dependencies{}, true, ip)
	if s.NetworkOut {
		t.Error("Reputation must never report NetworkOut — it is offline-only by design")
	}
	if s.Status != StageOK {
		t.Errorf("Status = %q for a clean public address with no threat feed loaded, want ok", s.Status)
	}
}

func TestRunReputationNoIPSkips(t *testing.T) {
	s := runReputation(Dependencies{}, false, netip.Addr{})
	if s.Status != StageSkipped {
		t.Errorf("Status = %q, want skipped without an IP", s.Status)
	}
}

func TestRunReputationPrivateAddrUnknown(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	s := runReputation(Dependencies{}, true, ip)
	if s.Status != StageUnknown {
		t.Errorf("Status = %q, want unknown for a private address (reputation doesn't apply)", s.Status)
	}
}
