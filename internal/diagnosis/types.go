// Package diagnosis is TRAZIP V1's correlation layer: it orchestrates the
// existing, mature engines (DNS, ping, traceroute, RDAP, BGP/RPKI, TLS, HTTP,
// reputation, GeoIP/ASN/NetClass) into one evidence-based DiagnosticReport,
// without duplicating what any of them already do (TRAZIP V1 MASTER
// IMPLEMENTATION, "PRINCIPIO CENTRAL V1").
//
// This package never makes a probe of its own kind — every fact it reports
// came from calling one of those engines — and it never asserts a cause the
// underlying facts don't demonstrate: DNS failing is a resolution problem,
// not proof the host is down; an unanswered ping is a missing ICMP reply,
// not proof the service is unreachable; RPKI invalid is a routing-security
// finding, not a declared hijack. See correlate.go for where each of these
// distinctions is actually enforced.
//
// Deliberately backend-only and UI-agnostic: it returns model.Assessment/
// model.Evidence-shaped data (the same central model every other TRAZIP
// judgement uses) so the same DiagnosticReport can drive the GUI today and a
// future CLI without a second implementation.
package diagnosis

import "trazip/internal/model"

// Mode controls how much active/external work DiagnoseTarget is allowed to
// do (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE B — QUICK DIAGNOSE 2.0").
type Mode string

const (
	// ModeOffline performs no deliberate network output at all: only
	// classification, GeoIP/ASN, NetClass and locally-downloaded reputation
	// lists.
	ModeOffline Mode = "offline"
	// ModeStandard adds system DNS, a short bounded ping, a short
	// traceroute, RDAP, BGP/RPKI, TLS and HTTP — no aggressive probing.
	ModeStandard Mode = "standard"
	// ModeFull adds a DNS comparison across well-known resolvers and a
	// deeper traceroute (more hops/probes) on top of everything Standard
	// does. Still a diagnostic operation, never a pentest.
	ModeFull Mode = "full"
)

// StageStatus is one DiagnosticStage's own outcome — deliberately distinct
// from "the underlying engine returned an error": a stage that skipped
// itself in Offline mode, or one whose engine call failed for reasons
// unrelated to the target's health (e.g. no RDAP bootstrap cached yet), must
// never be conflated with "this stage found a network problem" (master
// plan: "'error del motor' no equivale automáticamente a 'problema de
// red'").
type StageStatus string

const (
	StageOK      StageStatus = "ok"
	StageWarning StageStatus = "warning"
	StageProblem StageStatus = "problem"
	StageUnknown StageStatus = "unknown"
	StageSkipped StageStatus = "skipped"
	StageError   StageStatus = "error"
)

// Stage IDs, stable across the API/UI boundary — the frontend switches on
// these, not on Label (which is display text and may be localized).
const (
	StageIDResolution      = "resolution"
	StageIDReachability    = "reachability"
	StageIDRoute           = "route"
	StageIDOwnership       = "ownership"
	StageIDRoutingSecurity = "routing_security"
	StageIDTLS             = "tls"
	StageIDHTTP            = "http"
	StageIDReputation      = "reputation"
)

// DiagnosticStage is one engine's contribution to the report. Every stage
// TRAZIP considers running for a given target/mode gets an entry — even
// Skipped ones — so the UI's "cadena de diagnóstico" can show every step
// that was, or deliberately wasn't, taken.
type DiagnosticStage struct {
	ID      string      `json:"id"`
	Label   string      `json:"label"`
	Status  StageStatus `json:"status"`
	Summary string      `json:"summary"`
	// Subjects is exactly what this stage examined — a hostname, an IP, a
	// CIDR, an ASN, or a URL — declared explicitly rather than left for a
	// reader to assume every stage looked at the same thing (Phase B.1 fix
	// #3). This matters because it usually isn't true: Resolution can return
	// several A/AAAA addresses, but Reachability/Route/Ownership/Routing
	// Security/Reputation only ever probe ONE of them (DiagnosticReport.
	// PrimaryAddress), while TLS/HTTP independently resolve the hostname
	// themselves and may land on a different address the engine doesn't
	// even report back — so this package never claims one. Nil when the
	// stage never ran (Skipped) or had nothing concrete to name.
	Subjects []string `json:"subjects,omitempty"`
	// Evidence is this stage's own facts, in the central model shape —
	// never a bespoke per-engine format (master plan "MODELO COMÚN DE
	// DIAGNÓSTICO": "Reutilizarlo. No crear cinco modelos incompatibles.").
	Evidence []model.Evidence `json:"evidence,omitempty"`
	// Limitations are caveats specific to this stage's own result (e.g. "un
	// solo salto MTR corto, no una ventana sostenida").
	Limitations []string `json:"limitations,omitempty"`
	// NetworkOut is true when this stage sent traffic off the host —
	// deliberately explicit per-stage rather than inferred from Mode, so a
	// stage that degrades to a no-op (e.g. TLS with no host to contact)
	// reports the truth about what it actually did, not what its Mode
	// generally allows (master plan "PRIVACIDAD"). Kept as a convenience
	// bool alongside the structured NetworkActions below — true if and only
	// if NetworkActions is non-empty.
	NetworkOut bool `json:"networkOut"`
	// NetworkActions is the structured disclosure of what CLASSES of
	// external operation this stage initiated (Phase B.1 fix #5, reworded
	// for honesty in Phase B.1.1 fix #2). Deliberately NOT a packet-level
	// or request-level ledger: some stages (ping, traceroute, RDAP, BGP) map
	// cleanly to one entry per call this package itself makes, but ModeFull's
	// WebIntel pipeline is a black box internally — it can resolve several
	// redirect hostnames, dial through net/http's own system-level resolver,
	// and inspect TLS, none of which internal/webintel exposes as separately
	// countable events. So each entry answers "did this KIND of operation
	// happen, on what subject, toward what kind of destination" — never "here
	// is the exhaustive list of every socket/query" for a stage whose
	// underlying engine doesn't expose that. See NetworkAction's own doc
	// comment.
	NetworkActions []NetworkAction `json:"networkActions,omitempty"`
	DurationMs     int64           `json:"durationMs"`
}

// NetworkAction documents one class of external operation a stage initiated
// or reasonably may have executed as part of its work — TRAZIP's structured
// answer to "what left the host, in what form" (Phase B.1 fix #5), extending
// the same disclosure philosophy PassiveOSINT and external.Disclosure
// (rdap/bgp) already use to every stage, not just the ones that happened to
// have that envelope already.
//
// This is honestly scoped, not an exhaustive request-level ledger (Phase
// B.1.1 fix #2): for stages this package calls directly (ping, traceroute,
// RDAP, BGP, a Standard-mode TLS/HTTP call) one entry does correspond to one
// actual call. For ModeFull's WebIntel pipeline, an entry means "this class
// of operation happened as part of the pipeline" — internal/webintel can
// itself perform several DNS lookups (one per redirect hostname) or rely on
// net/http's own system-level resolver during TLS/HTTP, none of which the
// engine surfaces as individually countable events, so this never claims
// "exactly N requests" or "every socket opened" for a stage whose engine
// doesn't expose that. Never carries HTTP bodies, PCAP data, secrets or
// credentials — see DataSent below for what it IS allowed to say.
type NetworkAction struct {
	StageID string `json:"stageId"`
	// Kind is the protocol/mechanism — "dns" | "icmp" | "traceroute" |
	// "rdap" | "bgp" | "tls" | "http".
	Kind string `json:"kind"`
	// Subject is what this class of operation primarily concerned (an IP,
	// hostname, URL, prefix, or ASN) — the same vocabulary as
	// DiagnosticStage.Subjects. For a pipeline that may touch more than one
	// subject internally (e.g. WebIntel following a redirect to a different
	// host), this names the one this package itself knows about — the
	// original target — not a claim that nothing else was touched.
	Subject string `json:"subject"`
	// DestinationClass is WHERE this went, in a category a reader doesn't
	// need protocol knowledge to understand — "system_resolver" |
	// "public_resolver" | "target" | "target_path" | "rir" | "ripestat".
	DestinationClass string `json:"destinationClass"`
	// DataSent is a short, honest description of what was disclosed — e.g.
	// "hostname", "IP pública", "URL/hostname" — never more specific than
	// that: no HTTP response bodies, no PCAP data, no secrets or
	// credentials ever land here.
	DataSent  string `json:"dataSent"`
	QueriedAt string `json:"queriedAt"`
}

// DiagnosticReport is DiagnoseTarget's full result: the global correlated
// conclusion plus every stage's own evidence, reusing model.Assessment's own
// shape for the top-level judgement (master plan's DiagnosticReport sketch).
type DiagnosticReport struct {
	Target string `json:"target"`
	// Kind is "ip" | "host" | "url" — same vocabulary DiagnoseResult (Quick
	// Diagnose 1.0) already used, so the frontend's existing switch survives.
	Kind string `json:"kind"`
	Mode Mode   `json:"mode"`

	// ResolvedAddresses is every address Resolution actually returned (or,
	// for a direct-IP target, that single address) — the FULL set, so the
	// report never implies every stage examined all of them.
	ResolvedAddresses []string `json:"resolvedAddresses,omitempty"`
	// PrimaryAddress is the one address Reachability/Route/Ownership/
	// Routing Security/Reputation actually probed (see DiagnosticStage.
	// Subjects) — explicit and singular on purpose: those stages never
	// probe more than one address per run, and this is which one. Empty
	// when Resolution never produced an address to probe.
	PrimaryAddress string `json:"primaryAddress,omitempty"`

	// Summary/Level/Confidence/Evidence/CounterEvid/Limitations together are
	// this report's own model.Assessment-shaped global conclusion — built by
	// correlate() from every stage's structured facts, never from string
	// matching (master plan "Usar hechos estructurados. NO basarse solo en
	// strings.").
	Summary     string           `json:"summary"`
	Level       model.Level      `json:"level"`
	Confidence  model.Confidence `json:"confidence"`
	Evidence    []model.Evidence `json:"evidence,omitempty"`
	CounterEvid []model.Evidence `json:"counterEvidence,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`

	Stages []DiagnosticStage `json:"stages"`

	// NetworkOut summarizes, across every stage, whether ModeStandard/
	// ModeFull actually sent anything off the host — ModeOffline is always
	// false by construction (no stage it runs ever sets its own
	// NetworkOut).
	NetworkOut bool `json:"networkOut"`
	// NetworkActions is every stage's own NetworkActions, concatenated in
	// report order — the complete, structured disclosure of what this run
	// actually sent off the host (Phase B.1 fix #5). Empty in ModeOffline
	// by the same construction as NetworkOut above.
	NetworkActions []NetworkAction `json:"networkActions,omitempty"`

	StartedAt   string `json:"startedAt"`
	CompletedAt string `json:"completedAt"`
	DurationMs  int64  `json:"durationMs"`
}
