// Package correlation is TRAZIP V1's shared leaf contract for cross-module
// correlated results (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE E.0 — SHARED
// CORRELATED RESULT CONTRACT"). Diagnose, PCAP, Monitor and VoIP each own
// their own rich, module-specific result types — this package never
// duplicates or re-derives them — but a future Investigation workspace
// needs one small, normalized shape it can hold a list of, without
// importing any of those modules directly.
//
// Leaf by construction: this package may only import the standard library
// and internal/model. It must never import internal/api, internal/
// diagnosis, internal/monitor, internal/voip, internal/report,
// internal/session, or internal/investigation — every one of those may
// import correlation, never the other way around (see deps_test.go, which
// enforces this structurally rather than just by comment). This is what
// lets internal/api's PCAP types live here (Investigation needs them
// without depending on internal/api) while internal/diagnosis/internal/
// monitor/internal/voip's own richer types stay exactly where they are,
// each contributing a small adapter that maps its own result onto a
// Snapshot.
package correlation

import "trazip/internal/model"

// SourceKind identifies which TRAZIP module produced a Snapshot.
type SourceKind string

const (
	SourceDiagnose        SourceKind = "diagnose"
	SourcePCAP            SourceKind = "pcap"
	SourceMonitor         SourceKind = "monitor"
	SourceVoIP            SourceKind = "voip"
	SourceWebIntel        SourceKind = "webintel"
	SourceBGPIntelligence SourceKind = "bgp_intelligence"
)

// SnapshotSchemaVersion is Snapshot's own JSON schema version — bumped only
// when Snapshot's shape changes in a way a persisted/serialized value from
// an earlier version would need to migrate for.
const SnapshotSchemaVersion = 1

// Snapshot is one module's correlated result, normalized to a size and
// shape a future Investigation timeline can hold many of without becoming
// a blob store. Deliberately small and deliberately NOT yet the full
// InvestigationEntry Phase E will define — this is only the normalized
// unit that entry will wrap.
//
// Principios obligatorios (Phase E.0):
//   - reuses model.Assessment — never a second, incompatible Evidence/
//     Confidence/Level shape;
//   - never stores UI state (a tab name, a selected row, a scroll
//     position);
//   - never stores a local file path automatically — a caller that wants
//     one must pass it explicitly as SourceID/Subject;
//   - never stores PCAP bytes, HTTP bodies, or secrets/credentials;
//   - never embeds another module's full result (no DiagnosticReport, no
//     PcapResult, no voip.Call, no monitor.History) — that's deliberately
//     deferred; see each adapter's own doc comment for why.
type Snapshot struct {
	SchemaVersion int        `json:"schemaVersion"`
	Kind          SourceKind `json:"kind"`

	// SourceID identifies the specific object this snapshot came from
	// within its module (a RouteChange.ID, a voip Call.CallID) — never a
	// filesystem path, never PII beyond what the source module itself
	// already exposes. Empty when the source has no natural stable ID.
	SourceID string `json:"sourceId,omitempty"`
	// Subject is what this snapshot is about, in human terms — a target
	// hostname/IP, a "from → to" call pair. Never fabricated when the
	// source data doesn't have one to offer.
	Subject string `json:"subject,omitempty"`

	// OccurredAt is RFC3339, matching every other timestamp string in
	// TRAZIP's persisted models (monitor.Sample.Time, DegradationEvent.
	// Time, RouteChange.DetectedAt) — never time.Time, so this stays a
	// plain, directly-comparable/serializable string like the rest.
	OccurredAt string `json:"occurredAt,omitempty"`

	Assessment model.Assessment `json:"assessment"`
}
