package diagnosis

import (
	"trazip/internal/correlation"
	"trazip/internal/model"
)

// ToSnapshot adapts a DiagnosticReport into the shared correlation.Snapshot
// contract (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE E.0 — SNAPSHOT ADAPTER —
// DIAGNOSE") — a pure, exact field mapping, never a reinterpretation of any
// stage and never a recomputed diagnosis. NetworkActions are deliberately
// excluded from Assessment: they document what this run sent off the host,
// not evidence for or against the conclusion, and a future Investigation
// can still reach them through the full DiagnosticReport it stores
// separately if it chooses to.
func ToSnapshot(report DiagnosticReport) correlation.Snapshot {
	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		Subject:       report.Target,
		// CompletedAt over StartedAt: this snapshot represents the
		// finished, correlated conclusion, not the moment the run began —
		// consistent with how a diagnosis is only meaningful once
		// correlate() has actually produced Summary/Level/Confidence.
		OccurredAt: report.CompletedAt,
		Assessment: model.Assessment{
			Conclusion:  report.Summary,
			Level:       report.Level,
			Confidence:  report.Confidence,
			Evidence:    report.Evidence,
			CounterEvid: report.CounterEvid,
			Limitations: report.Limitations,
		},
	}
}
