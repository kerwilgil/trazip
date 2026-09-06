package voip

import "trazip/internal/correlation"

// ToSnapshot adapts a Call into the shared correlation.Snapshot contract
// (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE E.0 — SNAPSHOT ADAPTER — VOIP").
// Returns ok=false, without fabricating anything, when the call has no
// Diagnosis yet — a future Investigation decides for itself what, if
// anything, to do with an undiagnosed call; this adapter never invents one
// just to have something to return.
func ToSnapshot(c *Call) (correlation.Snapshot, bool) {
	if c == nil || c.Diagnosis == nil {
		return correlation.Snapshot{}, false
	}

	subject := ""
	if c.From != "" && c.To != "" {
		subject = c.From + " → " + c.To
	} else if c.From != "" {
		subject = c.From
	} else if c.To != "" {
		subject = c.To
	}

	occurredAt := ""
	if len(c.Timeline) > 0 {
		occurredAt = c.Timeline[0].TimeStr
	}

	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceVoIP,
		SourceID:      c.CallID,
		Subject:       subject,
		OccurredAt:    occurredAt,
		// Reuses *c.Diagnosis exactly — voip already builds it as a
		// model.Assessment (see Call.Diagnosis's own doc comment), so this
		// is a straight copy, never a recomputation.
		Assessment: *c.Diagnosis,
	}, true
}
