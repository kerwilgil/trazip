// Package osint tests for the enrichment engine.
package osint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnrichmentEngine_Empty(t *testing.T) {
	e := NewEnrichmentEngine()
	require.Equal(t, 0, e.FindingCount())
	require.Equal(t, 0, e.CorrelationCount())
	require.Equal(t, DefaultMaxFindings, e.MaxFindings())
	require.Equal(t, DefaultMaxCorrelations, e.MaxCorrelations())
	require.Equal(t, DefaultMaxEvidence, e.MaxEvidence())
	require.Len(t, e.Findings(), 0)
	require.Len(t, e.Correlations(), 0)
}

func TestEnrichmentEngine_AddFinding(t *testing.T) {
	e := NewEnrichmentEngine()
	f := Finding{
		ID:            "f1",
		Subject:       "example.com",
		Kind:          FindingKindDomain,
		EvidenceClass: EvidenceObserved,
		ProvenanceRef: "prov-1",
		SourceRefs:    []string{"src-1"},
		Attributes:    map[string]string{"org": "Example"},
		Summary:       "Test finding",
		CreatedAt:     "now",
		UpdatedAt:     "now",
	}
	require.NoError(t, e.AddFinding(f))
	require.Equal(t, 1, e.FindingCount())

	got, ok := e.Finding("f1")
	require.True(t, ok)
	require.Equal(t, f.ID, got.ID)
	require.Equal(t, f.Kind, got.Kind)
	require.Equal(t, f.EvidenceClass, got.EvidenceClass)
	require.Equal(t, f.ProvenanceRef, got.ProvenanceRef)
	require.Equal(t, f.SourceRefs, got.SourceRefs)
	require.Equal(t, f.Attributes, got.Attributes)
	require.Equal(t, f.Summary, got.Summary)
}

func TestEnrichmentEngine_AddFinding_Validates(t *testing.T) {
	e := NewEnrichmentEngine()
	tests := []struct {
		name  string
		f     Finding
		want  string
	}{
		{"missing ID", Finding{Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}, "missing ID"},
		{"missing kind", Finding{ID: "f1", Subject: "example.com", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}, "missing kind"},
		{"invalid evidence class", Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceUnknown, CreatedAt: "now", UpdatedAt: "now"}, "invalid evidence class"},
		{"observed without provenance", Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, CreatedAt: "now", UpdatedAt: "now"}, "OBSERVED requires non-empty ProvenanceRef"},
		{"missing CreatedAt", Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", UpdatedAt: "now"}, "missing CreatedAt"},
		{"missing UpdatedAt", Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}, "missing UpdatedAt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := e.AddFinding(tc.f)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestEnrichmentEngine_AddFinding_IdempotentIfIdentical(t *testing.T) {
	e := NewEnrichmentEngine()
	f := Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}
	require.NoError(t, e.AddFinding(f))
	require.NoError(t, e.AddFinding(f)) // second add identical = no-op
	require.Equal(t, 1, e.FindingCount())
}

func TestEnrichmentEngine_AddFinding_RejectsConflicting(t *testing.T) {
	e := NewEnrichmentEngine()
	f1 := Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}
	f2 := Finding{ID: "f1", Subject: "example.com", Kind: FindingKindDomain, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}
	require.NoError(t, e.AddFinding(f1))
	err := e.AddFinding(f2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "different content")
	require.Equal(t, 1, e.FindingCount())
}

func TestEnrichmentEngine_AddCorrelation(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindDomain, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))

	c := FindingCorrelation{
		ID:            "c1",
		From:          "f1",
		To:            "f2",
		Kind:          "resolves_to",
		Directed:      true,
		EvidenceClass: EvidenceObserved,
		ProvenanceRef: "prov-1",
		Label:         "Resolves",
		CreatedAt:     "now",
	}
	require.NoError(t, e.AddCorrelation(c))
	require.Equal(t, 1, e.CorrelationCount())

	got, ok := e.Correlation("f1", "f2", "resolves_to", "c1")
	require.True(t, ok)
	require.Equal(t, c.ID, got.ID)
	require.Equal(t, c.From, got.From)
	require.Equal(t, c.To, got.To)
	require.Equal(t, c.Kind, got.Kind)
	require.Equal(t, c.Directed, got.Directed)
	require.Equal(t, c.EvidenceClass, got.EvidenceClass)
	require.Equal(t, c.ProvenanceRef, got.ProvenanceRef)
	require.Equal(t, c.Label, got.Label)
}

func TestEnrichmentEngine_AddCorrelation_Validates(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindDomain, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))

	tests := []struct {
		name string
		c    FindingCorrelation
		want string
	}{
		{"missing ID", FindingCorrelation{From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}, "missing ID"},
		{"missing from", FindingCorrelation{ID: "c1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}, "missing from"},
		{"missing to", FindingCorrelation{ID: "c1", From: "f1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}, "missing to"},
		{"missing kind", FindingCorrelation{ID: "c1", From: "f1", To: "f2", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}, "missing kind"},
		{"invalid evidence class", FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceUnknown, CreatedAt: "now"}, "invalid evidence class"},
		{"observed without provenance", FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, CreatedAt: "now"}, "OBSERVED requires non-empty ProvenanceRef"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := e.AddCorrelation(tc.c)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestEnrichmentEngine_AddCorrelation_DuplicateRejected(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindDomain, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now", UpdatedAt: "now"}))
	c := FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov", CreatedAt: "now"}
	require.NoError(t, e.AddCorrelation(c))
	err := e.AddCorrelation(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestEnrichmentEngine_DeterministicOrdering(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f3", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))

	entities := e.Findings()
	require.Len(t, entities, 3)
	require.Equal(t, "f1", entities[0].ID)
	require.Equal(t, "f2", entities[1].ID)
	require.Equal(t, "f3", entities[2].ID)

	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c3", From: "f3", To: "f1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now"}))
	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now"}))
	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c2", From: "f2", To: "f3", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now"}))

	correlations := e.Correlations()
	require.Len(t, correlations, 3)
	require.Equal(t, "f1", correlations[0].From)
	require.Equal(t, "f2", correlations[0].To)
	require.Equal(t, "f2", correlations[1].From)
	require.Equal(t, "f3", correlations[1].To)
	require.Equal(t, "f3", correlations[2].From)
	require.Equal(t, "f1", correlations[2].To)
}

func TestEnrichmentEngine_FindingsBySubject(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindDomain, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f3", Subject: "other.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now", UpdatedAt: "now"}))

	results := e.FindingsBySubject("example.com")
	require.Len(t, results, 2)
	require.Equal(t, "f1", results[0].ID)
	require.Equal(t, "f2", results[1].ID)

	other := e.FindingsBySubject("other.com")
	require.Len(t, other, 1)
	require.Equal(t, "f3", other[0].ID)

	empty := e.FindingsBySubject("nonexistent.com")
	require.Nil(t, empty)
}

func TestEnrichmentEngine_CorrelationsFromTo(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f3", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now", UpdatedAt: "now"}))

	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now"}))
	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c2", From: "f3", To: "f1", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now"}))

	out := e.CorrelationsFrom("f1")
	require.Len(t, out, 1)
	require.Equal(t, "f1", out[0].From)
	require.Equal(t, "f2", out[0].To)

	in := e.CorrelationsTo("f1")
	require.Len(t, in, 1)
	require.Equal(t, "f3", in[0].From)
	require.Equal(t, "f1", in[0].To)
}

func TestEnrichmentEngine_FindingBoundEnforced(t *testing.T) {
	e := NewEnrichmentEngineWithBounds(2, DefaultMaxCorrelations, DefaultMaxEvidence)
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))
	err := e.AddFinding(Finding{ID: "f3", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now", UpdatedAt: "now"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "finding limit reached")
	require.Equal(t, 2, e.FindingCount())
}

func TestEnrichmentEngine_CorrelationBoundEnforced(t *testing.T) {
	e := NewEnrichmentEngineWithBounds(DefaultMaxFindings, 2, DefaultMaxEvidence)
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f3", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now"}))
	require.NoError(t, e.AddCorrelation(FindingCorrelation{ID: "c2", From: "f2", To: "f3", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now"}))
	err := e.AddCorrelation(FindingCorrelation{ID: "c3", From: "f3", To: "f1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3", CreatedAt: "now"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "correlation limit reached")
	require.Equal(t, 2, e.CorrelationCount())
}

func TestEnrichmentEngine_NoMutationThroughRetainedSlices(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", Attributes: map[string]string{"a": "1"}, CreatedAt: "now", UpdatedAt: "now"}))

	f1 := e.Findings()[0]
	f1.Attributes["a"] = "mutated"

	f2 := e.Findings()[0]
	require.Equal(t, "1", f2.Attributes["a"], "original finding should not be mutated")
}

func TestEnrichmentEngine_EvidenceClassBehavior(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))

	// OBSERVED requires provenance ref
	r1 := FindingCorrelation{ID: "r1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov-1", CreatedAt: "now"}
	require.NoError(t, e.AddCorrelation(r1))

	// POSSIBLE_CONTEXT does not require provenance ref
	r2 := FindingCorrelation{ID: "r2", From: "f1", To: "f2", Kind: "k2", EvidenceClass: EvidencePossibleContext, CreatedAt: "now"}
	require.NoError(t, e.AddCorrelation(r2))

	// NOT_PROVEN does not require provenance ref
	r3 := FindingCorrelation{ID: "r3", From: "f1", To: "f2", Kind: "k3", EvidenceClass: EvidenceNotProven, CreatedAt: "now"}
	require.NoError(t, e.AddCorrelation(r3))

	// Verify they remain distinct - no auto-promotion
	all := e.Correlations()
	require.Len(t, all, 3)

	observedCount := 0
	possibleCount := 0
	notProvenCount := 0
	for _, c := range all {
		switch c.EvidenceClass {
		case EvidenceObserved:
			observedCount++
		case EvidencePossibleContext:
			possibleCount++
		case EvidenceNotProven:
			notProvenCount++
		}
	}
	require.Equal(t, 1, observedCount)
	require.Equal(t, 1, possibleCount)
	require.Equal(t, 1, notProvenCount)
}

func TestEnrichmentEngine_EvidenceItems(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))

	// OBSERVED requires provenance ref
	r1 := FindingEvidence{ID: "e1", FindingID: "f1", Type: "dns", Value: "example.com", Source: "rdap", ProvenanceRef: "prov-1", Confidence: "high", Explain: "RDAP record", Timestamp: "now"}
	require.NoError(t, e.AddEvidence(r1))

	// POSSIBLE_CONTEXT does not require provenance ref
	r2 := FindingEvidence{ID: "e2", FindingID: "f1", Type: "dns", Value: "example.org", Source: "passive_dns", EvidenceClass: EvidencePossibleContext, Confidence: "medium", Timestamp: "now"}
	require.NoError(t, e.AddEvidence(r2))

	// NOT_PROVEN does not require provenance ref
	r3 := FindingEvidence{ID: "e3", FindingID: "f1", Type: "dns", Value: "example.net", Source: "guess", EvidenceClass: EvidenceNotProven, Confidence: "low", Timestamp: "now"}
	require.NoError(t, e.AddEvidence(r3))

	// Verify they remain distinct - no auto-promotion
	evidence := e.EvidenceForFinding("f1")
	require.Len(t, evidence, 3)
	// Check evidence classes are preserved
	foundObserved := false
	foundPossible := false
	foundNotProven := false
	for _, e := range evidence {
		switch e.ProvenanceRef {
		case "prov-1":
			foundObserved = true
		case "":
			if e.EvidenceClass == EvidencePossibleContext {
				foundPossible = true
			} else if e.EvidenceClass == EvidenceNotProven {
				foundNotProven = true
			}
		}
	}
	require.True(t, foundObserved)
	require.True(t, foundPossible)
	require.True(t, foundNotProven)
}

func TestEnrichmentEngine_EvidenceClass_RejectsUnknown(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	require.NoError(t, e.AddFinding(Finding{ID: "f2", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2", CreatedAt: "now", UpdatedAt: "now"}))

	r := FindingCorrelation{ID: "r1", From: "f1", To: "f2", Kind: "k", EvidenceClass: EvidenceUnknown, CreatedAt: "now"}
	err := e.AddCorrelation(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid evidence class")
}

func TestEnrichmentEngine_SelfCorrelationAllowed(t *testing.T) {
	e := NewEnrichmentEngine()
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", CreatedAt: "now", UpdatedAt: "now"}))
	c := FindingCorrelation{ID: "c1", From: "f1", To: "f1", Kind: "self_ref", Directed: true, EvidenceClass: EvidenceNotProven, CreatedAt: "now"}
	require.NoError(t, e.AddCorrelation(c)) // Self-edge allowed if explicitly added
	require.Equal(t, 1, e.CorrelationCount())
}

func TestEnrichmentEngine_AttributesDeepCopy(t *testing.T) {
	e := NewEnrichmentEngine()
	attrs := map[string]string{"a": "1"}
	require.NoError(t, e.AddFinding(Finding{ID: "f1", Subject: "example.com", Kind: FindingKindIP, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1", Attributes: attrs, CreatedAt: "now", UpdatedAt: "now"}))

	attrs["a"] = "mutated"

	e2 := e.Findings()[0]
	require.Equal(t, "1", e2.Attributes["a"], "finding attributes should be deep copied")
}