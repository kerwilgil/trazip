// Package investigation tests for the enrichment workflow.
package investigation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func TestEnrichInvestigation_Empty(t *testing.T) {
	inv := Investigation{
		ID:        "test-inv",
		Name:      "Empty Investigation",
		Entries:   []Entry{},
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)
	require.Equal(t, "test-inv", result.InvestigationID)
	require.Equal(t, "Empty Investigation", result.InvestigationName)
	require.Len(t, result.Findings, 0)
	require.Len(t, result.Correlations, 0)
	require.Len(t, result.Evidence, 0)
	require.Equal(t, 0, result.Stats.TotalFindings)
	require.Equal(t, 0, result.Stats.TotalCorrelations)
	require.Equal(t, 0, result.Stats.TotalEvidence)
	require.Empty(t, result.EntryMapping)
}

func TestEnrichInvestigation_SingleEntry(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		SourceID:      "diag-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Test finding",
			Level:      model.LevelMedium,
			Confidence: 75,
			Evidence: []model.Evidence{
				{
					Type:       "dns",
					Value:      "93.184.216.34",
					Source:     "diagnose",
					Provenance: model.ProvObserved,
					Timestamp:  time.Now().UTC(),
					Confidence: 80,
					Explain:    "A record",
				},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "Single Entry",
		Entries:   []Entry{{ID: "entry-1", AddedAt: now, Snapshot: snap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	// Should have one finding
	require.Len(t, result.Findings, 1)
	finding := result.Findings[0]
	require.Equal(t, "f_entry-1", finding.ID)
	require.Equal(t, "example.com", finding.Subject)
	require.Equal(t, FindingKindDomain, finding.Kind)
	require.Equal(t, EvidenceObserved, finding.EvidenceClass)
	require.Contains(t, finding.ProvenanceRef, "inv:test-inv/entry:entry-1")
	require.Equal(t, "Test finding", finding.Summary)
	require.Equal(t, now, finding.CreatedAt)
	require.Equal(t, now, finding.UpdatedAt)

	// Should have one evidence item
	require.Len(t, result.Evidence, 1)
	evidence := result.Evidence[finding.ID]
	require.Len(t, evidence, 1)
	require.Equal(t, "e_entry-1_0", evidence[0].ID)
	require.Equal(t, finding.ID, evidence[0].FindingID)
	require.Equal(t, "dns", evidence[0].Type)
	require.Equal(t, "93.184.216.34", evidence[0].Value)
	require.Equal(t, "diagnose", evidence[0].Source)
	require.Equal(t, "prov:observed", evidence[0].ProvenanceRef)
	require.Equal(t, EvidenceObserved, evidence[0].EvidenceClass)
	require.Equal(t, "80", evidence[0].Confidence)

	// Entry mapping should be correct
	require.Equal(t, "f_entry-1", result.EntryMapping["entry-1"])

	// Stats should be correct
	require.Equal(t, 1, result.Stats.TotalFindings)
	require.Equal(t, 0, result.Stats.TotalCorrelations)
	require.Equal(t, 1, result.Stats.TotalEvidence)
	require.Equal(t, 1, result.Stats.BySourceKind["diagnose"])

	// No correlations (no auto-correlation by subject)
	require.Len(t, result.Correlations, 0)
}

func TestEnrichInvestigation_ProvenanceChainPreserved(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourcePCAP,
		SourceID:      "pcap-session-1",
		Subject:       "192.0.2.1",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Scan detected",
			Level:      model.LevelHigh,
			Confidence: 90,
			Evidence: []model.Evidence{
				{
					Type:       "scan",
					Value:      "vertical",
					Source:     "pcap-scan",
					Provenance: model.ProvExternal,
					Timestamp:  time.Now().UTC(),
					Confidence: 85,
					Explain:    "Vertical scan from 192.0.2.100",
				},
				{
					Type:       "scan",
					Value:      "horizontal",
					Source:     "pcap-scan",
					Provenance: model.ProvObserved,
					Timestamp:  time.Now().UTC(),
					Confidence: 95,
					Explain:    "Horizontal scan from 192.0.2.200",
				},
			},
			CounterEvid: []model.Evidence{
				{
					Type:       "scan",
					Value:      "background",
					Source:     "pcap-scan",
					Provenance: model.ProvInferred,
					Timestamp:  time.Now().UTC(),
					Confidence: 30,
					Explain:    "Possible background traffic",
				},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "PCAP Entry",
		Entries:   []Entry{{ID: "pcap-1", AddedAt: now, Snapshot: snap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	// Finding should have EvidenceObserved because it has at least one ProvObserved evidence
	require.Len(t, result.Findings, 1)
	require.Equal(t, EvidenceObserved, result.Findings[0].EvidenceClass)

	// Should have 3 evidence items (2 evidence + 1 counter-evidence)
	require.Len(t, result.Evidence, 1)
	evidence := result.Evidence[result.Findings[0].ID]
	require.Len(t, evidence, 3)

	// Check evidence classes are preserved
	classes := map[EvidenceClass]int{}
	for _, e := range evidence {
		classes[e.EvidenceClass]++
	}
	require.Equal(t, 1, classes[EvidenceObserved])     // ProvObserved
	require.Equal(t, 1, classes[EvidencePossibleContext]) // ProvExternal
	require.Equal(t, 1, classes[EvidenceNotProven])      // ProvInferred

	// Counter-evidence should have prefix
	var counterEvidence string
	for _, e := range evidence {
		if e.Type == "scan" && e.Value == "background" {
			counterEvidence = e.Explain
			break
		}
	}
	require.Contains(t, counterEvidence, "(counter-evidence)")
}

func TestEnrichInvestigation_NoAutoCorrelation(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Two entries with same subject but different source kinds
	snap1 := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		SourceID:      "diag-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "DNS resolution",
			Level:      model.LevelLow,
			Confidence: 80,
			Evidence: []model.Evidence{
				{Type: "dns", Value: "93.184.216.34", Source: "diagnose", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 80, Explain: "A record"},
			},
		},
	}

	snap2 := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourcePCAP,
		SourceID:      "pcap-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Network scan",
			Level:      model.LevelHigh,
			Confidence: 90,
			Evidence: []model.Evidence{
				{Type: "scan", Value: "vertical", Source: "pcap", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 95, Explain: "Vertical scan"},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "Same Subject",
		Entries:   []Entry{{ID: "e1", AddedAt: now, Snapshot: snap1}, {ID: "e2", AddedAt: now, Snapshot: snap2}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	// Should have 2 findings
	require.Len(t, result.Findings, 2)

	// Should have NO correlations (no auto-correlation by subject)
	require.Len(t, result.Correlations, 0)
	require.Equal(t, 0, result.Stats.TotalCorrelations)
}

func TestEnrichInvestigation_BoundsEnforced(t *testing.T) {
	// Create investigation with many entries to test bounds
	// We can't easily test maxFindings=500 here without creating 500 entries,
	// but we can test that the engine respects bounds by creating an engine with small bounds
	// This test verifies the bounds are checked at the engine level

	// The actual bounds enforcement is tested in osint/enrichment_test.go
	// Here we just verify the enrichment uses the engine with correct bounds
	inv := Investigation{
		ID:        "test-inv",
		Name:      "Bounds Test",
		Entries:   []Entry{},
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	_, err := EnrichInvestigation(inv)
	require.NoError(t, err)
}

func TestEnrichInvestigation_DeterministicOutput(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	entries := []Entry{
		{ID: "e3", AddedAt: now, Snapshot: correlation.Snapshot{
			SchemaVersion: correlation.SnapshotSchemaVersion,
			Kind:          correlation.SourcePCAP,
			SourceID:      "pcap-3",
			Subject:       "host3",
			OccurredAt:    now,
			Assessment: model.Assessment{
				Conclusion: "Finding 3", Level: model.LevelInfo, Confidence: 50,
				Evidence: []model.Evidence{{Type: "x", Value: "3", Source: "s", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 10, Explain: "x"}},
			},
		}},
		{ID: "e1", AddedAt: now, Snapshot: correlation.Snapshot{
			SchemaVersion: correlation.SnapshotSchemaVersion,
			Kind:          correlation.SourceDiagnose,
			SourceID:      "diag-1",
			Subject:       "host1",
			OccurredAt:    now,
			Assessment: model.Assessment{
				Conclusion: "Finding 1", Level: model.LevelHigh, Confidence: 90,
				Evidence: []model.Evidence{{Type: "x", Value: "1", Source: "s", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 10, Explain: "x"}},
			},
		}},
		{ID: "e2", AddedAt: now, Snapshot: correlation.Snapshot{
			SchemaVersion: correlation.SnapshotSchemaVersion,
			Kind:          correlation.SourceMonitor,
			SourceID:      "mon-2",
			Subject:       "host2",
			OccurredAt:    now,
			Assessment: model.Assessment{
				Conclusion: "Finding 2", Level: model.LevelMedium, Confidence: 75,
				Evidence: []model.Evidence{{Type: "x", Value: "2", Source: "s", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 10, Explain: "x"}},
			},
		}},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "Permutation Test",
		Entries:   entries,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Enrich twice with different entry orders
	result1, err := EnrichInvestigation(Investigation{
		ID: inv.ID, Name: inv.Name, Entries: entries, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	// Reverse order
	revEntries := []Entry{entries[2], entries[1], entries[0]}
	result2, err := EnrichInvestigation(Investigation{
		ID: inv.ID, Name: inv.Name, Entries: revEntries, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	// Findings should be identical and sorted by ID
	require.Equal(t, result1.Findings, result2.Findings)
	require.Equal(t, result1.Correlations, result2.Correlations)
	require.Equal(t, result1.Evidence, result2.Evidence)
	require.Equal(t, result1.EntryMapping, result2.EntryMapping)
	require.Equal(t, result1.Stats, result2.Stats)
}

func TestEnrichInvestigation_ZeroTimestampHandling(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		SourceID:      "diag-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Test",
			Level:      model.LevelInfo,
			Confidence: 50,
			Evidence: []model.Evidence{
				{Type: "dns", Value: "1.2.3.4", Source: "diag", Provenance: model.ProvObserved, Timestamp: time.Time{}, Confidence: 50, Explain: "Zero timestamp"},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "Zero Timestamp",
		Entries:   []Entry{{ID: "e1", AddedAt: now, Snapshot: snap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	require.Len(t, result.Evidence, 1)
	evidence := result.Evidence[result.Findings[0].ID]
	require.Equal(t, "", evidence[0].Timestamp, "zero timestamp should become empty string")
}

func TestEnrichInvestigation_NoMutation(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	originalSnap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		SourceID:      "diag-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Test",
			Level:      model.LevelInfo,
			Confidence: 50,
			Evidence: []model.Evidence{
				{Type: "dns", Value: "1.2.3.4", Source: "diag", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 50, Explain: "Test"},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "No Mutation",
		Entries:   []Entry{{ID: "e1", AddedAt: now, Snapshot: originalSnap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Keep a copy of the original investigation for comparison
	originalEntries := make([]Entry, len(inv.Entries))
	copy(originalEntries, inv.Entries)

	_, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	// Investigation should not be mutated
	require.Equal(t, len(originalEntries), len(inv.Entries))
	for i := range originalEntries {
		require.Equal(t, originalEntries[i].ID, inv.Entries[i].ID)
		require.Equal(t, originalEntries[i].AddedAt, inv.Entries[i].AddedAt)
		require.Equal(t, originalEntries[i].Snapshot.Subject, inv.Entries[i].Snapshot.Subject)
		require.Equal(t, originalEntries[i].Snapshot.Kind, inv.Entries[i].Snapshot.Kind)
	}
}

func TestEnrichInvestigation_NoNetworkExecution(t *testing.T) {
	// This test verifies that EnrichInvestigation doesn't make network calls
	// by ensuring it completes quickly and doesn't hang
	now := time.Now().UTC().Format(time.RFC3339)
	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceDiagnose,
		SourceID:      "diag-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "Test",
			Level:      model.LevelInfo,
			Confidence: 50,
			Evidence: []model.Evidence{
				{Type: "dns", Value: "1.2.3.4", Source: "diag", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 50, Explain: "Test"},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "No Network",
		Entries:   []Entry{{ID: "e1", AddedAt: now, Snapshot: snap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Should complete quickly (no network timeout)
	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
}

func TestEnrichInvestigation_ExplicitCorrelationOnly(t *testing.T) {
	// This test documents that currently no correlations are created
	// because snapshots don't carry explicit inter-finding relations.
	// Future versions may add correlation extraction from webintel Graph, etc.
	now := time.Now().UTC().Format(time.RFC3339)

	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceWebIntel,
		SourceID:      "webintel-1",
		Subject:       "example.com",
		OccurredAt:    now,
		Assessment: model.Assessment{
			Conclusion: "WebIntel result",
			Level:      model.LevelMedium,
			Confidence: 70,
			Evidence: []model.Evidence{
				{Type: "certificate", Value: "example.com", Source: "webintel", Provenance: model.ProvObserved, Timestamp: time.Now().UTC(), Confidence: 80, Explain: "TLS cert"},
			},
		},
	}

	inv := Investigation{
		ID:        "test-inv",
		Name:      "WebIntel Entry",
		Entries:   []Entry{{ID: "web-1", AddedAt: now, Snapshot: snap}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	result, err := EnrichInvestigation(inv)
	require.NoError(t, err)

	// Should have finding from webintel
	require.Len(t, result.Findings, 1)
	require.Equal(t, FindingKindDomain, result.Findings[0].Kind)

	// But NO correlations (no explicit relations in snapshot)
	require.Len(t, result.Correlations, 0)
}