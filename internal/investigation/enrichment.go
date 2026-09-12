// Package investigation provides enrichment integration for Investigation workspace.
// This file connects Investigation entries to the OSINT EnrichmentEngine (V1.5-5)
// without re-executing any providers or making network calls.
package investigation

import (
	"fmt"
	"sort"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/model"
	"trazip/internal/osint"
)

// Type aliases for osint enrichment types — exposed for API layer
// without making investigation depend on osint in its public API surface.
type (
	Finding            = osint.Finding
	FindingEvidence    = osint.FindingEvidence
	FindingCorrelation = osint.FindingCorrelation
	EvidenceClass      = osint.EvidenceClass
)

const (
	EvidenceUnknown       = osint.EvidenceUnknown
	EvidenceObserved      = osint.EvidenceObserved
	EvidencePossibleContext = osint.EvidencePossibleContext
	EvidenceNotProven     = osint.EvidenceNotProven
)

type FindingKind = osint.FindingKind

const (
	FindingKindUnknown     = osint.FindingKindUnknown
	FindingKindIP          = osint.FindingKindIP
	FindingKindDomain      = osint.FindingKindDomain
	FindingKindASN         = osint.FindingKindASN
	FindingKindCertificate = osint.FindingKindCertificate
	FindingKindCVE         = osint.FindingKindCVE
	FindingKindOrganization = osint.FindingKindOrganization
	FindingKindURL         = osint.FindingKindURL
	FindingKindCountry     = osint.FindingKindCountry
	FindingKindNetwork     = osint.FindingKindNetwork
)

// EnrichmentResult is the output of enriching an Investigation.
// It is a read-only, deterministic transformation of existing evidence.
type EnrichmentResult struct {
	InvestigationID   string             `json:"investigationId"`
	InvestigationName string           `json:"investigationName"`
	Findings          []Finding          `json:"findings"`
	Correlations      []FindingCorrelation `json:"correlations"`
	Evidence          map[string][]FindingEvidence `json:"evidence"`
	EntryMapping      map[string]string  `json:"entryMapping"` // entryID -> findingID
	Stats             EnrichmentStats    `json:"stats"`
}

// EnrichmentStats provides summary counts for the enrichment result.
type EnrichmentStats struct {
	TotalFindings     int `json:"totalFindings"`
	TotalCorrelations int `json:"totalCorrelations"`
	TotalEvidence     int `json:"totalEvidence"`
	BySourceKind      map[string]int `json:"bySourceKind"`
}

// EnrichInvestigation enriches an Investigation by converting its Entries
// into Findings, Evidence, and Correlations using the EnrichmentEngine.
// This is a LOCAL transformation — no network calls, no provider execution,
// no new evidence generation. It only correlates what is already explicitly
// present in the Investigation's Entries.
func EnrichInvestigation(inv Investigation) (EnrichmentResult, error) {
	engine := osint.NewEnrichmentEngine()
	entryMapping := make(map[string]string)
	evidenceByFinding := make(map[string][]FindingEvidence)
	sourceKindCounts := make(map[string]int)

	// Process each Entry in the Investigation
	for _, entry := range inv.Entries {
		snap := entry.Snapshot

		// Create a Finding for this Entry
		findingID := "f_" + entry.ID
		finding := Finding{
			ID:            findingID,
			Subject:       snap.Subject,
			Kind:          sourceKindToFindingKind(snap.Kind),
			EvidenceClass: evidenceClassFromProvenance(snap.Assessment.Evidence),
			ProvenanceRef: buildProvenanceRef(inv.ID, entry.ID, snap),
			SourceRefs:    []string{entry.ID},
			Attributes: map[string]string{
				"investigation_id": inv.ID,
				"entry_id":         entry.ID,
				"source_kind":      string(snap.Kind),
				"level":            string(snap.Assessment.Level),
				"confidence":       fmt.Sprintf("%d", snap.Assessment.Confidence),
			},
			Summary:   snap.Assessment.Conclusion,
			CreatedAt: entry.AddedAt,
			UpdatedAt: entry.AddedAt,
		}

		if err := engine.AddFinding(finding); err != nil {
			return EnrichmentResult{}, fmt.Errorf("enrich: add finding for entry %s: %w", entry.ID, err)
		}

		entryMapping[entry.ID] = findingID
		sourceKindCounts[string(snap.Kind)]++

		// Convert Assessment Evidence to FindingEvidence
		for i, ev := range snap.Assessment.Evidence {
			evidenceID := fmt.Sprintf("e_%s_%d", entry.ID, i)
			findingEvidence := FindingEvidence{
				ID:            evidenceID,
				FindingID:     findingID,
				Type:          ev.Type,
				Value:         ev.Value,
				Source:        ev.Source,
				ProvenanceRef: provenanceRefFromModel(ev.Provenance),
				EvidenceClass: evidenceClassFromModelProvenance(ev.Provenance),
				Confidence:    fmt.Sprintf("%d", ev.Confidence),
				Explain:       ev.Explain,
				Timestamp:     ev.Timestamp.UTC().Format(time.RFC3339),
			}

			if err := engine.AddEvidence(findingEvidence); err != nil {
				return EnrichmentResult{}, fmt.Errorf("enrich: add evidence %s for entry %s: %w", evidenceID, entry.ID, err)
			}
			evidenceByFinding[findingID] = append(evidenceByFinding[findingID], findingEvidence)
		}

		// Note: CounterEvidence is also added as separate evidence items
		for i, ev := range snap.Assessment.CounterEvid {
			evidenceID := fmt.Sprintf("ce_%s_%d", entry.ID, i)
			findingEvidence := FindingEvidence{
				ID:            evidenceID,
				FindingID:     findingID,
				Type:          ev.Type,
				Value:         ev.Value,
				Source:        ev.Source,
				ProvenanceRef: provenanceRefFromModel(ev.Provenance),
				EvidenceClass: evidenceClassFromModelProvenance(ev.Provenance),
				Confidence:    fmt.Sprintf("%d", ev.Confidence),
				Explain:       "(counter-evidence) " + ev.Explain,
				Timestamp:     ev.Timestamp.UTC().Format(time.RFC3339),
			}
			if err := engine.AddEvidence(findingEvidence); err != nil {
				return EnrichmentResult{}, fmt.Errorf("enrich: add counter-evidence %s for entry %s: %w", evidenceID, entry.ID, err)
			}
			evidenceByFinding[findingID] = append(evidenceByFinding[findingID], findingEvidence)
		}
	}

	// Build correlations from explicit relationships in the Investigation
	// For V1.5-5, we only correlate when there is explicit shared evidence
	// or when the same Subject appears across multiple entries.
	buildExplicitCorrelations(engine, inv, entryMapping)

	// Collect all findings
	findings := engine.Findings()
	allCorrelations := engine.Correlations()

	// Build evidence map for output
	evidenceOut := make(map[string][]FindingEvidence)
	for _, f := range findings {
		evidenceOut[f.ID] = engine.EvidenceForFinding(f.ID)
	}

	stats := EnrichmentStats{
		TotalFindings:     len(findings),
		TotalCorrelations: len(allCorrelations),
		TotalEvidence:     engine.EvidenceCount(),
		BySourceKind:      sourceKindCounts,
	}

	return EnrichmentResult{
		InvestigationID:   inv.ID,
		InvestigationName: inv.Name,
		Findings:          findings,
		Correlations:      allCorrelations,
		Evidence:          evidenceOut,
		EntryMapping:      entryMapping,
		Stats:             stats,
	}, nil
}

// buildExplicitCorrelations creates correlations ONLY when there is
// explicit shared evidence or explicit relationship in the snapshots.
// NO auto-correlation by shared attributes (IP, ASN, country, etc.).
func buildExplicitCorrelations(engine *osint.EnrichmentEngine, inv Investigation, entryMapping map[string]string) {
	// Group findings by Subject to find explicit co-occurrence
	subjectGroups := make(map[string][]string)
	for _, entry := range inv.Entries {
		if entry.Snapshot.Subject != "" {
			findingID := entryMapping[entry.ID]
			if findingID != "" {
				subjectGroups[entry.Snapshot.Subject] = append(subjectGroups[entry.Snapshot.Subject], findingID)
			}
		}
	}

	// For each subject with multiple findings, create POSSIBLE_CONTEXT correlations
	// between them — this reflects "same subject appeared in multiple sources"
	// without claiming a proven relationship.
	for subject, findingIDs := range subjectGroups {
		if len(findingIDs) < 2 {
			continue
		}
		sort.Strings(findingIDs)
		for i := 0; i < len(findingIDs); i++ {
			for j := i + 1; j < len(findingIDs); j++ {
				corrID := fmt.Sprintf("c_%s_%s", findingIDs[i], findingIDs[j])
				corr := FindingCorrelation{
					ID:            corrID,
					From:          findingIDs[i],
					To:            findingIDs[j],
					Kind:          "same_subject",
					Directed:      false,
					EvidenceClass: EvidencePossibleContext,
					ProvenanceRef: "",
					Label:         fmt.Sprintf("Same subject: %s", subject),
					CreatedAt:     "",
				}
				_ = engine.AddCorrelation(corr)
			}
		}
	}

	// If any Entry has explicit graph data (e.g., webintel Graph edges),
	// we could add OBSERVED correlations here. For V1.5-5, we only
	// add what is explicitly derivable from the snapshot data.
	// Future versions may add richer correlation from PCAP graph, etc.
}

// sourceKindToFindingKind maps correlation.SourceKind to FindingKind.
func sourceKindToFindingKind(kind correlation.SourceKind) FindingKind {
	switch kind {
	case correlation.SourceDiagnose:
		return FindingKindDomain
	case correlation.SourcePCAP:
		return FindingKindNetwork
	case correlation.SourceMonitor:
		return FindingKindNetwork
	case correlation.SourceVoIP:
		return FindingKindDomain
	default:
		return FindingKindUnknown
	}
}

// evidenceClassFromProvenance determines the EvidenceClass from a slice of model.Evidence.
// If any evidence is ProvObserved, the finding is EvidenceObserved.
// If any is ProvExternal, it's EvidencePossibleContext.
// Otherwise EvidenceNotProven.
func evidenceClassFromProvenance(evs []model.Evidence) EvidenceClass {
	hasObserved := false
	hasExternal := false
	for _, ev := range evs {
		switch ev.Provenance {
		case model.ProvObserved:
			hasObserved = true
		case model.ProvExternal:
			hasExternal = true
		}
	}
	if hasObserved {
		return EvidenceObserved
	}
	if hasExternal {
		return EvidencePossibleContext
	}
	return EvidenceNotProven
}

// evidenceClassFromModelProvenance maps a single model.Provenance to EvidenceClass.
func evidenceClassFromModelProvenance(p model.Provenance) EvidenceClass {
	switch p {
	case model.ProvObserved:
		return EvidenceObserved
	case model.ProvExternal:
		return EvidencePossibleContext
	case model.ProvResolved:
		return EvidencePossibleContext
	default:
		return EvidenceNotProven
	}
}

// provenanceRefFromModel returns a provenance reference string for a model.Provenance.
func provenanceRefFromModel(p model.Provenance) string {
	switch p {
	case model.ProvObserved:
		return "prov:observed"
	case model.ProvExternal:
		return "prov:external"
	case model.ProvResolved:
		return "prov:resolved"
	default:
		return "prov:inferred"
	}
}

// buildProvenanceRef builds a composite provenance reference for a finding.
func buildProvenanceRef(invID, entryID string, snap correlation.Snapshot) string {
	return fmt.Sprintf("inv:%s/entry:%s/src:%s", invID, entryID, snap.Kind)
}