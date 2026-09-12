// Package investigation provides enrichment integration for Investigation workspace.
// This file connects Investigation entries to the OSINT EnrichmentEngine (V1.5-5)
// without re-executing any providers or making network calls.
package investigation

import (
	"encoding/json"
	"fmt"
	"time"

	"trazip/internal/bgp"
	"trazip/internal/correlation"
	"trazip/internal/model"
	"trazip/internal/osint"
	"trazip/internal/webintel"
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
				Timestamp:     formatTimestamp(ev.Timestamp),
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
				Timestamp:     formatTimestamp(ev.Timestamp),
			}
			if err := engine.AddEvidence(findingEvidence); err != nil {
				return EnrichmentResult{}, fmt.Errorf("enrich: add counter-evidence %s for entry %s: %w", evidenceID, entry.ID, err)
			}
			evidenceByFinding[findingID] = append(evidenceByFinding[findingID], findingEvidence)
		}
	}

	// NO auto-correlation by subject or shared attributes.
	// Correlations are only added when explicitly present in snapshot data.
	// For V1.5-5, snapshots do not carry explicit inter-finding relations,
	// so Correlations remains empty. Future versions may add explicit
	// correlation extraction from webintel Graph, PCAP findings, etc.

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

// formatTimestamp returns RFC3339 string if t is non-zero, empty string otherwise.
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
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
	case correlation.SourceWebIntel:
		return FindingKindDomain
	case correlation.SourceBGPIntelligence:
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

// ============================================================
// WebIntel Adapter
// ============================================================

// ToSnapshotWebIntel adapts a completed webintel.Result into a correlation.Snapshot
// for Investigation storage. This is a pure mapping — no recomputation, no network calls.
func ToSnapshotWebIntel(res webintel.Result, subject, sourceID, occurredAt string) (correlation.Snapshot, error) {
	if res.InputURL == "" && subject == "" {
		return correlation.Snapshot{}, fmt.Errorf("webintel: missing subject")
	}
	if subject == "" {
		subject = res.InputURL
	}

	// Build assessment from webintel result
	level := model.LevelInfo
	confidence := model.Confidence(50)
	conclusion := "Web Intelligence analysis completed"
	var evidence []model.Evidence

	if res.Error != nil {
		level = model.LevelHigh
		confidence = 80
		conclusion = "Web Intelligence analysis failed: " + res.Error.FriendlyMessageES
		evidence = append(evidence, model.Evidence{
			Type:       "error",
			Value:      res.Error.TechnicalDetail,
			Source:     "webintel",
			Provenance: model.ProvObserved,
			Timestamp:  time.Now().UTC(),
			Confidence: 80,
			Explain:    res.Error.FriendlyMessageES,
		})
	} else {
		// Extract evidence from TLS, HTTP, DNS chain
		if res.TLS != nil {
			for _, cert := range res.TLS.Chain {
				evidence = append(evidence, model.Evidence{
					Type:       "certificate",
					Value:      cert.Subject,
					Source:     "webintel-tls",
					Provenance: model.ProvObserved,
					Timestamp:  time.Now().UTC(),
					Confidence: 70,
					Explain:    fmt.Sprintf("TLS certificate: %s (issuer: %s)", cert.Subject, cert.Issuer),
				})
			}
		}
		for _, ep := range res.ContactedEndpoints {
			evidence = append(evidence, model.Evidence{
				Type:       "endpoint",
				Value:      ep.IP,
				Source:     "webintel-http",
				Provenance: model.ProvObserved,
				Timestamp:  time.Now().UTC(),
				Confidence: 60,
				Explain:    fmt.Sprintf("Contacted endpoint: %s (%s)", ep.Hostname, ep.IP),
			})
		}
		for _, hostname := range res.ExtractedHostnames {
			evidence = append(evidence, model.Evidence{
				Type:       "hostname",
				Value:      hostname,
				Source:     "webintel-extract",
				Provenance: model.ProvExternal,
				Timestamp:  time.Now().UTC(),
				Confidence: 50,
				Explain:    "Hostname extracted from response body/headers",
			})
		}
	}

	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceWebIntel,
		SourceID:      sourceID,
		Subject:       subject,
		OccurredAt:    occurredAt,
		Assessment: model.Assessment{
			Conclusion:  conclusion,
			Level:       level,
			Confidence:  confidence,
			Evidence:    evidence,
			Limitations: []string{"WebIntel analysis is point-in-time; results may change"},
		},
	}, nil
}

// ============================================================
// BGP Intelligence Adapter
// ============================================================

// ToSnapshotBGP adapts a completed BGP overview/security/prefixes result
// into a correlation.Snapshot for Investigation storage.
// This is a pure mapping — no recomputation, no network calls.
func ToSnapshotBGP(resource string, overview *bgp.Overview, security *bgp.SecurityResult, occurredAt string) (correlation.Snapshot, error) {
	if resource == "" {
		return correlation.Snapshot{}, fmt.Errorf("bgp: missing resource")
	}

	level := model.LevelInfo
	confidence := model.Confidence(50)
	conclusion := fmt.Sprintf("BGP Intelligence summary for %s", resource)
	var evidence []model.Evidence
	var limitations []string

	if overview != nil {
		// Check if resource has announced prefixes (either explicit prefixes or announced space)
		hasAnnounced := len(overview.Prefixes) > 0 || overview.AnnouncedSpaceV4 != nil || overview.AnnouncedSpaceV6 != nil
		if hasAnnounced {
			evidence = append(evidence, model.Evidence{
				Type:       "bgp_announced",
				Value:      resource,
				Source:     "bgp-overview",
				Provenance: model.ProvExternal,
				Timestamp:  time.Now().UTC(),
				Confidence: 80,
				Explain:    fmt.Sprintf("Resource %s is announced in BGP (holder: %s)", resource, overview.Holder),
			})
		}
		if len(overview.Prefixes) > 0 {
			for _, pfx := range overview.Prefixes {
				evidence = append(evidence, model.Evidence{
					Type:       "bgp_prefix",
					Value:      pfx,
					Source:     "bgp-overview",
					Provenance: model.ProvExternal,
					Timestamp:  time.Now().UTC(),
					Confidence: 70,
					Explain:    fmt.Sprintf("Announced prefix: %s", pfx),
				})
			}
		}
		limitations = append(limitations, "BGP data sourced from RIPE RIS/RIPEstat; may have visibility gaps")
	}

	if security != nil {
		switch security.Health.State {
		case bgp.HealthRisk, bgp.HealthDegraded, bgp.HealthAttention:
			level = model.LevelHigh
			confidence = 80
			conclusion = fmt.Sprintf("BGP security issue detected for %s: %s", resource, security.Health.State)
		}
		// Check RPKI validation results from States map
		if security.RPKI.States != nil {
			hasInvalid := false
			for state, count := range security.RPKI.States {
				if count > 0 && (state == bgp.RPKIInvalidASN || state == bgp.RPKIInvalidLength) {
					hasInvalid = true
					break
				}
			}
			if hasInvalid {
				evidence = append(evidence, model.Evidence{
					Type:       "bgp_rpki",
					Value:      "invalid",
					Source:     "bgp-security",
					Provenance: model.ProvExternal,
					Timestamp:  time.Now().UTC(),
					Confidence: 75,
					Explain:    "RPKI validation found INVALID_ASN or INVALID_LENGTH",
				})
			}
		}
		// Also check detailed results
		for _, r := range security.RPKI.Results {
			if r.State == bgp.RPKIInvalidASN || r.State == bgp.RPKIInvalidLength {
				evidence = append(evidence, model.Evidence{
					Type:       "bgp_rpki",
					Value:      fmt.Sprintf("%s: %s", r.Prefix, r.State),
					Source:     "bgp-security",
					Provenance: model.ProvExternal,
					Timestamp:  time.Now().UTC(),
					Confidence: 75,
					Explain:    fmt.Sprintf("RPKI validation for %s: %s", r.Prefix, r.State),
				})
			}
		}
		for _, origin := range security.Origins {
			evidence = append(evidence, model.Evidence{
				Type:       "bgp_origin",
				Value:      fmt.Sprintf("%d", origin),
				Source:     "bgp-security",
				Provenance: model.ProvExternal,
				Timestamp:  time.Now().UTC(),
				Confidence: 70,
				Explain:    fmt.Sprintf("Origin ASN: %d", origin),
			})
		}
		limitations = append(limitations, "BGP security analysis based on RIPEstat/RPKI; may not reflect real-time state")
	}

	if len(evidence) == 0 {
		conclusion = fmt.Sprintf("No BGP intelligence findings for %s", resource)
		limitations = append(limitations, "No announcements or security data found for resource")
	}

	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceBGPIntelligence,
		SourceID:      resource,
		Subject:       resource,
		OccurredAt:    occurredAt,
		Assessment: model.Assessment{
			Conclusion:  conclusion,
			Level:       level,
			Confidence:  confidence,
			Evidence:    evidence,
			Limitations: limitations,
		},
	}, nil
}

// ============================================================
// JSON serialization test helper
// ============================================================

// MarshalEnrichmentResult returns the JSON representation of an EnrichmentResult
// using standard JSON tags for frontend compatibility.
func MarshalEnrichmentResult(r EnrichmentResult) ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalEnrichmentResult parses an EnrichmentResult from JSON.
func UnmarshalEnrichmentResult(data []byte) (EnrichmentResult, error) {
	var r EnrichmentResult
	err := json.Unmarshal(data, &r)
	return r, err
}