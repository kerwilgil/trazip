// Package osint provides the enrichment layer for OSINT Intelligence (V1.5-5).
package osint

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ============================================================
// Finding — enriched investigation finding
// ============================================================

// FindingKind classifies the type of finding.
type FindingKind string

const (
	FindingKindUnknown     FindingKind = ""
	FindingKindIP          FindingKind = "ip"
	FindingKindDomain      FindingKind = "domain"
	FindingKindASN         FindingKind = "asn"
	FindingKindCertificate FindingKind = "certificate"
	FindingKindCVE         FindingKind = "cve"
	FindingKindOrganization FindingKind = "organization"
	FindingKindURL         FindingKind = "url"
	FindingKindCountry     FindingKind = "country"
	FindingKindNetwork     FindingKind = "network"
)

// Finding represents an enriched finding with explicit evidence.
type Finding struct {
	ID            string
	Subject       string
	Kind          FindingKind
	EvidenceClass EvidenceClass
	ProvenanceRef string
	SourceRefs    []string          // Source IDs that contributed to this finding
	Attributes    map[string]string
	Summary       string            // Human-readable summary
	CreatedAt     string            // RFC3339 (optional, preserved if provided)
	UpdatedAt     string            // RFC3339 (optional, preserved if provided)
}

// Validate checks that the finding is well-formed.
// Timestamps are optional; if provided they are preserved as-is.
func (f Finding) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("finding: missing ID")
	}
	if f.Subject == "" {
		return fmt.Errorf("finding: missing subject")
	}
	if f.Kind == FindingKindUnknown {
		return fmt.Errorf("finding: missing kind")
	}
	if !f.EvidenceClass.IsValid() {
		return fmt.Errorf("finding: invalid evidence class %q", f.EvidenceClass)
	}
	if f.EvidenceClass == EvidenceObserved && f.ProvenanceRef == "" {
		return fmt.Errorf("finding: OBSERVED requires non-empty ProvenanceRef")
	}
	return nil
}

// clone returns a deep copy of the finding.
func (f Finding) clone() Finding {
	cp := f
	if f.Attributes != nil {
		cp.Attributes = make(map[string]string, len(f.Attributes))
		for k, v := range f.Attributes {
			cp.Attributes[k] = v
		}
	}
	if f.SourceRefs != nil {
		cp.SourceRefs = make([]string, len(f.SourceRefs))
		copy(cp.SourceRefs, f.SourceRefs)
	}
	return cp
}

// FindingEvidence represents a single piece of evidence for a finding.
type FindingEvidence struct {
	ID            string
	FindingID     string
	Type          string
	Value         string
	Source        string
	ProvenanceRef string
	EvidenceClass EvidenceClass
	Confidence    string
	Explain       string
	Timestamp     string // RFC3339 (optional, preserved if provided)
}

// FindingCorrelation represents an explicit correlation between two findings.
type FindingCorrelation struct {
	ID            string
	From          string // Finding ID
	To            string // Finding ID
	Kind          string
	Directed      bool
	EvidenceClass EvidenceClass
	ProvenanceRef string
	Label         string
	CreatedAt     string // RFC3339 (optional, preserved if provided)
}

// ============================================================
// Enrichment Engine — builds findings from explicit inputs
// ============================================================

// EnrichmentError wraps enrichment operation errors.
type EnrichmentError struct {
	Op  string
	Err error
}

func (e *EnrichmentError) Error() string {
	return fmt.Sprintf("enrichment: %s: %v", e.Op, e.Err)
}

func (e *EnrichmentError) Unwrap() error { return e.Err }

func IsEnrichmentError(err error) bool {
	var ee *EnrichmentError
	return errors.As(err, &ee)
}

// EnrichmentEngine builds findings from explicit inputs only.
// NO inference, NO automatic promotion, NO fabricated data.
type EnrichmentEngine struct {
	mu              sync.RWMutex
	findings        map[string]Finding
	correlations    map[string]FindingCorrelation // key = correlation ID
	evidenceItems   map[string][]FindingEvidence  // findingID -> evidence list
	evidenceByID    map[string]FindingEvidence    // global evidence ID -> evidence
	bySubject       map[string][]string           // subject -> finding IDs
	bySourceRef     map[string][]string           // source ref -> finding IDs
	maxFindings     int
	maxCorrelations int
	maxEvidence     int
}

// NewEnrichmentEngine creates an empty enrichment engine with default bounds.
func NewEnrichmentEngine() *EnrichmentEngine {
	return NewEnrichmentEngineWithBounds(
		DefaultMaxFindings,
		DefaultMaxCorrelations,
		DefaultMaxEvidence,
	)
}

// NewEnrichmentEngineWithBounds creates an empty enrichment engine with custom bounds.
func NewEnrichmentEngineWithBounds(maxFindings, maxCorrelations, maxEvidence int) *EnrichmentEngine {
	if maxFindings <= 0 {
		maxFindings = DefaultMaxFindings
	}
	if maxCorrelations <= 0 {
		maxCorrelations = DefaultMaxCorrelations
	}
	if maxEvidence <= 0 {
		maxEvidence = DefaultMaxEvidence
	}
	return &EnrichmentEngine{
		findings:        make(map[string]Finding),
		correlations:    make(map[string]FindingCorrelation),
		evidenceItems:   make(map[string][]FindingEvidence),
		evidenceByID:    make(map[string]FindingEvidence),
		bySubject:       make(map[string][]string),
		bySourceRef:     make(map[string][]string),
		maxFindings:     maxFindings,
		maxCorrelations: maxCorrelations,
		maxEvidence:     maxEvidence,
	}
}

// AddFinding adds a finding to the engine. Validates evidence class and provenance.
// Idempotent if identical; rejects conflicting duplicate.
// Timestamps are preserved as provided; not auto-generated.
func (e *EnrichmentEngine) AddFinding(f Finding) error {
	if err := f.Validate(); err != nil {
		return &EnrichmentError{Op: "AddFinding", Err: err}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.findings[f.ID]; ok {
		if !findingsEqual(existing, f) {
			return &EnrichmentError{Op: "AddFinding", Err: fmt.Errorf("finding %q already exists with different content", f.ID)}
		}
		return nil
	}

	if len(e.findings) >= e.maxFindings {
		return &EnrichmentError{Op: "AddFinding", Err: fmt.Errorf("finding limit reached (%d)", e.maxFindings)}
	}

	cloned := f.clone()
	e.findings[f.ID] = cloned
	e.bySubject[f.Subject] = append(e.bySubject[f.Subject], f.ID)
	for _, src := range f.SourceRefs {
		e.bySourceRef[src] = append(e.bySourceRef[src], f.ID)
	}
	return nil
}

// AddCorrelation adds an explicit correlation between two findings.
// Validates from/to exist as findings, evidence class, and provenance for OBSERVED.
// Idempotent if identical ID + identical content; rejects conflicting duplicate.
// Timestamps are preserved as provided; not auto-generated.
func (e *EnrichmentEngine) AddCorrelation(c FindingCorrelation) error {
	if c.ID == "" {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: missing ID")}
	}
	if c.From == "" {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: missing from")}
	}
	if c.To == "" {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: missing to")}
	}
	if c.Kind == "" {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: missing kind")}
	}
	if !c.EvidenceClass.IsValid() {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: invalid evidence class %q", c.EvidenceClass)}
	}
	if c.EvidenceClass == EvidenceObserved && c.ProvenanceRef == "" {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: OBSERVED requires non-empty ProvenanceRef")}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate from/to exist as findings
	if _, ok := e.findings[c.From]; !ok {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: from finding %q does not exist", c.From)}
	}
	if _, ok := e.findings[c.To]; !ok {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation: to finding %q does not exist", c.To)}
	}

	// Global ID integrity: same ID must have identical content
	if existing, exists := e.correlations[c.ID]; exists {
		if correlationsEqual(existing, c) {
			return nil // idempotent
		}
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation ID %q already exists with different content", c.ID)}
	}

	if len(e.correlations) >= e.maxCorrelations {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation limit reached (%d)", e.maxCorrelations)}
	}

	e.correlations[c.ID] = c
	return nil
}

// AddEvidence adds an evidence item to a finding.
// Validates evidence class and provenance for OBSERVED.
// Idempotent if identical ID + identical content; rejects conflicting duplicate.
// Timestamps are preserved as provided; not auto-generated.
func (e *EnrichmentEngine) AddEvidence(evid FindingEvidence) error {
	if evid.ID == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: missing ID")}
	}
	if evid.FindingID == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: missing finding ID")}
	}
	if evid.Type == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: missing type")}
	}
	if evid.Value == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: missing value")}
	}
	if evid.Source == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: missing source")}
	}
	if !evid.EvidenceClass.IsValid() {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: invalid evidence class %q", evid.EvidenceClass)}
	}
	if evid.EvidenceClass == EvidenceObserved && evid.ProvenanceRef == "" {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: OBSERVED requires non-empty ProvenanceRef")}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.findings[evid.FindingID]; !ok {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: finding %q does not exist", evid.FindingID)}
	}

	// Global ID integrity: same ID must have identical content
	if existing, exists := e.evidenceByID[evid.ID]; exists {
		if evidencesEqual(existing, evid) {
			return nil // idempotent
		}
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence ID %q already exists with different content", evid.ID)}
	}

	// Check total evidence bound
	total := len(e.evidenceByID)
	if total >= e.maxEvidence {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence limit reached (%d)", e.maxEvidence)}
	}

	// Store in both indices
	e.evidenceItems[evid.FindingID] = append(e.evidenceItems[evid.FindingID], evid)
	e.evidenceByID[evid.ID] = evid
	return nil
}

// Finding returns a copy of the finding by ID.
func (e *EnrichmentEngine) Finding(id string) (Finding, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	f, ok := e.findings[id]
	if !ok {
		return Finding{}, false
	}
	return f.clone(), true
}

// Findings returns all findings as a deterministic slice (sorted by ID).
func (e *EnrichmentEngine) Findings() []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.findings))
	for id := range e.findings {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.findings[id].clone())
	}
	return out
}

// Correlations returns all correlations as a deterministic slice (sorted by ID).
func (e *EnrichmentEngine) Correlations() []FindingCorrelation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.correlations))
	for id := range e.correlations {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]FindingCorrelation, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.correlations[id])
	}
	return out
}

// EvidenceForFinding returns all evidence for a finding in deterministic order (sorted by ID).
func (e *EnrichmentEngine) EvidenceForFinding(findingID string) []FindingEvidence {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := e.evidenceItems[findingID]
	if len(items) == 0 {
		return nil
	}
	// Sort by ID for deterministic ordering
	sorted := make([]FindingEvidence, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}

// FindingsBySubject returns findings for a subject, sorted by ID.
func (e *EnrichmentEngine) FindingsBySubject(subject string) []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := e.bySubject[subject]
	if len(ids) == 0 {
		return nil
	}
	ids = append([]string(nil), ids...)
	sortStrings(ids)
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.findings[id].clone())
	}
	return out
}

// FindingsBySourceRef returns findings referencing a source, sorted by ID.
func (e *EnrichmentEngine) FindingsBySourceRef(src string) []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := e.bySourceRef[src]
	if len(ids) == 0 {
		return nil
	}
	ids = append([]string(nil), ids...)
	sortStrings(ids)
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.findings[id].clone())
	}
	return out
}

// Correlation returns a correlation by ID.
func (e *EnrichmentEngine) Correlation(id string) (FindingCorrelation, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c, ok := e.correlations[id]
	if !ok {
		return FindingCorrelation{}, false
	}
	return c, true
}

// CorrelationsFrom returns outgoing correlations for a finding, sorted by key.
func (e *EnrichmentEngine) CorrelationsFrom(id string) []FindingCorrelation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []FindingCorrelation
	for _, c := range e.correlations {
		if c.From == id {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return correlationKey(out[i].From, out[i].To, out[i].Kind, out[i].ID) <
			correlationKey(out[j].From, out[j].To, out[j].Kind, out[j].ID)
	})
	return out
}

// CorrelationsTo returns incoming correlations for a finding, sorted by key.
func (e *EnrichmentEngine) CorrelationsTo(id string) []FindingCorrelation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []FindingCorrelation
	for _, c := range e.correlations {
		if c.To == id {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return correlationKey(out[i].From, out[i].To, out[i].Kind, out[i].ID) <
			correlationKey(out[j].From, out[j].To, out[j].Kind, out[j].ID)
	})
	return out
}

// FindingCount returns the number of findings.
func (e *EnrichmentEngine) FindingCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.findings)
}

// CorrelationCount returns the number of correlations.
func (e *EnrichmentEngine) CorrelationCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.correlations)
}

// EvidenceCount returns the total number of evidence items.
func (e *EnrichmentEngine) EvidenceCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.evidenceByID)
}

// MaxFindings returns the configured finding limit.
func (e *EnrichmentEngine) MaxFindings() int { return e.maxFindings }

// MaxCorrelations returns the configured correlation limit.
func (e *EnrichmentEngine) MaxCorrelations() int { return e.maxCorrelations }

// MaxEvidence returns the configured evidence limit.
func (e *EnrichmentEngine) MaxEvidence() int { return e.maxEvidence }

// ============================================================
// Helper functions
// ============================================================

func findingsEqual(a, b Finding) bool {
	if a.ID != b.ID || a.Subject != b.Subject || a.Kind != b.Kind ||
		a.EvidenceClass != b.EvidenceClass || a.ProvenanceRef != b.ProvenanceRef ||
		a.Summary != b.Summary || a.CreatedAt != b.CreatedAt || a.UpdatedAt != b.UpdatedAt {
		return false
	}
	if len(a.SourceRefs) != len(b.SourceRefs) {
		return false
	}
	for i, v := range a.SourceRefs {
		if b.SourceRefs[i] != v {
			return false
		}
	}
	if len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for k, v := range a.Attributes {
		if b.Attributes[k] != v {
			return false
		}
	}
	return true
}

func correlationsEqual(a, b FindingCorrelation) bool {
	return a.ID == b.ID &&
		a.From == b.From &&
		a.To == b.To &&
		a.Kind == b.Kind &&
		a.Directed == b.Directed &&
		a.EvidenceClass == b.EvidenceClass &&
		a.ProvenanceRef == b.ProvenanceRef &&
		a.Label == b.Label &&
		a.CreatedAt == b.CreatedAt
}

func evidencesEqual(a, b FindingEvidence) bool {
	return a.ID == b.ID &&
		a.FindingID == b.FindingID &&
		a.Type == b.Type &&
		a.Value == b.Value &&
		a.Source == b.Source &&
		a.ProvenanceRef == b.ProvenanceRef &&
		a.EvidenceClass == b.EvidenceClass &&
		a.Confidence == b.Confidence &&
		a.Explain == b.Explain &&
		a.Timestamp == b.Timestamp
}

func correlationKey(from, to, kind, id string) string {
	return from + "\x00" + to + "\x00" + kind + "\x00" + id
}