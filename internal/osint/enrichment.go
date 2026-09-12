// Package osint provides the enrichment layer for OSINT Intelligence (V1.5-5).
package osint

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ============================================================
// Finding — enriched investigation finding
// ============================================================

// FindingKind classifies the type of finding.
type FindingKind string

const (
	FindingKindUnknown    FindingKind = ""
	FindingKindIP         FindingKind = "ip"
	FindingKindDomain     FindingKind = "domain"
	FindingKindASN        FindingKind = "asn"
	FindingKindCertificate FindingKind = "certificate"
	FindingKindCVE        FindingKind = "cve"
	FindingKindOrganization FindingKind = "organization"
	FindingKindURL        FindingKind = "url"
	FindingKindCountry    FindingKind = "country"
	FindingKindNetwork    FindingKind = "network"
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
	CreatedAt     string            // RFC3339
	UpdatedAt     string            // RFC3339
}

// Validate checks that the finding is well-formed.
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
	if f.CreatedAt == "" {
		return fmt.Errorf("finding: missing CreatedAt")
	}
	if f.UpdatedAt == "" {
		return fmt.Errorf("finding: missing UpdatedAt")
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
	Timestamp     string // RFC3339
}

// FindingCorrelation represents an explicit correlation between two entities/findings.
type FindingCorrelation struct {
	ID            string
	From          string // Finding ID or Entity ID
	To            string // Finding ID or Entity ID
	Kind          string
	Directed      bool
	EvidenceClass EvidenceClass
	ProvenanceRef string
	Label         string
	CreatedAt     string // RFC3339
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
	correlations    map[string]FindingCorrelation
	evidenceItems   map[string][]FindingEvidence
	bySubject       map[string][]string // subject -> finding IDs
	bySourceRef     map[string][]string // source ref -> finding IDs
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
		bySubject:       make(map[string][]string),
		bySourceRef:     make(map[string][]string),
		maxFindings:     maxFindings,
		maxCorrelations: maxCorrelations,
		maxEvidence:     maxEvidence,
	}
}

// AddFinding adds a finding to the engine. Validates evidence class and provenance.
// Idempotent if identical; rejects conflicting duplicate.
func (e *EnrichmentEngine) AddFinding(f Finding) error {
	if err := f.Validate(); err != nil {
		return &EnrichmentError{Op: "AddFinding", Err: err}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if f.CreatedAt == "" {
		f.CreatedAt = now
	}
	f.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

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

// AddCorrelation adds an explicit correlation between two findings/entities.
// Validates from/to exist, evidence class, and provenance for OBSERVED.
func (e *EnrichmentEngine) AddCorrelation(c FindingCorrelation) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}

	e.mu.Lock()
	defer e.mu.Unlock()

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

	key := correlationKey(c.From, c.To, c.Kind, c.ID)
	if _, exists := e.correlations[key]; exists {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation %q already exists", key)}
	}

	if len(e.correlations) >= e.maxCorrelations {
		return &EnrichmentError{Op: "AddCorrelation", Err: fmt.Errorf("correlation limit reached (%d)", e.maxCorrelations)}
	}

	e.correlations[key] = c
	return nil
}

// AddEvidence adds an evidence item to a finding.
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
	if evid.EvidenceClass != EvidenceUnknown && !evid.EvidenceClass.IsValid() {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: invalid evidence class %q", evid.EvidenceClass)}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.findings[evid.FindingID]; !ok {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence: finding %q does not exist", evid.FindingID)}
	}

	total := 0
	for _, items := range e.evidenceItems {
		total += len(items)
	}
	if total >= e.maxEvidence {
		return &EnrichmentError{Op: "AddEvidence", Err: fmt.Errorf("evidence limit reached (%d)", e.maxEvidence)}
	}

	e.evidenceItems[evid.FindingID] = append(e.evidenceItems[evid.FindingID], evid)
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

// Correlations returns all correlations as a deterministic slice.
func (e *EnrichmentEngine) Correlations() []FindingCorrelation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	keys := make([]string, 0, len(e.correlations))
	for k := range e.correlations {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]FindingCorrelation, 0, len(keys))
	for _, k := range keys {
		out = append(out, e.correlations[k])
	}
	return out
}

// EvidenceForFinding returns all evidence for a finding.
func (e *EnrichmentEngine) EvidenceForFinding(findingID string) []FindingEvidence {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := e.evidenceItems[findingID]
	if len(items) == 0 {
		return nil
	}
	out := make([]FindingEvidence, len(items))
	copy(out, items)
	return out
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

// Correlation returns a correlation by from/to/kind/id.
func (e *EnrichmentEngine) Correlation(from, to, kind, id string) (FindingCorrelation, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	key := correlationKey(from, to, kind, id)
	c, ok := e.correlations[key]
	if !ok {
		return FindingCorrelation{}, false
	}
	return c, true
}

// CorrelationsFrom returns outgoing correlations for an entity.
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

// CorrelationsTo returns incoming correlations for an entity.
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
		a.Summary != b.Summary {
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

func correlationKey(from, to, kind, id string) string {
	return from + "\x00" + to + "\x00" + kind + "\x00" + id
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }