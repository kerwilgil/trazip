TRAZIP V1.5-5 — INVESTIGATION ENRICHMENT REVIEW REPORT

BASE_SHA: 8b1d9edf2d88f4df6e58f0918609823b0294ac77
BRANCH: feature/v1.5-5-investigation-enrichment
HEAD_SHA: f4697a3c
PR_NUMBER: 19
COMMITS: 1 (f4697a3)
CHANGED_FILES: 4 (internal/osint/enrichment.go, internal/osint/enrichment_test.go, internal/osint/model.go, internal/osint/entitygraph.go)
AHEAD/BEHIND: 1 ahead / 0 behind main

Implementación:
- Finding: finding ID, subject, kind, evidence_class, provenance_ref, source_refs, attributes, summary, timestamps
- FindingEvidence: finding_id, type, value, source, provenance_ref, evidence_class, confidence, explain, timestamp
- FindingCorrelation: from, to, kind, directed, evidence_class, provenance_ref, label, created_at
- Engine: EnrichmentEngine with explicit input-only semantics (no inference, no auto-promotion, no fabricated data)
- bounds: DefaultMaxFindings=500, DefaultMaxCorrelations=1000, DefaultMaxEvidence=2000
- ordering: deterministic (sorted by ID/key) for all queries
- defensive copies: all getters return clones to prevent mutation through retained slices
- duplicate policy: identical idempotent, conflicting rejected
- provenance policy: OBSERVED requires non-empty ProvenanceRef
- evidence policy: classes preserved, no auto-promotion between classes
- correlation policy: explicit only, no auto-correlation by shared attributes (same IP, ASN, country, org, cert, co-occurrence, proximity)
- Entity Graph integration: uses same EvidenceClass enum and validation; V1.5-5 does NOT auto-connect to EntityGraph at runtime; integration contract prepared (same evidence classes, provenance refs, deterministic ordering, defensive copies)
- UI/runtime integration: backend-only by architecture; no fake findings, no fake correlations, no demo investigation runtime; fixtures only in tests

Tests específicos:
- EvidenceUnknown reject
- OBSERVED missing provenance reject
- POSSIBLE_CONTEXT preserved
- NOT_PROVEN preserved
- no auto-promotion
- duplicate identical idempotent
- duplicate conflict rejected
- finding bounds enforced
- correlation bounds enforced
- evidence bounds enforced
- deterministic ordering
- permutation stability
- dangling reference rejection
- defensive copy
- explicit relation only
- no fake runtime

Validación:
go test ./internal/osint/...: PASS
go test ./...: PASS
go vet: PASS
go build: PASS
npm test: PASS (90 tests)
npm run build: PASS
govulncheck: PASS (no vulnerabilities in called code)
gitleaks: PASS (no new leaks in current changes)
git diff --check: PASS (only LF/CRLF line ending warnings in working copy, no actual whitespace errors)
git status --short: 4 modified/created files staged

CI_RUN: SUCCESS (7/7 required checks)
P0: Backend / Test (Linux) - PASS (58s)
P0: Backend / Test (Windows) - PASS (3m8s)
P0: Backend / Test (macOS) - PASS (1m26s)
P0: Frontend / Build - PASS (23s)
P1: Security / Gitleaks - PASS (13s)
P1: Security / Govulncheck - PASS (30s)
P2: Security / SBOM - PASS (1m5s)

Build Linux/Windows/macOS: SKIPPED (expected in PR)

VEREDICTO MÁXIMO: READY_FOR_INDEPENDENT_REVIEW

NO MERGE.
NO iniciar V1.5-6.
NO iniciar todavía el Scanner hotfix.
STOP.