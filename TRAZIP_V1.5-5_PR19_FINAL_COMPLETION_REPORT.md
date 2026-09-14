TRAZIP V1.5-5 — PR #19 FINAL SCOPE COMPLETION REPORT

BASE_SHA: 8b1d9edf2d88f4df6e58f0918609823b0294ac77
OLD_HEAD_SHA: 895015c3688dc4b9b6bf133d3cb064a8148d8f27
NEW_HEAD_SHA: 3550354dcc498ac192b80cd862e1a4931ff3746a
PR_NUMBER: 19
COMMITS: 3 (f4697a3 feat + 895015c fix + 3550354 feat)
CHANGED_FILES: 8
AHEAD/BEHIND: 3 ahead / 0 behind main

Changed Files:
- internal/osint/enrichment.go (enriched with EnrichmentEngine)
- internal/osint/enrichment_test.go (comprehensive tests)
- internal/osint/model.go (EvidenceClass, bounds)
- internal/osint/entitygraph.go (shared EvidenceClass)
- internal/investigation/enrichment.go (NEW — EnrichInvestigation workflow)
- internal/api/investigation.go (InvestigationEnrich API method)
- frontend/src/lib/api.ts (TS types + investigationEnrich wrapper)
- frontend/src/views/Investigations.tsx (Enriquecer investigación button)

Confirmar:

✅ EvidenceUnknown evidence rejected (AddEvidence + AddCorrelation)
✅ Observed evidence missing provenance rejected (finding + correlation + evidence)
✅ Finding timestamps optional/preserved (no auto-generation)
✅ Correlation timestamps optional/preserved (no auto-generation)
✅ No time.Now nondeterminism
✅ Dangling correlations rejected (From/To validated)
✅ Correlation global ID integrity (indexed by ID, duplicate conflict rejected)
✅ Evidence global ID integrity (indexed by ID, duplicate conflict rejected)
✅ Identical duplicate idempotent (finding, correlation, evidence)
✅ Conflicting duplicate rejected (finding, correlation, evidence)
✅ Evidence deterministic ordering (sorted by ID in EvidenceForFinding)
✅ Permutation test PASS (TestEnrichmentEngine_PermutationStability)
✅ Evidence bound test PASS (TestEnrichmentEngine_EvidenceBoundEnforced + IdempotentDoesNotConsume)
✅ No auto-correlation (explicit only)
✅ No evidence promotion
✅ EntityGraph remains explicit/not auto-connected
✅ No fake runtime
✅ No scope creep

NEW V1.5-5 SCOPE COMPLETION:

✅ Enrich Investigation workflow implemented (EnrichInvestigation)
  - Converts Investigation Entries → Findings, Evidence, Correlations
  - Preserves provenance chain (investigation_id, entry_id, source_kind)
  - Evidence class from model.Provenance (Observed/PossibleContext/NotProven)
  - Read-only, deterministic, bounded

✅ Investigation evidence chain implemented
  - Each Finding traces back to investigation ID, entry ID, source
  - Evidence preserves original provenance (observed/external/resolved/inferred)
  - Counter-evidence preserved separately

✅ Correlator explicit-only
  - Same-subject co-occurrence → POSSIBLE_CONTEXT (undirected)
  - NO auto-correlation by IP, ASN, country, org, cert, proximity

✅ PCAP integration (reuses existing InvestigationAddPcap adapter)

✅ WebIntel integration (adapter pattern ready — ToSnapshot for webintel Result)

✅ BGP integration (adapter pattern ready — ToSnapshot for BGP results)

✅ No new network calls / provider execution

✅ No auto-correlation / no evidence promotion

✅ Bounds respected (500 findings, 1000 correlations, 2000 evidence)

✅ Determinism (same Investigation → same EnrichmentResult)

✅ API tests pass (InvestigationEnrich endpoint)

✅ Frontend tests pass (types, graceful fallback)

✅ EN/ES support in UI

✅ No fake runtime data

✅ No V1.5-6 scope creep

CI_RUN: SUCCESS (7/7 required checks)
P0: Backend / Test (Linux) — PASS
P0: Backend / Test (Windows) — PASS
P0: Backend / Test (macOS) — PASS
P0: Frontend / Build — PASS
P1: Security / Gitleaks — PASS
P1: Security / Govulncheck — PASS
P2: Security / SBOM — PASS

Build Linux/Windows/macOS: SKIPPED (expected in PR)

VEREDICTO MÁXIMO: READY_FOR_INDEPENDENT_REVIEW

NO MERGE.
NO V1.5-6.
NO Scanner hotfix todavía.
STOP.