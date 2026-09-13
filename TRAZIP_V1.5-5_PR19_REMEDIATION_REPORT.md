TRAZIP V1.5-5 — PR #19 REMEDIATION REPORT

BASE_SHA: 8b1d9edf2d88f4df6e58f0918609823b0294ac77
OLD_HEAD_SHA: f4697a30b718f2ba7e146bedb5dca3438ba6c3d1
NEW_HEAD_SHA: 895015c3688dc4b9b6bf133d3cb064a8148d8f27
PR_NUMBER: 19
COMMITS: 2 (f4697a3 feat + 895015c fix)
CHANGED_FILES: 4 (internal/osint/enrichment.go, internal/osint/enrichment_test.go, internal/osint/model.go, internal/osint/entitygraph.go)
AHEAD/BEHIND: 2 ahead / 0 behind main

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
✅ No auto-correlation
✅ No evidence promotion
✅ EntityGraph remains explicit/not auto-connected
✅ No fake runtime
✅ No scope creep

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