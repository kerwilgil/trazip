## Summary
Completes V1.5-5 Investigation Enrichment scope by integrating the EnrichmentEngine with the existing Investigation workspace.

## Architecture
- **EnrichInvestigation workflow**: Converts Investigation Entries → Findings, Evidence, Correlations
- **EnrichmentEngine**: Existing OSINT engine (V1.5-5) — no inference, no auto-promotion, no fabricated data
- **Integration**: Reuses existing Investigation, Correlation, API, and frontend components

## Models (from internal/osint)
- `Finding` — ID, Subject, Kind, EvidenceClass, ProvenanceRef, SourceRefs, Attributes, Summary, timestamps
- `FindingEvidence` — ID, FindingID, Type, Value, Source, ProvenanceRef, EvidenceClass, Confidence, Explain, Timestamp
- `FindingCorrelation` — ID, From, To, Kind, Directed, EvidenceClass, ProvenanceRef, Label, CreatedAt

## Bounds (enforced)
- `DefaultMaxFindings = 500`
- `DefaultMaxCorrelations = 1000`
- `DefaultMaxEvidence = 2000`

## Evidence Semantics
- `EvidenceUnknown` (0) = INVALID sentinel, rejected
- `EvidenceObserved` = directly backed by provenance; REQUIRES non-empty ProvenanceRef
- `EvidencePossibleContext` = plausible investigative context; no provenance required
- `EvidenceNotProven` = relationship shown only as not proven; no provenance required
- **NO auto-promotion** — classes preserved as added

## Provenance Chain
Each Finding preserves:
- `investigation_id` — the case it came from
- `entry_id` — the specific Entry
- `source_kind` — diagnose/pcap/monitor/voip
- `level` / `confidence` — from original Assessment

## Correlation Policy (Explicit Only)
- **Same-subject co-occurrence** → `POSSIBLE_CONTEXT` (undirected)
- NO auto-correlation by: same IP, same ASN, same country, same org, same cert, co-occurrence, proximity
- Directed semantics preserved

## Entity Graph Integration
- EntityGraph uses same `EvidenceClass` and validation
- V1.5-5 does NOT auto-connect to EntityGraph
- Integration contract prepared: same evidence classes, provenance refs, deterministic ordering, defensive copies

## API
- `InvestigationEnrich(id)` — read-only, deterministic, bounded
- Returns `EnrichmentResult` with findings, correlations, evidence, entry mapping, stats
- Does NOT modify stored Investigation
- Does NOT execute providers or make network calls

## UI
- **Enriquecer investigación** button in investigation detail view
- Shows result summary using existing error display mechanism
- No alert/console.log — uses existing error display mechanism

## Tests
Backend:
- `TestEnrichInvestigation_Empty`
- `TestEnrichInvestigation_SingleEntry`
- `TestEnrichInvestigation_ProvenanceChainPreserved`
- `TestEnrichInvestigation_NoAutoCorrelation`
- `TestEnrichInvestigation_BoundsEnforced`
- `TestEnrichInvestigation_DeterministicOutput`
- `TestEnrichInvestigation_ZeroTimestampHandling`
- `TestEnrichInvestigation_NoMutation`
- `TestEnrichInvestigation_NoNetworkExecution`
- `TestEnrichInvestigation_ExplicitCorrelationOnly`
- API tests: empty, valid, nonexistent, corrupt, empty arrays serialize safely, stored investigation unchanged

Frontend:
- Types hand-declared (Finding, FindingEvidence, FindingCorrelation, EnrichmentStats)
- Graceful fallback when Wails binding not yet generated

## Scope Exclusions (NOT in this PR)
- External providers (Shodan, Censys, VirusTotal, SecurityTrails, AbuseIPDB, GreyNoise, OTX)
- Active scanner
- Investigation provider execution
- Internet Infrastructure (PeeringDB, TeleGeography, SubmarineCableMap)
- Updater, release/signing
- V1.5-6 work

BASE_SHA: 8b1d9edf2d88f4df6e58f0918609823b0294ac77
HEAD_SHA: c74faad