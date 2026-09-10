# TRAZIP OSINT Entity Graph (V1.5-4)

## Purpose

V1.5-4 adds an **Entity Graph** visualization to the OSINT Intelligence workspace.
It renders explicit entity relationships as a deterministic graph — no inference,
no fabricated data, no external providers.

The graph visualizes entities (IP, Domain, ASN, Certificate, CVE, Organization,
URL, Country) and their directed/undirected relationships, each tagged with an
evidence class:

- **Observed** — directly backed by provenance/evidence.
- **Possible context** — plausible investigative context, NOT proven.
- **Not proven** — shown only as not proven.

No automatic promotion between evidence classes ever occurs.

---

## Architecture

```
internal/osint/
├── model.go           # EvidenceClass, Entity, EntityRelation
├── entitygraph.go     # EntityGraph builder with bounds & validation
├── entitygraph_test.go
└── ...

frontend/src/lib/
├── entityGraph.ts     # Pure view-model: types, layout, filters, zoom
├── entityGraph.test.ts
└── ...

frontend/src/views/
└── OsintIntelligence.tsx  # Entity Graph section integrated
```

---

## Model

### EvidenceClass (Go)

```go
type EvidenceClass int

const (
    EvidenceUnknown EvidenceClass = iota
    EvidenceObserved
    EvidencePossibleContext
    EvidenceNotProven
)
```

- `String()` → `"observed" | "possible_context" | "not_proven" | "unknown"`
- `IsValid()` enforces defined range.

### EntityKind (Go / TypeScript)

Extensible identifier:
`ip | domain | asn | certificate | cve | organization | url | country | unknown`

### Entity (Go / TypeScript)

```go
type Entity struct {
    ID         string
    Kind       EntityKind
    Label      string
    Value      string
    Attributes map[string]string
}
```

Validation: non-empty ID, kind, label, value. Defensive copy on clone.

### EntityRelation (Go / TypeScript)

```go
type EntityRelation struct {
    ID            string
    From          string
    To            string
    Kind          string
    Directed      bool
    EvidenceClass EvidenceClass
    ProvenanceRef string
    Label         string
}
```

Validation: non-empty ID, from, to, kind; valid evidence class. No dangling edges.

---

## EntityGraph (Go)

### Bounds

```go
const (
    DefaultMaxEntities  = 500
    DefaultMaxRelations = 1000
)
```

`NewEntityGraphWithBounds(maxEntities, maxRelations)` for custom limits.

Tests enforce: rejection at limit, no growth beyond limit.

### Operations

| Method | Description |
|--------|-------------|
| `AddEntity(Entity) error` | Idempotent if identical; rejects conflicting duplicate |
| `AddRelation(EntityRelation) error` | Validates from/to exist, no duplicate key, evidence class valid, **OBSERVED requires non-empty ProvenanceRef** |
| `Entity(id) (Entity, bool)` | Returns clone |
| `Relation(id, from, to, kind) (EntityRelation, bool)` | Returns clone |
| `Entities() []Entity` | Deterministic (sorted by ID) |
| `Relations() []EntityRelation` | Deterministic (sorted by from→to→kind→ID) |
| `EntitiesByKind(kind) []Entity` | Filtered + sorted |
| `RelationsByEvidenceClass(ec) []EntityRelation` | Filtered + sorted |
| `Neighbors(id) []Entity` | Incoming + outgoing, deduped, sorted |
| `Outgoing(id) []EntityRelation` | Sorted |
| `Incoming(id) []EntityRelation` | Sorted |
| `EntityCount() int` / `RelationCount() int` | |

### Duplicate Policy

- Same ID, identical content → no-op (idempotent).
- Same ID, different content → **error** (no silent overwrite).
- Relation key = `from\x00to\x00kind\x00id` → duplicate rejected. **ID tiebreaker ensures total ordering and uniqueness for parallel edges with same from/to/kind.**

### Dangling Edge Policy

`AddRelation` requires both `from` and `to` entities to exist. Missing → error.

### Self-Edges

Allowed if explicitly added (e.g., reflexive relations). Not created automatically.

### Thread Safety

`sync.RWMutex` guards all mutations. Safe for concurrent registration/lookup.

### No Background Activity

No goroutines, no polling, no background workers.

---

## Frontend View-Model (entityGraph.ts)

### Types

- `OsintEntity`, `OsintRelation` — normalized from backend DTOs.
- `OsintEvidenceClass`, `OsintEntityKind` — string unions matching Go.
- `EntityGraphLayout` / `EntityLayoutNode` — deterministic coordinates.
- `EntityGraphViewBox` — zoom/pan viewport.
- `EntityGraphFilters` — entity kinds + evidence classes.
- `EntityGraphSelection` — selected entity/relation ID.

### Layout Algorithm

Deterministic layered layout using **only explicit directed relations**:

1. Build adjacency + indegree from directed edges only.
2. Topological level assignment (BFS from sources).
3. Cycles → level 0 (deterministic seed).
4. Within level: sort by degree (desc), place in centered grid.
5. Undirected edges do not create levels.
6. **Same input → same coordinates** (tested).

### Edge Rendering

- `entityEdgeEndpoints`: computes start/end on node rectangle.
- `entityEdgeCurve`: light Bézier with deterministic lane offset.
- `entityEdgeLaneOffsets`: stable fan-out/in separation by sorted endpoints.
- Evidence class → edge style:
  - `observed` → solid
  - `possible_context` → dashed
  - `not_proven` → dotted

### Zoom / ViewBox

```ts
ENTITY_GRAPH_MIN_ZOOM = 0.3
ENTITY_GRAPH_MAX_ZOOM = 3
ENTITY_GRAPH_ZOOM_STEP = 0.25
```

`entityGraphViewBox` centers zoom on layout centre. `fitEntityGraphViewBox` auto-fits container.

### Filters

```ts
filterEntities(entities, filters)
filterRelations(relations, filters, entitySet)
```

Both pure, deterministic, testable.

### Empty State

Zero entities → centered `∅` with message:

> "No hay entidades OSINT para visualizar todavía."

No fake/demo data ever rendered.

---

## Integration (OsintIntelligence.tsx)

New section **after** "Errores contemplados":

- Header: "Grafo de entidades" + description.
- Filter bar: entity kind multi-select, evidence class multi-select, reset button.
- SVG canvas (420px height) with:
  - Zoom controls (− / % / + / ⌂ Fit).
  - Mouse wheel + Ctrl/Meta to zoom.
  - Click canvas to clear selection.
  - Edges with evidence-style strokes, arrowheads for directed.
  - Nodes as rounded rects with kind label, value, ID.
  - Selection highlights (entity/relation) + detail panel.
- Empty state when no entities.

### Accessibility

- Canvas: `role="img"` + `aria-label` (empty state message or "Grafo de entidades OSINT").
- Nodes/edges: `tabIndex={0}`, `role="button"`, `aria-label` with full description.
- Selection state: `aria-pressed`.
- Meaning not color-only (text + patterns + aria-label).

### Themes

Inherits CSS custom properties (`--surface-2`, `--surface-3`, `--border`, `--text`, `--text-dim`, `--text-faint`, `--accent`, `--accent-bg`). Works in Light / Dark / System.

### i18n

All visible strings use `t()` with ES source + EN translations in `frontend/src/lib/i18n.tsx`.

---

## Evidence Semantics (Hard Rules)

| Class | Label (ES) | Label (EN) | Meaning |
|-------|------------|------------|---------|
| `observed` | Observado | Observed | Directly backed by provenance/evidence. |
| `possible_context` | Contexto posible | Possible context | Plausible investigative context, NOT proven. |
| `not_proven` | No demostrado | Not proven | Shown only as not proven. |

**NEVER** auto-promote:
- `possible_context` → `observed`
- `not_proven` → `possible_context` / `observed`

Classification comes **explicitly from the input**.

---

## Provenance

`EvidenceObserved` relations **MUST** carry a non-empty `ProvenanceRef` linking to a real
`osint.Provenance` (provider, capability, retrievedAt, endpoint, confidence).
**Absence of ProvenanceRef for OBSERVED is a validation error — the relation is rejected at `AddRelation` time (fail-closed).**
`EvidencePossibleContext` and `EvidenceNotProven` do not require a provenance reference.
UI never presents an OBSERVED relation without provenance as a valid runtime state.

No fake timestamps, no fabricated provenance.

---

## Runtime Data

**V1.5-4 ships with empty Entity Graph.** No real OSINT providers exist yet.
The graph shows the empty state. When providers are added in future versions,
they will populate the graph via explicit DTOs — never via inference.

---

## No Providers / No Execution / No External Calls

| Feature | Status |
|---------|--------|
| Real providers (crt.sh, NVD, Shodan, …) | ❌ Not in V1.5-4 |
| Execution API (`ExecuteOSINT`) | ❌ Not added |
| Active scanning | ❌ Not added |
| Submarine cables / PeeringDB | ❌ Not added |
| Investigation integration | ❌ V1.5-5+ |

---

## Tests

### Backend (Go)

- `TestEntityGraph_Empty`
- `TestEntityGraph_AddEntity` (valid, invalid, idempotent, conflicting)
- `TestEntityGraph_AddRelation` (valid, invalid, missing from/to, duplicate)
- `TestEntityGraph_DeterministicOrdering`
- `TestEntityGraph_EntitiesByKind`
- `TestEntityGraph_RelationsByEvidenceClass`
- `TestEntityGraph_Neighbors` / `Outgoing` / `Incoming`
- `TestEntityGraph_EntityBoundEnforced`
- `TestEntityGraph_RelationBoundEnforced`
- `TestEntityGraph_NoMutationThroughRetainedSlices`
- `TestEntityGraph_EvidenceClassBehavior` (no auto-promotion)
- `TestEntityGraph_SelfEdgeAllowed`
- `TestEntityGraph_AttributesDeepCopy`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentContent`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentFrom`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentTo`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentKind`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentEvidenceClass`
- `TestEntityGraph_RelationID_ConflictSameIDDifferentProvenance`
- `TestEntityGraph_OBSERVED_RequiresProvenanceRef`
- `TestEntityGraph_EvidenceUnknown_Rejected`

### Frontend (Vitest)

- `clampEntityGraphZoom` / `entityGraphViewBox` / `fitEntityGraphViewBox`
- Evidence descriptors completeness + edge styles
- Entity kind descriptors completeness
- `asEvidenceClass` / `asEntityKind` mapping
- `normalizeEntity` / `normalizeRelation` defaults
- `sortEntities` / `sortRelations` determinism (includes ID tiebreaker)
- `buildEntityGraphLayout`:
  - Deterministic coordinates
  - Missing endpoints / self-loops ignored
  - Directed edges create levels
  - Undirected edges no levels
  - Minimum canvas size
- `entityEdgeEndpoints` (identical nodes, edge centers)
- `entityEdgeLaneOffsets` stable fan-out/in (uses relation ID in keys)
- `filterEntities` / `filterRelations` (kind, evidence class, dangling)
- `sortRelations` permutation determinism with ID tiebreaker
- Parallel edges with same from/to/kind different IDs → distinct lane offsets
- Filter integration alters derived render dataset
- Fit uses `fitEntityGraphViewBox` and remains bounded
- Entity selection resolves kind, value, ID, attributes, associated relations
- Relation selection resolves evidence class, provenance ref
- OBSERVED without provenance never presented as valid state
- Empty runtime graph shows only empty state
- No demo/fake nodes/edges in runtime

---

## Validation Gates

```bash
# Go
gofmt -l internal/osint/...
go test ./internal/osint/... -count=1
go test ./... -count=1
go vet ./...
go build ./...

# Frontend
cd frontend && npm ci && npm test && npm run build

# Security
govulncheck ./...
gitleaks detect --source .
git diff --check
```

All gates pass with **0 vulnerabilities**, **0 new leaks**, **0 diff errors**.

---

## Visual QA (Manual)

| Scenario | Result |
|----------|--------|
| Empty graph | ✅ Shows centered ∅ + message |
| Light theme | ✅ Inherits tokens |
| Dark theme | ✅ Inherits tokens |
| ES locale | ✅ All strings localized |
| EN locale | ✅ All strings localized |
| Zoom in/out/fit | ✅ Bounded, centered |
| Node selection | ✅ Highlights + detail panel |
| Edge selection | ✅ Highlights + detail panel |
| Evidence class styles | ✅ Solid / dashed / dotted |
| Filters | ✅ Kind + evidence class |
| Desktop viewport | ✅ No horizontal overflow |
| Narrow viewport | ⚠️ Not executed (pending) |

---

## Files Added / Modified

| File | Status |
|------|--------|
| `internal/osint/model.go` | Modified (EvidenceClass, Entity, EntityRelation, Result restored) |
| `internal/osint/entitygraph.go` | **Added** |
| `internal/osint/entitygraph_test.go` | **Added** |
| `frontend/src/lib/entityGraph.ts` | **Added** |
| `frontend/src/lib/entityGraph.test.ts` | **Added** |
| `frontend/src/views/OsintIntelligence.tsx` | Modified (Entity Graph section) |
| `frontend/src/lib/i18n.tsx` | Modified (ES/EN strings) |
| `docs/OSINT_ENTITY_GRAPH.md` | **Added** |

---

## Deferred (Not in V1.5-4)

- Narrow viewport physical QA
- MultiLimiter.Acquire rollback (P2 from V1.5-3)
- v1.4 → v1.5 physical bridge
- `trazip-releases` retirement
- Real providers / execution API / active scanning / cables / investigation integration

---

## Verdict

**TRAZIP_V1_5_4_ENTITY_GRAPH_PASS**  
**READY_FOR_REVIEW**

NO MERGE.  
NO V1.5-5.