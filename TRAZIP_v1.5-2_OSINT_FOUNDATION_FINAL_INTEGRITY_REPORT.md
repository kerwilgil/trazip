# TRAZIP v1.5-2 — FINAL INTEGRITY REPORT

## Baseline
- previous HEAD: `ee22475928bb63557b84d351f9283b013d2ec331`
- final HEAD: `d9b0d7825836028fe53b45ec60c74124d13c747a`
- commits ahead of `main`: **3** — `81b35a0` (foundation), `ee22475` (execution safety invariants), `d9b0d78` (capability + provenance integrity)
- branch: `feature/v1.5-2-osint-foundation` — sin amend, sin force push, sin push a main; tercer commit añadido y pusheado normal.

---

## P1-04 — No fabricated "example" results
- **runtime ExampleProvider removed:** sí. `ExampleProvider` / `NewExampleProvider` eliminados de `internal/osint/passive/provider.go` y `internal/osint/active/provider.go`. Ambos paquetes son ahora **solo contrato**: el alias de tipo (`Provider = osint.PassiveRunner` / `= osint.ActiveRunner`) y las constantes de capability. Nada que construya un `Result`. `grep -rn "ExampleProvider" --include=*.go` en todo el repo → sin resultados.
- **fabricated success paths remaining:** ninguno. No hay provider productivo capaz de devolver éxito ficticio. Test `TestNoFabricatedDataInContractPackages` escanea el fuente de `passive/` y `active/` (no-test) y falla si aparece `NewProvenance(`, `"not implemented"` u `osint.Result{`.

---

## P1-05 — Central capability gate
- **central capability gate:** sí. `Executor.ExecutePassive` y `Executor.ExecuteActive` comprueban `requested capability ∈ ProviderMeta.Capabilities` **antes** de invocar `Lookup` / `Probe`. Para active, la comprobación ocurre **antes** del ScopeGuard — no se intenta ninguna interacción activa para una capability no declarada. Capability no declarada → `UnsupportedCapabilityError`, invocation count 0.
- **orden de validación fijo** (documentado en `executor.go`):
  `context → provider lookup → pipeline/activity → capability → active scope → invocation → provenance`.
  Antes del paso *invocation*, el código del provider **no** se ejecuta.
- **passive unsupported calls:** `TestExecutorPassiveUnsupportedCapability` — `IsUnsupportedCapability`, provider calls **0**.
- **active unsupported calls:**
  - con scope válido: `TestExecutorActiveUnsupportedCapabilityWithValidScope` — `IsUnsupportedCapability`, calls **0**.
  - sin guard: `TestExecutorActiveUnsupportedCapabilityNoGuard` — como la capability se valida antes que el scope, devuelve `IsUnsupportedCapability` (no `ScopeRequired`), calls **0**. El ScopeGuard nunca se consulta para una capability no declarada.

---

## P1-06 — Provenance must match execution exactly
`finalizeResult(res, meta, requestedCapability)` — sobre todo `Result` **exitoso** exige, además de `Provenance.Validate()`, igualdad exacta:

- **ProviderID match:** `Provenance.ProviderID == ProviderMeta.ID`
- **ProviderName match:** `Provenance.ProviderName == ProviderMeta.Name`
- **Capability match:** `Provenance.Capability == string(requestedCapability)`
- **ActivityClass match:** `Provenance.ActivityClass == ProviderMeta.ActivityClass`
- **DisclosureClass match:** `Provenance.DisclosureClass == ProviderMeta.DisclosureClass`

Cualquier discrepancia (aunque cada campo sea individualmente válido) → `InvalidProvenanceError` fail-closed, `Data == nil`, `IsOK() == false`.

- **mismatch tests:** `TestExecutorProvenanceMustMatchExecution` (tabla): `correct` → PASS; `provider id mismatch`, `provider name mismatch`, `capability mismatch`, `disclosure mismatch` → todos `IsInvalidProvenance`, `Data == nil`. `TestExecutorActiveProvenanceActivityMismatch` cubre `ActivityClass` para un provider activo. `TestExecutorRejectsSuccessWithoutProvenance` (provenance zero) y `TestExecutorRejectsProvenanceIdentityMismatch` siguen verdes. `TestExecutorPassesThroughPreExecutionFailure` confirma que un fallo previo a la ejecución (para una capability declarada) se propaga sin reclasificarse como error de provenance.

---

## P2
- **typed nil:** `Registry.Register` usa `isNilProvider(p)` — además del `p == nil` de interfaz, detecta un puntero typed-nil metido en la interfaz (`var x *T; Register(x)`) vía un `reflect.Value.Kind()` + `IsNil()` acotado (Pointer/Interface/Map/Slice/Chan/Func). Devuelve error, no panic. Test `TestRegistryRejectsTypedNilProvider` (interfaz nil + `*testActiveProvider` nil).
- **nil context:** `contextError(ctx)` — si `ctx == nil` devuelve `InvalidConfigError` (`IsInvalidConfig` true) en vez de dejar que `ctx.Err()` haga panic. Aplica a ambos pipelines antes de resolver el provider. Test `TestExecutorNilContextRejected` (passive + active, provider calls **0**).
- **PR body updated:** sí. El body de PR #16 se reescribió para reflejar el HEAD final `d9b0d78`, los tres commits, y las validaciones reales sobre ese HEAD. Ya no afirma que el estado validado es `81b35a0`.

---

## Tests
| Gate | Resultado |
|---|---|
| OSINT (`go test ./internal/osint/... -count=1`, context-tests también `-count=2/3`) | **PASS** |
| full Go (`go test ./... -count=1`) | **PASS** (todos los paquetes); también con la exclusión canónica de CI `-skip 'TestPingMonitorAgainstLoopback'`. Ese test pasa localmente en este host; CI lo salta porque necesita ICMP loopback que algunos runners deniegan — se usó `-skip` para paridad y además se confirmó el run sin `-skip` en verde aquí. |
| `go vet ./...` | **PASS** |
| `go build ./...` | **PASS** |
| frontend `npm ci` / `npm test` (30/30) / `npm run build` | **PASS** — frontend sin tocar |
| `govulncheck ./...` | **PASS** — 0 vulnerabilidades en código / imports |
| gitleaks (archivos nuevos + tocados, scan aislado) | **no leaks** |
| `git diff --cached --check` | limpio |
| `gofmt -l internal/osint/` | limpio |

---

## PR
- #: **16** (actualizado in-place — sin PR nuevo)
- HEAD: `d9b0d7825836028fe53b45ec60c74124d13c747a`
- state: OPEN
- mergeable: MERGEABLE · mergeStateStatus: **CLEAN**
- changed files: 18 (`+3953 / -0` vs `main`)
- CI run: **`34398526142`** — status `completed`, conclusion **success** — https://github.com/kerwilgil/trazip/actions/runs/34398526142

### 7 required checks
| Check | Status |
|---|---|
| Backend / Test | **SUCCESS** (56s) |
| Backend / Test (Windows) | **SUCCESS** (2m01s) |
| Backend / Test (macOS) | **SUCCESS** (1m19s) |
| Frontend / Build | **SUCCESS** (21s) |
| Security / Gitleaks | **SUCCESS** (19s) |
| Security / Govulncheck | **SUCCESS** (36s) |
| Security / SBOM | **SUCCESS** (1m02s) |

### builds
| Build | Status |
|---|---|
| Build / Linux | SKIPPED (esperado en PR) |
| Build / Windows | SKIPPED (esperado en PR) |
| Build / macOS | SKIPPED (esperado en PR) |

---

## Remaining
- **P0:** 0
- **P1:** 0
- **P2 / non-blocking:**
  - `-race` no ejecutable en este host (sin cgo / toolchain C); CI tampoco corre `-race`. `Registry` (RWMutex) y `Executor` (sin estado) revisados a mano.
  - Hallazgos históricos de `gitleaks` en commits antiguos (`bbf0be2`, `7e56fd4`, `KEY ID.txt`) — previos y ajenos a esta rama; el check `Security / Gitleaks` del PR pasa.
  - Warning de Vite "chunks > 500 kB" en el frontend — pre-existente, no introducido aquí.
  - `isNilProvider` usa `reflect` de forma acotada (kind switch + `IsNil`), solo en `Register` (arranque) — sin coste en caliente ni rediseño.
  - Los `.md` de informe en la raíz del repo (`TRAZIP_v1.5-1_...`, `..._RECOVERY_...`, `..._HARDENING_...`, este) quedan untracked y **no** forman parte del PR, por diseño.

---

## VERDICT

P0 = 0 · P1 = 0 · 7/7 required checks = **SUCCESS** (CI run `34398526142` → success).

**TRAZIP_V1_5_2_FINAL_REVIEW_PASS**
**READY_FOR_SQUASH_MERGE**

NO MERGEAR. STOP.
