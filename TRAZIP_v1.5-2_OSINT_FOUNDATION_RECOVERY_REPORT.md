# TRAZIP v1.5-2 — RECOVERY & VALIDATION REPORT

## TRAZIP v1.5-2 — RECOVERY SNAPSHOT

- current branch: `feature/v1.5-2-osint-foundation`
- HEAD (inicial): `6cae3b70ca81dadc27404851a9d6823c6f8d8f68` (== baseline canónico, == origin/main)
- origin/main: `6cae3b70ca81dadc27404851a9d6823c6f8d8f68`
- ahead/behind (inicial): 0 / 0
- modified files: ninguno (0 tracked modificados)
- untracked files: `internal/osint/` (14 archivos `.go`), `docs/OSINT_FOUNDATION.md`, `TRAZIP_v1.5-1_UPDATE_CHANNEL_MIGRATION_REPORT.md` (ajeno a esta fase)
- staged files: ninguno
- commits de V1.5-2 encontrados: 0
- remote branch existe: NO
- PR existe: NO
- clasificación: **A** (cambios de V1.5-2 presentes pero NO committed) con solapamiento **E** (parciales/defectuosos: el paquete no compilaba y 2 tests fallaban)

---

## Recovery

- **estado encontrado:** Nemotron dejó 15 archivos sin trackear (`internal/osint/**` + `docs/OSINT_FOUNDATION.md`). Sin commit, sin push, sin rama remota, sin PR. El paquete **no compilaba** (`model.go:7: "errors" imported and not used`) y, tras arreglar eso, **2 tests fallaban** (`TestLimiterDynamicRate`, `TestLimiterDynamicBurst`). Conclusión: nunca ejecutó `go build` ni `go test`.
- **trabajo de Nemotron reutilizado:** ~95%. Toda la arquitectura (modelos, contratos de provider + registry, separación passive/active en paquetes e interfaces separados, ScopeGuard fail-closed, provenance, disclosure, cache LRU+TTL acotada, rate limiter token-bucket, taxonomía de errores tipados, doc) se conservó tal cual.
- **trabajo descartado:** nada eliminado. Solo se corrigieron defectos puntuales y se reescribieron 2 tests que afirmaban un comportamiento que la implementación nunca tuvo.
- **problemas encontrados:**
  1. `model.go` no compilaba — import `errors` sin usar.
  2. `TestLimiterDynamicRate` / `TestLimiterDynamicBurst` asumían que `SetRate`/`SetBurst` fabrican tokens; token-bucket estándar no lo hace → fallo.
  3. `Limiter.Acquire`/`TryAcquire` leían `l.rate` fuera del mutex (carrera con `SetRate`).
  4. `MultiLimiter.TryAcquire`, al hacer rollback de un intento parcial, llamaba `l2.Reset()` → dejaba los limiters previos a **burst completo**, fabricando tokens que el llamante nunca tuvo.
  5. Los 14 archivos `.go` no estaban pasados por `gofmt`.
- **correcciones realizadas:**
  - `model.go`: eliminado el import `errors` sin usar.
  - `ratelimit.go`: `rate` se lee bajo mutex en `Acquire`/`TryAcquire`; `Acquire` además re-comprueba dentro del bucle y deja de bloquear si `rate` pasa a "ilimitado" (`<= 0`) mientras espera.
  - `ratelimit.go`: rollback de `MultiLimiter.TryAcquire` ahora reembolsa **1 token** por limiter ya adquirido (`refund()`), nunca `Reset()`.
  - `ratelimit_test.go`: reescritos `TestLimiterDynamicRate` y `TestLimiterDynamicBurst` para validar semántica real de token-bucket; añadido `TestMultiLimiterTryAcquireRollbackDoesNotManufactureTokens` (regresión del bug #4).
  - `gofmt -w` sobre todo `internal/osint/`.

---

## Baseline

- origin/main: `6cae3b70ca81dadc27404851a9d6823c6f8d8f68`
- branch: `feature/v1.5-2-osint-foundation`
- initial branch HEAD: `6cae3b70ca81dadc27404851a9d6823c6f8d8f68`
- final branch HEAD: `81b35a01eb4f8e88bccb9de1faace5934dbfd118`
- ahead/behind (final): 1 / 0 respecto de origin/main

---

## Architecture

- **provider contract:** `Provider` mínima (`Meta()` + `Execute(ctx, capability, input) Result`). Identidad estable e inmutable vía `ProviderMeta` (`ID`, `Name`, `Capabilities`, `ActivityClass`, `DisclosureClass`, `RequiresScope`, `RateLimit`). `context.Context` en toda operación con posible bloqueo. `Registry` thread-safe (RWMutex) con lookup por ID / capability / passive / active. Sin God-interface: `PassiveProvider` y `ActiveProvider` extienden `Provider` con métodos específicos.
- **passive/active:** separación **real** — interfaces distintas (`osint.PassiveProvider` / `osint.ActiveProvider`), **paquetes** distintos (`internal/osint/passive`, `internal/osint/active`), y `ActivityClass` tipado. `ProviderMeta.Validate()` es fail-closed cruzado: `ActivityActive && !RequiresScope` → error; `ActivityPassive && RequiresScope` → error. Un provider activo sin `ScopeGuard` devuelve `ScopeRequiredError` y no ejecuta.
- **ScopeGuard:** envuelve `internal/scope.Guard`. Fail-closed: sin scope declarado → `ScopeRequiredError`; scope vacío → `Authorize` falla; target fuera de scope → `ScopeDeniedError`; ambos envuelven `ErrScopeDenied`. `RequireTarget()` combina "hay scope" + "target dentro". No hay recon activo automático (no hay init, no hay workers).
- **disclosure:** `DisclosureClass` tipado — `DisclosureLocal` / `DisclosurePassive` / `DisclosureActive` (+ sentinela `DisclosureUnknown` inválido). `IsValid()` rechaza el sentinela.
- **provenance:** `Provenance` (struct por valor, sin setters) con `ProviderID`, `ProviderName`, `Capability`, `ActivityClass`, `DisclosureClass`, `RetrievedAt` (RFC3339), `Endpoint` saneado, `Confidence`, y el sobre `external.Disclosure`. `NewProvenance()` la sella en creación. Todo `Result` la lleva obligatoriamente.
- **cache:** `container/list` + mapa, un solo `sync.Mutex`. Acotada (`maxSize`, default 500; `<= 0` → default, nunca 0). TTL: entrada expirada = MISS y se desaloja al instante (nunca sirve stale). Desalojo LRU al llegar a capacidad con clave nueva (sin off-by-one: evict→insert deja `len == maxSize`). `WithClock()` para tests deterministas. Sin goroutine de fondo, sin polling.
- **limiter:** token-bucket, `sync.Mutex`, sin goroutines de fondo (refill por tiempo transcurrido en cada llamada). `Acquire(ctx)` cancelable (`select` sobre `ctx.Done()` / `time.After`), sin busy-loop. `rate <= 0` = ilimitado. `TryAcquire()` no bloqueante. `MultiLimiter` = todos o ninguno, con rollback correcto.
- **cancellation:** `context.Context` propagado en `Provider.Execute` y `Limiter.Acquire`. `IsCanceled` / `IsDeadlineExceeded` detectan tanto los sentinelas propios como `context.Canceled` / `context.DeadlineExceeded` envueltos. No se ocultan errores de contexto.
- **typed errors:** 11 sentinelas + wrappers concretos con `Unwrap()` → `errors.Is` y `errors.As` funcionan. Helpers `IsInvalidConfig` / `IsUnsupportedCapability` / `IsScopeDenied` / `IsRateLimited` / `IsProviderUnavailable` / `IsExternalLookupFailed` / `IsCanceled` / `IsDeadlineExceeded` / `IsRetryable` / `IsPermanent`.

---

## Tests

- **OSINT tests:** `go test ./internal/osint/... -count=1` → **PASS** (paquete `trazip/internal/osint` ok; `active` y `passive` sin tests propios — solo skeletons de referencia).
- **full Go:** `go test ./... -count=1 -skip 'TestPingMonitorAgainstLoopback'` (igual que CI) → **PASS** en los 64 paquetes con tests.
- **go vet:** `go vet ./...` → **PASS**.
- **frontend tests:** `npm test` (vitest) → **PASS**, 30/30 en 3 archivos. Frontend sin cambios.
- **frontend build:** `npm ci` + `npm run build` (`tsc && vite build`) → **PASS**. Warning pre-existente de chunk > 500 kB (no bloqueante).
- **govulncheck:** `govulncheck ./...` → **0 vulnerabilidades** en código y en paquetes importados (5 en módulos requeridos pero no alcanzados por el código — estado pre-existente).
- **gitleaks:** scan aislado de los archivos nuevos (`internal/osint/**` + `docs/OSINT_FOUNDATION.md`) → **no leaks**. `Security / Gitleaks` y `gitleaks` en el PR → **PASS**. (Hallazgos históricos en commits `bbf0be2` y `7e56fd4` son previos y ajenos a esta rama.)
- **git diff --check:** `git diff --cached --check` → limpio (sin whitespace errors, sin conflict markers).
- **-race:** no ejecutable en este host (falta cgo/toolchain C). CI tampoco usa `-race`. Rutas de concurrencia revisadas a mano (ver Deep Review).

Cobertura frente a la matriz A–N del doc: A metadata (`TestProviderMetaValidate`, `TestProviderMetaValidation`, `TestRegistryInvalidMeta`) · B passive/active (paquetes + `TestPassive/ActiveProviderRequiresScope*`, `TestProviderCapabilities`) · C ScopeGuard fail-closed (`TestScopeGuardFailClosed`) · D out-of-scope (`TestScopeGuardCheckTarget`, `TestActiveProviderExecution`) · E synthetic active autorizado (`TestActiveProviderExecution`, `TestScopeGuardRequireTarget`) · F provenance (`TestProvenanceCreation`, asserts en `TestPassive/ActiveProviderExecution`) · G/H/I cache (`TestCacheCapacityAndEviction`, `TestCacheLRUOrder`, `TestCacheTTLExpiry`, `TestCacheWithClock`) · J limiter cancel (`TestLimiterContextCancellation`, `TestLimiterDeadline`) · K context (idem + firmas `Execute(ctx,…)`) · L typed errors (`errors_test.go` completo con `errors.Is`) · M disclosure (`TestDisclosureClass`, asserts de `DisclosureClass` en execution) · N sin Internet (todo con providers sintéticos; sin `net/http` ni `net.Dial` en el paquete). Los tests reescritos ya no son tautológicos: comprueban tiempos reales de espera y conteos reales de tokens.

---

## Scope

- **real providers:** NO — solo contratos + `ExampleProvider` skeletons no funcionales (`Data: "not implemented"`).
- **active scanner:** NO — solo interfaz `ActiveProvider` y skeleton que exige ScopeGuard.
- **frontend feature:** NO — frontend sin tocar (0 archivos).
- **update/release touched:** NO — `internal/update/`, `dist/`, `update.json`, `update.json.sig` sin cambios (verificado con `git status`).
- **signing touched:** NO — sin cambios en infraestructura de firma ni en `cmd/trazip-sign`. `kerwilgil/trazip-releases` sin tocar.

---

## Git

- **files changed:** 15 (todos nuevos, `+3044 / -0`): 6 `.go` de dominio + 6 `_test.go` + 2 `provider.go` (passive/active) + `docs/OSINT_FOUNDATION.md`.
- **commits encontrados:** 0 (Nemotron no hizo commit).
- **commits nuevos:** 1 — `81b35a0` `feat: complete OSINT intelligence foundation`.
- **push:** hecho — `origin/feature/v1.5-2-osint-foundation` = `81b35a0`. Push normal (sin `--force`).
- **worktree:** limpio salvo `TRAZIP_v1.5-1_UPDATE_CHANNEL_MIGRATION_REPORT.md` (untracked, pertenece a la fase v1.5-1 — **deliberadamente NO incluido** en este commit) y este propio informe.

---

## PR

- **number:** #16
- **state:** OPEN
- **head:** `81b35a01eb4f8e88bccb9de1faace5934dbfd118`
- **base:** `main`
- **mergeable:** MERGEABLE (`mergeStateStatus: CLEAN`)
- **changed files:** 15 (`+3044 / -0`)
- URL: https://github.com/kerwilgil/trazip/pull/16

---

## CI

- **run:** `34382122884` — status `completed`, conclusion **success** — https://github.com/kerwilgil/trazip/actions/runs/34382122884
- **Backend / Test:** PASS (1m10s)
- **Backend / Test (Windows):** PASS (3m06s)
- **Backend / Test (macOS):** PASS (1m28s)
- **Frontend / Build:** PASS (16s)
- **Security / Gitleaks:** PASS (18s) — (+ check `gitleaks` app: PASS)
- **Security / Govulncheck:** PASS (28s)
- **Security / SBOM:** PASS (1m12s)
- **Build / Linux:** SKIPPED (no PR — no es PASS)
- **Build / Windows:** SKIPPED (no PR — no es PASS)
- **Build / macOS:** SKIPPED (no PR — no es PASS)

Todos los required checks reales en SUCCESS. Los `Build / *` están SKIPPED por diseño en PRs.

---

## Deep Review Final (revisión manual)

- **data races:** rutas de `Limiter` corregidas (lectura de `rate` bajo mutex). `Cache` con mutex único consistente. `Registry` con RWMutex. `ScopeGuard` delega en `scope.Guard` (RWMutex propio). Sin estado global mutable. `-race` no ejecutable localmente (sin cgo); CI tampoco lo corre.
- **cache capacity off-by-one:** no — evict-then-insert deja exactamente `maxSize`; update de clave existente no crece. `NewCache(0)`/negativo → default 500, nunca 0.
- **TTL boundary:** `!now.Before(expiresAt)` → expira exactamente en `expiresAt` (borde exclusivo), consistente. `ttl=0` = no cachea de facto.
- **nil context:** la interfaz exige `ctx`; los skeletons y tests pasan `context.Background()`. Sin `context.TODO()` mal usado.
- **limiter deadlocks:** lock/unlock siempre emparejados, nunca se mantiene el lock a través de `select`/`time.After`. `SetRate(0)` durante `Acquire` ya no cuelga (re-check dentro del bucle).
- **channel/goroutine leaks:** el paquete no lanza goroutines (verificado: sin `go ` ni `func init(` en código no-test). `time.After` abandonado se recolecta (Go 1.26).
- **errors mal envueltos:** todos los wrappers tienen `Unwrap()` al sentinela; `ScopeRequiredError`→`ErrScopeDenied`; `errors.Join` en tests funciona con `Is`.
- **ScopeGuard bypass / empty scope / wildcard:** doble fail-closed (wrapper + `scope.Guard`). `Authorize([])` falla. Sin soporte de wildcard implícito; `/0` solo si el operador lo declara explícitamente.
- **passive marcado active / active sin guard:** `ProviderMeta.Validate()` lo impide; skeleton activo con guard `nil` → `ScopeRequiredError`.
- **provenance mutable:** `Provenance` es struct por valor sin punteros/slices/maps y sin setters — inmutable en la práctica.
- **timestamps no deterministas:** `Cache` usa reloj inyectable en tests; los tests de TTL con `time.Sleep` usan márgenes amplios (patrón ya usado en el repo).
- **slices/maps sin acotar / retry loops / tráfico externo silencioso:** cache acotada; mapas de `Registry` acotados por nº de providers (fijo en arranque); ningún retry real en la fundación; sin `net/http`/`net.Dial`/DNS ni `init()` en el paquete.

---

## Remaining Issues

- **P0:** ninguno.
- **P1:** ninguno.
- **P2 (hardening futuro, no bloqueante):**
  - `ProviderMeta.Capabilities` es un slice compartido con el valor devuelto por `Meta()`; un consumidor podría mutarlo. Clonar al devolver cuando lleguen providers reales (V1.5-3).
  - `internal/scope.Guard.Authorize` acepta una entrada no parseable como scope de host (comportamiento pre-existente de `internal/scope`, con sus propios tests; no es código OSINT). El fail-closed frente a targets reales se mantiene.
  - `docs/OSINT_FOUNDATION.md` menciona helpers `AsXxx` que no existen (solo `IsXxx`); `errors.As` funciona igualmente vía los tipos wrapper concretos. Nota cosmética de doc.
- **non-blocking:**
  - `-race` no verificable en este host (sin toolchain C); CI tampoco lo ejecuta.
  - Hallazgos de `gitleaks` en el historial (`bbf0be2`, `7e56fd4`, `KEY ID.txt`) — pre-existentes, ajenos a esta rama; el gitleaks del PR pasa.
  - Warning de Vite "chunks > 500 kB" — pre-existente en el frontend.
  - `TRAZIP_v1.5-1_UPDATE_CHANNEL_MIGRATION_REPORT.md` queda untracked en el worktree (fase v1.5-1) — no incluido a propósito.

---

## VERDICT

**TRAZIP_V1_5_2_OSINT_FOUNDATION_PASS**
**READY_FOR_REVIEW**

Sin P0/P1. Todas las validaciones obligatorias reales pasan (build, `go test ./...`, `go vet`, frontend ci/test/build, govulncheck, gitleaks, `git diff --check`) y el run de CI del PR #16 concluyó en `success`. No se inicia V1.5-3. No se mergea desde aquí — queda para revisión humana.
