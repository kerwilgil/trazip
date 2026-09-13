# TRAZIP v1.5-2 — FINAL RATE LIMITER HARDENING REPORT

## Baseline
- previous HEAD: `d9b0d7825836028fe53b45ec60c74124d13c747a`
- new HEAD: `7c16bb4ad02b26d4bd8f6f43de65986340931eba`
- commits ahead of `main`: **4** — `81b35a0` (foundation), `ee22475` (execution safety), `d9b0d78` (capability + provenance integrity), `7c16bb4` (dynamic rate limiting)
- branch: `feature/v1.5-2-osint-foundation` — sin amend, sin force, sin push a main; cuarto commit añadido y pusheado normal; PR #16 actualizado in-place.

---

## P1-07 — Dynamic rate change wakes Acquire

- **waiter wake mechanism:** `Limiter` mantiene un `reconfig chan struct{}`. `Acquire`, bajo mutex, hace `refillLocked()`, decide esperar, **captura `reconfig := l.reconfig`** y libera el mutex; luego `timer := time.NewTimer(wait)` y `select` sobre:
  - `ctx.Done()` → `timer.Stop()`, devuelve `ctx.Err()`
  - `timer.C` → reintenta
  - `reconfig` → `if !timer.Stop() { <-timer.C }` (Stop + drain), recalcula contra la nueva configuración
  `SetRate` / `SetBurst` / `Reset`, bajo el mismo mutex, hacen `close(l.reconfig); l.reconfig = make(chan struct{})`. El canal capturado por el waiter es exactamente el que se cierra → sin wakeup perdido, sin doble-close (cada canal se cierra una vez bajo el mutex).
- **SetRate(0) wakes waiter:** sí. `TestSetRateToUnlimitedWakesWaitingAcquire` — limiter a ~1000 s/token, burst consumido, `Acquire` en goroutine, se comprueba que sigue esperando 50 ms, `SetRate(0)` → `Acquire` retorna `nil` en < 2 s (safety timeout corto; no se esperan segundos reales).
- **SetRate increase recalculates:** sí. `TestSetRateIncreaseWakesAndRecalculates` — waiter bajo rate ~100 s/token, `SetRate(1000)` → el waiter despierta, recalcula un `wait` de ~1 ms y completa en < 2 s desde el cambio (no espera el timer viejo).
- **old-rate elapsed accounting:** ver P1-07B.
- **cancellation:** preservada. `TestSetRateContextCancellationStillWins` — `cancel()` desbloquea el `Acquire` en espera y devuelve `IsCanceled(err) == true`; el timer se `Stop`ea, sin goroutine colgada. Además `Acquire` comprueba `ctx.Err()` al inicio de cada iteración.
- **goroutine/background workers:** ninguno. No se lanza ninguna goroutine en `ratelimit.go`. Sin polling, sin busy-loop (tras un wake por reconfigure el waiter recalcula; la frecuencia de wakes es la de `SetRate`, no un spin). Timers `Stop`/drenados en el camino de wake temprano.

---

## P1-07B — Rate accounting across SetRate
- `SetRate` y `SetBurst` llaman `refillLocked()` **antes** de mutar: acreditan el intervalo transcurrido desde el último accounting a la tasa **vigente en ese momento** y avanzan `lastRefill`. Un aumento de tasa posterior ya no puede acreditar retroactivamente el intervalo anterior.
- `refillLocked()` omite la aritmética de tokens mientras `rate <= 0` (unlimited) — solo avanza `lastRefill` — así un retorno a tasa finita no acredita el intervalo "ilimitado".
- Reloj inyectable `now func() time.Time` + `WithClock(fn) (restore func())` para tests deterministas sin sleeps.
- **old-rate elapsed accounting (test):** `TestRateChangeUsesOldRateForElapsedInterval` — reloj congelado, `NewLimiter(1, 50)` (1 tok/s, burst 50), bucket drenado, se avanza el reloj 2 s, `SetRate(100)`. Resultado: `Tokens() ≈ 2` (2 s × tasa vieja 1/s), `> 3` falla; con el bug (2 s × 100/s → 50) el test rompe. Además comprueba que tras el cambio la tasa **nueva** sí aplica hacia delante (+0,5 s × 100/s → satura a 50).

---

## P1-08 — Invalid / duplicate capabilities
`ProviderMeta.Validate()` valida ahora cada elemento de `Capabilities`, además de `len > 0`:
- **CapabilityUnknown rejected:** sí (`c == CapabilityUnknown`).
- **empty capability rejected:** sí (`Capability("")` es `CapabilityUnknown`).
- **duplicates rejected:** sí (set `seen`; segundo elemento igual → `InvalidConfigError`).
- **extensible custom capability accepted:** sí — `Capability("vendor.custom.thing")` pasa. La regla es **non-empty + unique**, NO una whitelist de las constantes actuales.
- Un provider con capability set inválido **no puede registrarse** (`Registry.Register` valida el meta), luego nunca alcanza `Lookup` / `Probe`.

Tests:
- `model_test.go` / `TestProviderMetaValidate` (tabla): `passive + CapabilityUnknown` → reject; `empty-string capability` → reject; `active + CapabilityUnknown` → reject; `duplicate capability` → reject; `multiple unique capabilities` → PASS; `custom extensible capability` → PASS.
- `executor_integrity_test.go`:
  - `TestRegistryRejectsInvalidCapabilitiesAndProviderNeverRuns` — passive unknown / active unknown / duplicate → `Register` falla con `IsInvalidConfig`; ninguno registrado ⇒ `Executor` no los alcanza; `calls == 0` en los tres (provider con metadata inválida ni siquiera se registra).
  - `TestRegistryAcceptsMultipleUniqueCapabilities` — provider con `{RDAP, ASNMapping}` se registra y cada capability declarada ejecuta; una no declarada sigue `UnsupportedCapability`.

---

## Tests
| Gate | Resultado |
|---|---|
| focused x10 (`go test ./internal/osint/... -run 'SetRate|Capability' -count=10`) | **PASS** (también `-run 'Limiter|Rate|Multi|SetRate' -count=10` en verde) |
| OSINT (`go test ./internal/osint/... -count=1`) | **PASS** |
| full Go (`go test ./... -count=1`) | **PASS** (todos los paquetes); también con la exclusión canónica de CI `-skip 'TestPingMonitorAgainstLoopback'` — ese test necesita ICMP loopback que algunos runners deniegan; pasa localmente aquí |
| `go vet ./...` | **PASS** |
| `go build ./...` | **PASS** |
| frontend `npm ci` / `npm test` (30/30) / `npm run build` | **PASS** — frontend sin tocar |
| `govulncheck ./...` | **PASS** — 0 vulnerabilidades en código / imports |
| gitleaks (nuevos + tocados, scan aislado) | **no leaks** |
| `git diff --cached --check` · `gofmt -l internal/osint/` | limpio |

---

## PR
- number: **16** (actualizado in-place — sin PR nuevo)
- HEAD: `7c16bb4ad02b26d4bd8f6f43de65986340931eba`
- state: OPEN
- mergeable: MERGEABLE · mergeStateStatus: **CLEAN**
- changed files: 18 (`+4278 / -0` vs `main`)
- CI run: **`34414647409`** — status `completed`, conclusion **success** — https://github.com/kerwilgil/trazip/actions/runs/34414647409

### 7 required
| Check | Status |
|---|---|
| Backend / Test | **SUCCESS** (1m06s) |
| Backend / Test (Windows) | **SUCCESS** (2m09s) |
| Backend / Test (macOS) | **SUCCESS** (1m21s) |
| Frontend / Build | **SUCCESS** (19s) |
| Security / Gitleaks | **SUCCESS** (16s) |
| Security / Govulncheck | **SUCCESS** (37s) |
| Security / SBOM | **SUCCESS** (1m03s) |

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
  - `-race` no ejecutable en este host (sin cgo / toolchain C); CI tampoco corre `-race`. `Limiter` (un solo `sync.Mutex`, canal `reconfig` capturado/cerrado bajo el mutex), `Registry` (RWMutex) y `Executor` (sin estado) revisados a mano.
  - `Limiter.Acquire(nil)` llamado **directamente** con `ctx == nil` haría panic en `ctx.Err()` — como cualquier uso de `context`; el gate (`Executor`) ya rechaza `ctx` nil antes de llegar al limiter (P2 previo). No en scope de esta ronda.
  - Hallazgos históricos de `gitleaks` en commits antiguos (`bbf0be2`, `7e56fd4`) — previos y ajenos a la rama; el check del PR pasa.
  - Warning de Vite "chunks > 500 kB" en el frontend — pre-existente.
  - Los `.md` de informe en la raíz del repo quedan untracked y **no** forman parte del PR, por diseño.

---

## VERDICT

P0 = 0 · P1 = 0 · 7/7 required checks = **SUCCESS** (CI run `34414647409` → success).

**TRAZIP_V1_5_2_RELEASE_GATE_PASS**
**READY_FOR_SQUASH_MERGE**

NO MERGEAR. STOP.
