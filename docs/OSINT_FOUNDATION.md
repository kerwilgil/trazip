# TRAZIP OSINT Intelligence Foundation (V1.5-2)

## Purpose

This document describes the **OSINT Intelligence Foundation** introduced in TRAZIP v1.5-2.

**V1.5-2 is foundation only.** It provides:
- Architectural contracts for OSINT providers
- Hard separation between passive and active operations
- Scope Guard integration for active operations
- Provenance tracking on every result
- Bounded caches and rate limiters
- Context-aware cancellation
- Typed error taxonomy

**V1.5-2 does NOT include:**
- Real provider implementations (RDAP, CVE, CT, ASN, etc.)
- Active scanners (port scan, traceroute, service detection)
- OSINT UI / dashboards
- Entity graph visualization
- Investigation enrichment
- Submarine cable mapping
- PeeringDB / Censys / Shodan / VirusTotal integrations
- Any release artifacts

Those belong to V1.5-3 and beyond.

---

## Architecture Overview

```
internal/osint/
├── model.go           # ActivityClass, DisclosureClass, Provenance (+Validate), ProviderMeta (+Validate), Result
├── errors.go          # Typed error taxonomy: sentinels + wrapper types with Unwrap, IsXxx predicates
├── provider.go        # Provider (identity only), PassiveRunner / ActiveRunner, Registry (metadata lookup), BaseProvider
├── executor.go        # Executor — the central execution gate (ExecutePassive / ExecuteActive)
├── cache.go           # Bounded LRU+TTL cache (thread-safe, no background goroutines)
├── ratelimit.go       # Token-bucket limiter (context-aware, cancelable, dynamic — wakes waiters on reconfigure)
├── scope.go           # ScopeGuard wrapper (fail-closed, wraps internal/scope)
├── passive/
│   └── provider.go    # PassiveRunner alias + capability constants (contract only, no runnable provider)
└── active/
    └── provider.go    # ActiveRunner alias + capability constants (contract only, no runnable provider)
```

> The `passive/` and `active/` packages are **contracts only** — a type
> alias and the capability constants. They ship **no runnable provider**:
> a worked example lives in the tests and in this document, never in the
> production tree, so nothing there can return a fabricated success.

### Key Design Principles

1. **Local-first, explicit disclosure** — Every provider declares its disclosure class. Nothing leaves the machine without the user's knowledge.

2. **Passive/Active hard boundary** — Separate runner interfaces, separate packages, separate activity classes. The framework — not the provider — enforces the boundary: `Executor.ExecutePassive` rejects a non-passive provider, and `Executor.ExecuteActive` rejects anything that is not active, each *before* the provider's code runs.

3. **Central execution gate** — A registered provider is never run by calling a method on it directly. `Registry` hands out only metadata; the only route to execution is `Executor`, which runs the authorization, pipeline, context and provenance checks in one place.

4. **Fail-closed Scope Guard** — Active execution is rejected unless an explicit, authorized `ScopeGuard` exists AND the target is within it. A nil guard, an unauthorized guard, or an out-of-scope target each stop the call before the provider is invoked.

5. **Provenance on every successful result** — Provider ID, name, capability, activity class, disclosure class, timestamp. The gate validates it and converts a successful result with missing/incoherent provenance into a fail-closed error. Results that fail *before* the provider gathers intelligence (scope denied, unsupported capability, invalid input, dead context) are not required to carry provenance.

6. **Bounded resources** — Caches have a hard max size. Rate limiters have configurable burst/rate. No unbounded maps, no goroutine leaks.

7. **Context throughout** — Every blocking operation accepts `context.Context`. The gate checks `ctx.Err()` before invoking a provider; cancellation and deadline errors are surfaced (never swallowed) via `ErrCanceled` / `ErrDeadlineExceeded`.

8. **Typed errors** — Wrapper types implement `Unwrap`, so `errors.Is` and `errors.As` both work against them; `IsXxx` predicates are provided for the common checks. Distinguish: invalid config, unsupported capability, scope denied, activity violation, invalid provenance, rate limited, provider unavailable, external failure, canceled, deadline exceeded.

---

## Activity Class Separation

### Passive (`ActivityPassive`)
- **Definition**: No interacción activa directa con la infraestructura del objetivo. La clase de divulgación indica si el procesamiento es puramente local o consulta a un tercero.
- **Ejemplos**: Consultas RDAP, búsquedas en base de datos CVE, búsquedas en logs de Certificate Transparency, mapeo ASN, enumeración pasiva de subdominios.
- **Divulgación**: `DisclosureLocal` o `DisclosurePassive` — nunca `DisclosureActive`.
- **Scope Guard**: NO requerido.
- **Runner**: implementa `osint.PassiveRunner` (`Lookup`), se ejecuta vía `Executor.ExecutePassive`.

### Active (`ActivityActive`)
- **Definition**: Sends packets/probes directly to target infrastructure.
- **Examples**: Port scanning, traceroute, service detection, active DNS (AXFR, brute force).
- **Disclosure**: `DisclosureActive` (required).
- **Scope Guard**: REQUIRED — must be authorized AND target within scope.
- **Runner**: implements `osint.ActiveRunner` (`Probe`), run via `Executor.ExecuteActive`. The runner performs **no** scope check of its own — the gate has already authorized the target.

### Registration-time consistency (`ProviderMeta.Validate`)
```go
// ActivityActive  => RequiresScope == true  && DisclosureClass == DisclosureActive
// ActivityPassive => RequiresScope == false && DisclosureClass in {DisclosureLocal, DisclosurePassive}
```
`Registry.Register` additionally rejects a provider whose declared `ActivityClass`
does not match the runner interface it implements (passive ⇒ `PassiveRunner`,
active ⇒ `ActiveRunner`).

**Capabilities** must be a valid *set*: at least one entry, every entry
**non-empty** (`CapabilityUnknown` / `Capability("")` rejected) and **unique**
(no duplicates). It is not a closed whitelist — `Capability` is an extensible
string, so a custom `Capability("vendor.thing")` is accepted. The central
capability gate relies on this, so a provider with an empty or undefined
capability can never register and therefore can never reach `Lookup` / `Probe`.

### Runtime enforcement (`Executor`)
- `ExecutePassive` rejects any provider whose `ActivityClass != ActivityPassive` — the provider is **not** invoked.
- `ExecuteActive` rejects a nil guard, an unauthorized guard, or an out-of-scope target — the provider is **not** invoked.
- Either pipeline rejects a capability not in `ProviderMeta.Capabilities` **before** invocation (and, for active, before the ScopeGuard).
- Both inspect the context first and validate returned provenance last.

---

## Provider Contract

### ProviderMeta (Identity & Capabilities)
```go
type ProviderMeta struct {
    ID              string        // stable: "rdap.ripe", "cve.nvd"
    Name            string        // human: "RDAP via RIPE NCC"
    Capabilities    []Capability  // at least one
    ActivityClass   ActivityClass // Passive or Active
    DisclosureClass DisclosureClass
    RequiresScope   bool          // must agree with ActivityClass (see Validate)
    RateLimit       string        // free-text quota note
}
```
Set once by the provider. `Registry` stores a defensive snapshot (the
`Capabilities` slice is copied) and every accessor returns a copy, so a
caller cannot mutate registry state through a retained slice.

### Interfaces
```go
// Identity only — this is what Registry hands out. No execution method.
type Provider interface {
    Meta() ProviderMeta
}

// Implemented by passive providers. Invoked ONLY by Executor.ExecutePassive.
type PassiveRunner interface {
    Provider
    Lookup(ctx context.Context, capability Capability, input any) Result
}

// Implemented by active providers. Invoked ONLY by Executor.ExecuteActive,
// which has already authorized the target. Probe does no scope check.
type ActiveRunner interface {
    Provider
    Probe(ctx context.Context, capability Capability, target string, input any) Result
}
```

### Registry (metadata only)
```go
reg := osint.NewRegistry()
reg.Register(myProvider)                     // validates meta + class/runner match

meta, ok := reg.Lookup("rdap.ripe")          // (ProviderMeta, bool)
metas := reg.MetasByCapability(osint.CapabilityRDAP)
passive := reg.PassiveMetas()
active := reg.ActiveMetas()
```
There is no `Registry` method that returns a runnable provider — execution
goes through `Executor` only.

### Executor (the execution gate)
```go
ex := osint.NewExecutor(reg)

// Passive: rejects a non-passive provider before its code runs.
res := ex.ExecutePassive(ctx, "rdap.ripe", osint.CapabilityRDAP, "1.1.1.1")

// Active: fail-closed. guard nil / unauthorized / target out of scope => reject.
guard := osint.NewScopeGuard()
_ = guard.Authorize("LAN audit", []string{"192.168.1.0/24"})
res = ex.ExecuteActive(ctx, guard, "portscan.local", osint.CapabilityPortScan, "192.168.1.10", nil)
```

**Fixed check order** (every step fail-closed; an invalid request never
reaches the ScopeGuard or the provider):

1. **context** — `nil` context → `InvalidConfigError`; already-done context → `ErrCanceled` / `ErrDeadlineExceeded`
2. **provider** — unknown ID → `ErrProviderNotFound`
3. **pipeline** — wrong pipeline for the provider's `ActivityClass` → `ActivityViolationError`
4. **capability** — requested capability not in `ProviderMeta.Capabilities` → `UnsupportedCapabilityError` (checked **before** the scope gate, so no active interaction is attempted for an undeclared capability)
5. **active scope** *(active only)* — `nil` guard / unauthorized guard → `ScopeRequiredError`; target out of scope → `ScopeDeniedError`
6. **invocation** — only now is `Lookup` / `Probe` called
7. **provenance** — a successful `Result` must carry provenance that exactly describes this provider and request (see below), else `InvalidProvenanceError` with `Data` dropped

At every step before 6 the provider's code is **not** executed.

### Result
```go
type Result struct {
    Data       any        // capability-specific payload
    Provenance Provenance // required on success; validated by the gate
    Err        error      // when non-nil, Data is nil
}
```

---

## Scope Guard

Wraps `internal/scope.Guard` with OSINT-specific helpers. The gate calls
`RequireTarget` for you before any active provider runs; providers do not
call it themselves.

```go
guard := osint.NewScopeGuard()
guard.Authorize("LAN audit", []string{"192.168.1.0/24", "internal.example.com"})
```

### Behavior (as seen through `Executor.ExecuteActive`)
- **guard == nil** → `ScopeRequiredError` (wraps `ErrScopeDenied`)
- **Unauthorized guard** → `ScopeRequiredError` (wraps `ErrScopeDenied`)
- **Authorized but target out of scope** → `ScopeDeniedError` (wraps `ErrScopeDenied`)
- **Authorized and in scope** → the provider's `Probe` is invoked
- Dynamic scope revocation is **not** offered in V1.5-2.

---

## Disclosure Model

Every provider declares `DisclosureClass`:

| Class | Meaning | Examples |
|-------|---------|----------|
| `DisclosureLocal` | Nothing leaves machine | Local GeoIP, OUI lookup, hash calc |
| `DisclosurePassive` | External passive lookup | RDAP, CVE, CT, ASN mapping |
| `DisclosureActive` | Active network interaction | Port scan, traceroute, service detect |

The `external.Disclosure` envelope (from `internal/intel/external`) is embedded in `Provenance` for passive ops.

---

## Provenance

```go
type Provenance struct {
    ProviderID       string
    ProviderName     string
    Capability       string
    ActivityClass    ActivityClass
    DisclosureClass  DisclosureClass
    RetrievedAt      string    // RFC3339
    Endpoint         string    // sanitized, no secrets
    Confidence       string    // "alta" | "media" | "baja"
    Disclosure       external.Disclosure
}
```

`Provenance.Validate()` requires a successful result to carry, at minimum,
`ProviderID`, `ProviderName`, `Capability`, a valid `ActivityClass` and
`DisclosureClass`, and a non-empty `RetrievedAt`, with activity/disclosure
coherent.

`Executor` runs that check **and** then verifies the provenance describes
the execution *exactly* — every one of:

| Provenance field | must equal |
|---|---|
| `ProviderID` | registered `ProviderMeta.ID` |
| `ProviderName` | registered `ProviderMeta.Name` |
| `Capability` | the capability passed to `ExecutePassive` / `ExecuteActive` |
| `ActivityClass` | registered `ProviderMeta.ActivityClass` |
| `DisclosureClass` | registered `ProviderMeta.DisclosureClass` |

Any mismatch — even with individually valid fields — is converted to a
fail-closed `InvalidProvenanceError` and the `Data` is dropped.

Future extensions (V1.5-3+):
- `EvidenceClass`: `OBSERVED` | `POSSIBLE_CONTEXT` | `NOT_PROVEN`
- Cable path inference → `POSSIBLE_CONTEXT` only
- Never `OBSERVED` for inferred paths

---

## Bounded Cache

```go
cache := osint.NewCache(500) // max 500 entries
cache.Set(key, value, 5*time.Minute)
val, ok := cache.Get(key)
```

### Properties
- **Bounded**: Hard max entries (default 500, configurable)
- **TTL-aware**: Expired entries are misses, never served stale
- **LRU eviction**: Least-recently-used evicted when at capacity
- **Thread-safe**: Mutex-protected
- **No background goroutines**: Expiration checked lazily on Get
- **Testable**: `WithClock(func() time.Time)` for deterministic time

### Test Coverage Required
- Max capacity enforcement
- LRU eviction order
- TTL expiry
- Concurrent access safety
- No growth beyond limit

---

## Rate Limiter

```go
limiter := osint.NewLimiter(10, 20) // 10 req/sec, burst 20
err := limiter.Acquire(ctx)         // blocks until token or ctx done
ok := limiter.TryAcquire()          // non-blocking
```

### Properties
- **Token bucket**: Smooth rate limiting with burst allowance
- **Context-aware**: `Acquire(ctx)` returns on cancellation
- **No goroutines**: Refill on demand, no background ticker; no polling, no busy-loop
- **Dynamic**: `SetRate()` / `SetBurst()` at runtime. The interval since the
  last accounting is credited at the **old** rate *before* the change takes
  effect — a rate increase never retroactively over-credits the past
  interval. The change then **wakes any `Acquire` that is waiting** (via an
  internal reconfigure channel — a timer, `Stop`ped/drained on wake) so it
  recomputes against the new configuration instead of sleeping out the stale
  timer. `SetRate(0)` (unlimited) therefore releases a waiter promptly.
- **Testable**: `WithClock(func() time.Time)` for a deterministic clock
- **Composable**: `NewMultiLimiter(perProvider, global)` for layered limits

### Test Coverage Required
- Rate enforcement over time
- Burst allowance
- Context cancellation during wait — still wins after a reconfigure
- `SetRate(0)` wakes a waiting `Acquire`; a rate increase wakes it and it recomputes (does not wait out the old timer)
- Rate change credits the elapsed interval at the old rate (no retroactive over-credit)
- TryAcquire non-blocking behavior
- MultiLimiter all-or-nothing semantics

---

## Context & Cancellation

Blocking operation signatures:
```go
Executor.ExecutePassive(ctx context.Context, ...) Result
Executor.ExecuteActive(ctx context.Context, guard *ScopeGuard, ...) Result
PassiveRunner.Lookup(ctx context.Context, ...) Result
ActiveRunner.Probe(ctx context.Context, ...) Result
Limiter.Acquire(ctx context.Context) error
Cache.Get(key string) (any, bool)  // non-blocking
```

### Cancellation Rules
- `Executor` inspects the context before invoking any provider — an already
  done context means the provider is never called.
- `nil` context → `InvalidConfigError` (`IsInvalidConfig` true); rejected fail-closed rather than left to panic.
- Context cancellation → `ErrCanceled` (wrapping `context.Canceled`); `IsCanceled` is true.
- Deadline exceeded → `ErrDeadlineExceeded` (wrapping `context.DeadlineExceeded`); `IsDeadlineExceeded` is true.
- Provider must NOT retry infinitely on cancellation, and must NOT swallow context errors.

### Test Coverage Required
- Already-canceled context: provider invocation count = 0 (passive and active paths)
- Expired deadline: provider invocation count = 0 (passive and active paths)
- Cancellation while waiting on the rate limiter
- No hidden infinite retry loops

---

## Typed Error Taxonomy

| Error | Sentinel | Wrapper | Retryable? |
|-------|----------|---------|------------|
| Invalid config | `ErrInvalidConfig` | `InvalidConfigError` | No |
| Unsupported capability | `ErrUnsupportedCapability` | `UnsupportedCapabilityError` | No |
| Scope denied | `ErrScopeDenied` | `ScopeDeniedError` / `ScopeRequiredError` | No |
| Activity violation | `ErrActivityViolation` | `ActivityViolationError` | No |
| Invalid provenance | `ErrInvalidProvenance` | `InvalidProvenanceError` | No |
| Rate limited | `ErrRateLimited` | `RateLimitedError` | **Yes** |
| Provider unavailable | `ErrProviderUnavailable` | `ProviderUnavailableError` | **Yes** |
| External lookup failed | `ErrExternalLookupFailed` | `ExternalLookupFailedError` | **Yes** |
| Canceled | `ErrCanceled` | — | N/A |
| Deadline exceeded | `ErrDeadlineExceeded` | — | N/A |

Helper predicates:
```go
osint.IsRetryable(err)    // rate limited, unavailable, external fail, deadline
osint.IsPermanent(err)    // invalid config, unsupported, scope denied,
                          // activity violation, invalid provenance
osint.IsCanceled(err)         // context.Canceled or wrapped
osint.IsDeadlineExceeded(err)
osint.IsScopeDenied(err)
osint.IsRateLimited(err)
osint.IsActivityViolation(err)
osint.IsInvalidProvenance(err)
```
There are no `AsXxx` helpers: use `errors.As` directly with the concrete
wrapper types (`*ScopeDeniedError`, `*ActivityViolationError`, …).

---

## Testing Requirements (V1.5-2)

All tests use synthetic providers / `httptest` — **no real network**.

| Test | Description |
|------|-------------|
| A | ProviderMeta validation (valid/invalid) incl. activity/disclosure/scope coherence |
| B | Passive/Active separation enforced by the framework (a malicious active provider run without/with-unauthorized/out-of-scope guard is rejected with invocation count 0; authorized+in-scope runs once; active-via-passive rejected) |
| C | ScopeGuard fail-closed (nil guard, unauthorized) |
| D | Out-of-scope active target rejected before provider invocation |
| E | Authorized synthetic active target allowed |
| F | Provenance enforced: a successful result whose provenance is missing, or whose `ProviderID` / `ProviderName` / `Capability` / `ActivityClass` / `DisclosureClass` does not match the registered provider and the request, is converted to a fail-closed error with `Data` dropped; pre-execution failures are exempt |
| G | Cache max capacity enforced |
| H | Cache LRU eviction |
| I | Cache TTL expiry |
| J | Rate limiter: context cancellation during wait; `SetRate(0)` / rate increase wakes and recomputes a waiting `Acquire`; a rate change credits the elapsed interval at the old rate (deterministic clock) |
| K | Context: nil context → `InvalidConfig`; already-canceled / past-deadline → typed error, provider not invoked (passive + active) |
| L | Typed errors detectable via `errors.Is` / `errors.As` |
| M | Disclosure classification correct |
| N | No unexpected network in tests |
| O | Capability gate: an undeclared capability is rejected by the framework (`UnsupportedCapabilityError`, invocation count 0) on both pipelines, and — for active — before the ScopeGuard is consulted |
| P | Contract packages contain no runnable provider that can fabricate a result (source scan) |
| Q | `Registry.Register` rejects a nil / typed-nil provider without panicking |
| R | `ProviderMeta.Capabilities` validated as a set: empty/unknown and duplicate entries rejected at `Validate` / `Register`; multiple unique + custom string capabilities accepted; a provider with an invalid capability set never registers, so its invocation count stays 0 |

---

## What is NOT Implemented (Yet)

| Feature | Target Version |
|---------|----------------|
| Real RDAP provider | V1.5-3 |
| Real CVE provider (NVD) | V1.5-3 |
| Real CT provider (crt.sh) | V1.5-3 |
| Real ASN mapping (RIPEstat) | V1.5-3 |
| Port scanner | V1.5-3 |
| Traceroute | V1.5-3 |
| Service detection | V1.5-4 |
| Subdomain enumeration | V1.5-4 |
| Entity graph UI | V1.5-4+ |
| Investigation enrichment | V1.5-4+ |
| Submarine cable mapping | V1.5-5+ |
| PeeringDB integration | V1.5-5+ |
| OSIRIS integration | V1.5-5+ |
| TeleGeography data | **Never** (copyright) |
| Release artifacts | V1.5-3+ |

---

## Rules for Future Integrations (V1.5-3+)

1. **One provider per package** under `internal/osint/providers/<name>/`
2. **Implement the correct runner** — `PassiveRunner` (`Lookup`) or `ActiveRunner` (`Probe`); run it through `Executor`, never directly
3. **Declare accurate metadata** — `ActivityClass`, `DisclosureClass`, `RequiresScope` (coherent per `ProviderMeta.Validate`), and **every** capability you handle in `Capabilities` as a non-empty, duplicate-free set (the gate rejects an undeclared one before `Lookup` / `Probe`; an empty/duplicate set fails registration)
4. **Do not scope-check inside `Probe`** — the gate has already authorized the target
5. **Use bounded cache** — `osint.NewCache(size)` per provider
6. **Use rate limiter** — `osint.NewLimiter(rate, burst)` per provider
7. **Respect context** — all blocking calls accept `ctx`
8. **Return typed errors** — wrap sentinel errors with context
9. **Preserve provenance exactly** — `osint.NewProvenance(...)` on every successful result; its `ProviderID` / `ProviderName` / `Capability` / `ActivityClass` / `DisclosureClass` must equal your registered metadata and the requested capability, or the gate drops the result
10. **No secrets in logs** — sanitize endpoints, no API keys in output
11. **Tests with httptest** — no real Internet in unit tests
12. **Document disclosure** — what data leaves, where it goes
13. **Cable inference = POSSIBLE_CONTEXT** — never OBSERVED

---

## Quality Gates

```bash
gofmt -l internal/osint/...
go test ./internal/osint/... -count=1
go test ./... -count=1
go vet ./...
cd frontend && npm ci && npm test && npm run build
govulncheck ./...
gitleaks detect --source .
git diff --check
```

---

## Security / Privacy Invariants (Enforced by Architecture)

- ✅ Local-first default
- ✅ Explicit disclosure declaration per provider, coherent with activity class
- ✅ Active execution requires an authorized Scope Guard — enforced by `Executor`, not the provider (fail-closed)
- ✅ A provider cannot be run through the wrong pipeline, or at all, except via `Executor`
- ✅ A capability the provider did not declare is rejected before the provider (and the ScopeGuard) is reached
- ✅ A successful result whose provenance does not exactly match the provider and request is rejected fail-closed, `Data` dropped
- ✅ The contract packages ship no runnable provider — no fabricated "example" results
- ✅ No unbounded caches
- ✅ No background polling goroutines
- ✅ No secrets in code/fixtures/logs
- ✅ No silent network calls on import/init
- ✅ Context cancellation checked before any provider is invoked

---

## Files Added in V1.5-2

| File | Purpose |
|------|---------|
| `internal/osint/model.go` | Core types: ActivityClass, DisclosureClass, Provenance (+Validate), ProviderMeta (+Validate/clone), Result, Capability |
| `internal/osint/errors.go` | Typed error sentinels + wrapper types (Unwrap) + IsXxx predicates |
| `internal/osint/provider.go` | Provider (identity), PassiveRunner / ActiveRunner, Registry (metadata lookup + defensive snapshot), BaseProvider |
| `internal/osint/executor.go` | Executor — central execution gate (ExecutePassive / ExecuteActive), context + provenance enforcement |
| `internal/osint/cache.go` | Bounded LRU+TTL cache |
| `internal/osint/ratelimit.go` | Token-bucket limiter (context-aware) |
| `internal/osint/scope.go` | ScopeGuard wrapper (fail-closed) |
| `internal/osint/passive/provider.go` | PassiveRunner alias + capability constants — contract only, no runnable provider |
| `internal/osint/active/provider.go` | ActiveRunner alias + capability constants — contract only, no runnable provider |
| `docs/OSINT_FOUNDATION.md` | This document |