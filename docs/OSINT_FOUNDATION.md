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
├── model.go           # ActivityClass, DisclosureClass, Provenance, ProviderMeta, Result
├── errors.go          # Typed error taxonomy (IsXxx, AsXxx, Unwrap)
├── provider.go        # Provider interface, Registry, BaseProvider, Passive/Active contracts
├── cache.go           # Bounded LRU+TTL cache (thread-safe, no background goroutines)
├── ratelimit.go       # Token-bucket limiter (context-aware, cancelable)
├── scope.go           # ScopeGuard wrapper (fail-closed, wraps internal/scope)
├── passive/
│   └── provider.go    # PassiveProvider interface + capability constants + example
└── active/
    └── provider.go    # ActiveProvider interface + capability constants + example
```

### Key Design Principles

1. **Local-first, explicit disclosure** — Every provider declares its disclosure class. Nothing leaves the machine without the user's knowledge.

2. **Passive/Active hard boundary** — Separate interfaces, separate packages, separate activity classes. An active operation cannot accidentally enter the passive pipeline. A passive operation never requires a Scope Guard.

3. **Fail-closed Scope Guard** — Active operations are rejected unless an authorized scope exists AND the target is within it. No exceptions.

4. **Provenance on every result** — Provider ID, capability, activity class, disclosure class, timestamp, endpoint, confidence. No silent enrichment.

5. **Bounded resources** — Caches have hard max size. Rate limiters have configurable burst/rate. No unbounded maps, no goroutine leaks.

6. **Context throughout** — Every blocking operation accepts `context.Context`. Cancellation propagates. No hidden retry loops.

7. **Typed errors** — `errors.Is/As` work. Distinguish: invalid config, unsupported capability, scope denied, rate limited, provider unavailable, external failure, canceled, deadline exceeded.

---

## Activity Class Separation

### Passive (`ActivityPassive`)
- **Definition**: Purely external lookups. No packets sent to target infrastructure.
- **Examples**: RDAP queries, CVE database lookups, Certificate Transparency log searches, ASN mapping, passive subdomain enumeration.
- **Disclosure**: `DisclosurePassive` (external HTTP/DNS to third party).
- **Scope Guard**: NOT required.
- **Interface**: `osint.PassiveProvider` (in `internal/osint/passive`)

### Active (`ActivityActive`)
- **Definition**: Sends packets/probes directly to target infrastructure.
- **Examples**: Port scanning, traceroute, service detection, active DNS (AXFR, brute force).
- **Disclosure**: `DisclosureActive` (direct network interaction with target).
- **Scope Guard**: REQUIRED — must be authorized AND target within scope.
- **Interface**: `osint.ActiveProvider` (in `internal/osint/active`)

### Compile-time Enforcement
```go
// ProviderMeta.Validate() enforces:
if meta.ActivityClass == ActivityActive && !meta.RequiresScope {
    return error // active MUST require scope
}
if meta.ActivityClass == ActivityPassive && meta.RequiresScope {
    return error // passive MUST NOT require scope
}
```

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
    RequiresScope   bool          // derived from ActivityClass
    RateLimit       string        // free-text quota note
}
```

### Provider Interface
```go
type Provider interface {
    Meta() ProviderMeta
    Execute(ctx context.Context, capability Capability, input any) Result
}
```

### Registry
```go
reg := osint.NewRegistry()
reg.Register(myProvider)        // at startup
providers := reg.GetByCapability(osint.CapabilityRDAP)
passive := reg.GetPassive()
active := reg.GetActive()
```

### Result (Always carries Provenance)
```go
type Result struct {
    Data       any        // capability-specific payload
    Provenance Provenance // mandatory
    Err        error      // if failed, Data may be nil
}
```

---

## Scope Guard

Wraps `internal/scope.Guard` with OSINT-specific helpers.

```go
guard := osint.NewScopeGuard()
guard.Authorize("LAN audit", []string{"192.168.1.0/24", "internal.example.com"})

// In active provider Execute:
if err := guard.RequireTarget("port_scan", "nmap.active", target); err != nil {
    return osint.Result{Err: err} // ScopeDeniedError or ScopeRequiredError
}
```

### Behavior
- **Unauthorized** → `ScopeRequiredError` (wraps `ErrScopeDenied`)
- **Authorized but target out of scope** → `ScopeDeniedError` (wraps `ErrScopeDenied`)
- **Authorized and in scope** → proceeds

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
- **No goroutines**: Refill on demand, no background ticker
- **Dynamic**: `SetRate()`, `SetBurst()` at runtime
- **Composable**: `NewMultiLimiter(perProvider, global)` for layered limits

### Test Coverage Required
- Rate enforcement over time
- Burst allowance
- Context cancellation during wait
- TryAcquire non-blocking behavior
- MultiLimiter all-or-nothing semantics

---

## Context & Cancellation

Every blocking operation signature:
```go
Execute(ctx context.Context, ...) Result
Acquire(ctx context.Context) error
Get(key string) (any, bool)  // non-blocking
```

### Cancellation Rules
- Context cancellation → return `context.Canceled` (wrapped as `ErrCanceled`)
- Deadline exceeded → return `context.DeadlineExceeded` (wrapped as `ErrDeadlineExceeded`)
- Provider must NOT retry infinitely on cancellation
- Provider must NOT swallow context errors

### Test Coverage Required
- Already-canceled context
- Cancellation mid-operation
- Cancellation while waiting on rate limiter
- No hidden infinite retry loops

---

## Typed Error Taxonomy

| Error | Sentinel | Wrapper | Retryable? |
|-------|----------|---------|------------|
| Invalid config | `ErrInvalidConfig` | `InvalidConfigError` | No |
| Unsupported capability | `ErrUnsupportedCapability` | `UnsupportedCapabilityError` | No |
| Scope denied | `ErrScopeDenied` | `ScopeDeniedError` / `ScopeRequiredError` | No |
| Rate limited | `ErrRateLimited` | `RateLimitedError` | **Yes** |
| Provider unavailable | `ErrProviderUnavailable` | `ProviderUnavailableError` | **Yes** |
| External lookup failed | `ErrExternalLookupFailed` | `ExternalLookupFailedError` | **Yes** |
| Canceled | `ErrCanceled` | — | N/A |
| Deadline exceeded | `ErrDeadlineExceeded` | — | N/A |

Helper predicates:
```go
osint.IsRetryable(err)    // rate limited, unavailable, external fail, deadline
osint.IsPermanent(err)    // invalid config, unsupported, scope denied
osint.IsCanceled(err)     // context.Canceled or wrapped
osint.IsDeadlineExceeded(err)
osint.IsScopeDenied(err)
osint.IsRateLimited(err)
```

---

## Testing Requirements (V1.5-2)

All tests use synthetic providers / `httptest` — **no real network**.

| Test | Description |
|------|-------------|
| A | ProviderMeta validation (valid/invalid) |
| B | Passive/Active separation (compile + runtime) |
| C | ScopeGuard fail-closed (unauthorized) |
| D | Out-of-scope active target rejected |
| E | Authorized synthetic active target allowed |
| F | Provenance preserved on Result |
| G | Cache max capacity enforced |
| H | Cache LRU eviction |
| I | Cache TTL expiry |
| J | Rate limiter context cancellation |
| K | Context cancellation propagation |
| L | Typed errors detectable via Is/As |
| M | Disclosure classification correct |
| N | No unexpected network in tests |

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
2. **Implement correct interface** — `PassiveProvider` or `ActiveProvider`
3. **Declare accurate metadata** — ActivityClass, DisclosureClass, RequiresScope
4. **Use bounded cache** — `osint.NewCache(size)` per provider
5. **Use rate limiter** — `osint.NewLimiter(rate, burst)` per provider
6. **Respect context** — all blocking calls accept `ctx`
7. **Return typed errors** — wrap sentinel errors with context
8. **Preserve provenance** — `osint.NewProvenance(...)` on every result
9. **No secrets in logs** — sanitize endpoints, no API keys in output
10. **Tests with httptest** — no real Internet in unit tests
11. **Document disclosure** — what data leaves, where it goes
12. **Cable inference = POSSIBLE_CONTEXT** — never OBSERVED

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
- ✅ Explicit disclosure declaration per provider
- ✅ Active ops require Scope Guard (fail-closed)
- ✅ No unbounded caches
- ✅ No background polling goroutines
- ✅ No secrets in code/fixtures/logs
- ✅ No silent network calls on import/init
- ✅ Context cancellation respected everywhere

---

## Files Added in V1.5-2

| File | Purpose |
|------|---------|
| `internal/osint/model.go` | Core types: ActivityClass, DisclosureClass, Provenance, ProviderMeta, Result, Capability |
| `internal/osint/errors.go` | Typed error sentinels + wrappers + Is/As helpers |
| `internal/osint/provider.go` | Provider interface, Registry, BaseProvider, Passive/Active contracts |
| `internal/osint/cache.go` | Bounded LRU+TTL cache |
| `internal/osint/ratelimit.go` | Token-bucket limiter (context-aware) |
| `internal/osint/scope.go` | ScopeGuard wrapper (fail-closed) |
| `internal/osint/passive/provider.go` | PassiveProvider interface + capabilities + example |
| `internal/osint/active/provider.go` | ActiveProvider interface + capabilities + example |
| `docs/OSINT_FOUNDATION.md` | This document |