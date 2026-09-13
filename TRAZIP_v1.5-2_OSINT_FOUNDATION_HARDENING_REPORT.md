# TRAZIP v1.5-2 — FOUNDATION HARDENING REPORT

## Baseline
- previous HEAD: `81b35a01eb4f8e88bccb9de1faace5934dbfd118`
- new HEAD: `ee22475928bb63557b84d351f9283b013d2ec331`
- commits ahead of `main`: **2** (`81b35a0` foundation, `ee22475` hardening)
- branch: `feature/v1.5-2-osint-foundation` — no amend of the pushed commit, no force push; one new commit added and pushed normally.

---

## P1-01 — Active execution enforced by the framework

- **central execution gate:** `internal/osint/executor.go` — new `Executor` type, the only supported way to run a registered provider.
  - `Provider` interface now exposes **identity only** (`Meta()`); no execution method.
  - Providers implement `PassiveRunner` (`Lookup`) or `ActiveRunner` (`Probe`). Those methods are documented as gate-only.
  - `Registry` public accessors return **`ProviderMeta` copies** (`Lookup`, `MetasByCapability`, `PassiveMetas`, `ActiveMetas`, `AllMetas`). The concrete provider is reachable only through the **package-private** `Registry.provider(id)`, whose sole caller is `Executor`.
  - `Registry.Register` additionally rejects a provider whose declared `ActivityClass` does not match the runner interface it implements (passive ⇒ `PassiveRunner`, active ⇒ `ActiveRunner`).
- **raw active bypass prevented:** yes. There is no public route from `Registry` to a runnable provider. `ExecutePassive` rejects a non-passive provider before invoking it; `ExecuteActive` is fail-closed on nil guard / unauthorized guard / out-of-scope target, and only then calls `Probe`. Scope is checked by the gate (`guard.RequireTarget`), not by the provider.
- **malicious active provider test:** `TestExecutorActiveBypassPrevention` in `internal/osint/executor_test.go`. `maliciousActiveProvider` declares `ActivityActive` + `RequiresScope=true`, returns success, performs **no** scope check, and counts its invocations.
  - A. no guard → `IsScopeDenied`, invocation count **0**
  - B. unauthorized guard → `IsScopeDenied`, invocation count **0**
  - C. authorized guard, target out of scope → `IsScopeDenied`, invocation count **0**
  - D. authorized guard, target in scope → success, invocation count **1**
  - E. active provider via passive pipeline (`ExecutePassive`) → `IsActivityViolation`, invocation count **0**
  - Mirror cases: `TestExecutorPassivePipelineRejectsActive`, `TestExecutorActivePipelineRejectsPassive`.
- **provider not invoked before authorization:** confirmed by the invocation-count assertions above — the gate, not provider cooperation, blocks the bypass.

---

## P1-02 — Activity / disclosure consistency

- **activity/disclosure validation:** `ProviderMeta.Validate` now enforces
  - `ActivityActive` ⇒ `RequiresScope == true` **and** `DisclosureClass == DisclosureActive`
  - `ActivityPassive` ⇒ `RequiresScope == false` **and** `DisclosureClass != DisclosureActive` (`DisclosureLocal` or `DisclosurePassive` allowed)
- **negative combinations tested:** `TestProviderMetaValidate` (table) in `internal/osint/model_test.go`
  - active + `DisclosurePassive` → reject
  - active + `DisclosureLocal` → reject
  - active + `DisclosureActive` → accept
  - passive + `DisclosureActive` → reject
  - passive + `DisclosurePassive` → accept
  - passive + `DisclosureLocal` → accept

---

## P1-03 — Provenance really mandatory

- **provenance validation:** new `Provenance.Validate()` — requires non-empty `ProviderID`, `ProviderName`, `Capability`, `RetrievedAt`; valid `ActivityClass` and `DisclosureClass`; and activity/disclosure coherence. Unit-tested by `TestProvenanceValidate` (8 negative cases + zero-value).
- The gate's `finalizeResult` runs `Provenance.Validate()` on every **successful** `Result` and also verifies the provenance's `ProviderID` and `ActivityClass` match the provider/pipeline that actually ran. A violation is converted to a fail-closed `InvalidProvenanceError` (`IsInvalidProvenance`, permanent), with `Data` dropped.
- Pre-execution failures (`ScopeRequired`, `UnsupportedCapability`, invalid input, dead context) are **exempt** — `finalizeResult` passes a `Result` that already carries an error straight through.
- **invalid successful result rejected:** `TestExecutorRejectsSuccessWithoutProvenance` — synthetic `noProvenanceProvider` returns `Data != nil, Err == nil, Provenance == zero`; framework returns `IsInvalidProvenance`, `res.IsOK() == false`, `res.Data == nil`, and the provider *did* run (`calls == 1`) — the framework rejected its output.
  - Also `TestExecutorRejectsProvenanceIdentityMismatch` (provenance names another provider) and `TestExecutorPassesThroughPreExecutionFailure` (exemption).

---

## Context

- The gate calls `contextError(ctx)` (checks `ctx.Err()`) **before** looking up or invoking any provider, and again after the scope check on the active path. A done context maps to `ErrCanceled` / `ErrDeadlineExceeded` (wrapping the stdlib error), so `IsCanceled` / `IsDeadlineExceeded` are true.
- **pre-canceled invocation:** `TestExecutorContextAlreadyCanceled` — canceled `context`, both `ExecutePassive` and `ExecuteActive`: error `IsCanceled`, provider invocation count **0**.
- **deadline invocation:** `TestExecutorContextDeadlineExceeded` — `context.WithDeadline(..., now-1h)` (cancelled synchronously in the constructor, no timer race), both pipelines: error `IsDeadlineExceeded`, provider invocation count **0**.

---

## P2

- **capability defensive copy:** `ProviderMeta.clone()` copies the `Capabilities` slice. `Registry.Register` stores a clone; `Lookup` / `provider` / all `*Metas` accessors return clones. `TestRegistryCapabilitiesDefensiveCopy` proves a caller mutating (a) the slice it passed in or (b) the slice it got back cannot alter registry state.
- **docs corrected:** `docs/OSINT_FOUNDATION.md` rewritten to describe only real behavior — the execution gate, `PassiveRunner`/`ActiveRunner`, the registration-time consistency rules, runtime enforcement, provenance validation, the new error rows. Removed the "AsXxx" helper claim (there are none; `errors.As` works on the concrete wrapper types). `ProviderMeta` / `Provenance` described as *set once + defensively snapshotted / validated* rather than "immutable". `WithScopeContext` removed from the docs.
- **WithScopeContext:** removed from `scope.go` entirely — it offered no dynamic revocation and only invited a misleading contract. Docs now state revocation is not offered in V1.5-2.
- **CheckAddr/CheckPrefix:** `CheckPrefix` removed (its name implied CIDR-specific handling it did not do). `CheckAddr` / `CheckHost` kept but reduced to honest one-line aliases of `CheckTarget`, with the stale "we need netip" comment deleted. `CheckTarget` is the single canonical entry point; its doc matches what `scope.Guard.CheckTarget` actually does (prefix-first, then addr, then host).

New typed errors: `ErrActivityViolation` / `*ActivityViolationError`, `ErrInvalidProvenance` / `*InvalidProvenanceError` — both `Unwrap` to their sentinel, both classified permanent by `IsPermanent`, covered by `errors_test.go`.

---

## Tests

| Gate | Result |
|---|---|
| OSINT (`go test ./internal/osint/... -count=1`, run x2/x3 on context tests) | **PASS** |
| full Go (`go test ./... -count=1`) | **PASS** — also passes with the CI canonical exclusion `-skip 'TestPingMonitorAgainstLoopback'`. That test passes locally on this host; CI skips it because it needs loopback ICMP that some runners deny, so this report used the same `-skip` for parity and additionally confirmed the un-skipped run is green here. |
| `go vet ./...` | **PASS** |
| frontend `npm ci` / `npm test` (30/30) / `npm run build` | **PASS** — frontend untouched |
| `govulncheck ./...` | **PASS** — 0 vulnerabilities in code / imports |
| `gitleaks` (new + changed files, isolated scan) | **no leaks** |
| `git diff --cached --check` | clean |
| `gofmt -l internal/osint/` | clean |

---

## PR

- number: **#16** (updated in place — no new PR)
- new HEAD: `ee22475928bb63557b84d351f9283b013d2ec331`
- state: OPEN · mergeable: MERGEABLE · mergeStateStatus: **CLEAN**
- changed files: 17 (`+3710 / -0` vs `main`)
- CI run: **`34386791748`** — status `completed`, conclusion **success** — https://github.com/kerwilgil/trazip/actions/runs/34386791748

### 7 required checks
| Check | Status |
|---|---|
| Backend / Test | **PASS** (1m20s) |
| Backend / Test (Windows) | **PASS** (2m57s) |
| Backend / Test (macOS) | **PASS** (1m20s) |
| Frontend / Build | **PASS** (19s) |
| Security / Gitleaks | **PASS** (21s) |
| Security / Govulncheck | **PASS** (32s) |
| Security / SBOM | **PASS** (1m47s) |

Build / Linux · Windows · macOS: **SKIPPED** (expected on a PR — not counted as PASS).

---

## Remaining

- **P0:** 0
- **P1:** 0
- **P2 / non-blocking:**
  - `Registry.Register` catches a plain `nil` provider but a *typed-nil* pointer (`var p *T; reg.Register(p)`) would panic on the nil-receiver `Meta()` call rather than returning an error. No code path constructs one (there are no real providers yet); harden with a reflect/`Meta()`-recover guard when providers land in V1.5-3.
  - `-race` not runnable on this host (no cgo/C toolchain); CI does not run `-race` either. `Registry` RWMutex usage is consistent and `Executor` is stateless; reviewed by hand.
  - Pre-existing `gitleaks` findings in old history commits (`bbf0be2`, `7e56fd4`, `KEY ID.txt`) — unrelated to this branch; the PR-scoped `Security / Gitleaks` check passes.
  - Frontend Vite "chunks > 500 kB" warning — pre-existing, not introduced here.
  - Repo-root report files (`TRAZIP_v1.5-1_...`, `TRAZIP_v1.5-2_...RECOVERY...`, this file) remain untracked and are **not** part of the PR by design.

---

## VERDICT

P0 = 0, P1 = 0. gofmt / go vet / full `go test ./...` / frontend / govulncheck / gitleaks / `git diff --check` all clean; PR #16 CI run `34386791748` concluded **success** with all 7 required checks green.

**TRAZIP_V1_5_2_OSINT_FOUNDATION_PASS**
**READY_FOR_FINAL_REVIEW**

NO MERGEAR. STOP.
