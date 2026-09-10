// Package osint: the central execution gate.
//
// Executor is the only supported way to run a registered provider. It runs
// a fixed, fail-closed sequence of checks — in this exact order — so that
// an invalid request never reaches the ScopeGuard or the provider:
//
//  1. context      — a nil or already-done context stops here;
//  2. provider      — an unknown provider ID stops here;
//  3. pipeline      — the passive pipeline rejects non-passive providers and
//     vice versa (ActivityViolationError);
//  4. capability    — the requested capability must be declared in the
//     provider's ProviderMeta.Capabilities
//     (UnsupportedCapabilityError);
//  5. active scope  — active only: a nil guard, an unauthorized guard, or an
//     out-of-scope target stops here;
//  6. invocation    — only now is Lookup / Probe called;
//  7. provenance    — the returned Result, if successful, must carry
//     provenance that exactly describes this provider and
//     this request (InvalidProvenanceError).
//
// A Result that already carries an error is passed through untouched — a
// provider that failed before gathering intelligence owes no provenance.
package osint

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// Executor runs providers registered in a Registry, enforcing the
// passive/active safety invariants centrally.
type Executor struct {
	reg *Registry
}

// NewExecutor returns an Executor bound to reg.
func NewExecutor(reg *Registry) *Executor {
	return &Executor{reg: reg}
}

// ExecutePassive runs a passive provider by ID. Steps 1-4 and 7 above are
// enforced; an active provider, an undeclared capability, or a dead context
// each stop the call before the provider's code runs.
func (e *Executor) ExecutePassive(ctx context.Context, providerID string, capability Capability, input any) Result {
	if err := contextError(ctx); err != nil {
		return Result{Err: err}
	}

	p, meta, ok := e.reg.provider(providerID)
	if !ok {
		return Result{Err: fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)}
	}
	if meta.ActivityClass != ActivityPassive {
		return Result{Err: &ActivityViolationError{Provider: providerID, Pipeline: ActivityPassive, Actual: meta.ActivityClass}}
	}
	if !metaHasCapability(meta, capability) {
		return Result{Err: &UnsupportedCapabilityError{Provider: providerID, Capability: capability}}
	}
	runner, ok := p.(PassiveRunner)
	if !ok {
		return Result{Err: &InvalidConfigError{Provider: providerID, Field: "PassiveRunner", Reason: "passive provider does not implement PassiveRunner"}}
	}

	return finalizeResult(runner.Lookup(ctx, capability, input), meta, capability)
}

// ExecuteActive runs an active provider by ID. The capability is checked
// (step 4) BEFORE the scope gate (step 5), so no active interaction is ever
// attempted for a capability the provider did not declare.
func (e *Executor) ExecuteActive(ctx context.Context, guard *ScopeGuard, providerID string, capability Capability, target string, input any) Result {
	if err := contextError(ctx); err != nil {
		return Result{Err: err}
	}

	p, meta, ok := e.reg.provider(providerID)
	if !ok {
		return Result{Err: fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)}
	}
	if meta.ActivityClass != ActivityActive {
		return Result{Err: &ActivityViolationError{Provider: providerID, Pipeline: ActivityActive, Actual: meta.ActivityClass}}
	}
	if !metaHasCapability(meta, capability) {
		return Result{Err: &UnsupportedCapabilityError{Provider: providerID, Capability: capability}}
	}
	runner, ok := p.(ActiveRunner)
	if !ok {
		return Result{Err: &InvalidConfigError{Provider: providerID, Field: "ActiveRunner", Reason: "active provider does not implement ActiveRunner"}}
	}

	// Authorization gate — reached only for a declared capability.
	if guard == nil {
		return Result{Err: &ScopeRequiredError{Operation: string(capability), Provider: providerID}}
	}
	if err := guard.RequireTarget(string(capability), providerID, target); err != nil {
		return Result{Err: err}
	}
	// The guard touches shared state; re-check the context before running.
	if err := contextError(ctx); err != nil {
		return Result{Err: err}
	}

	return finalizeResult(runner.Probe(ctx, capability, target, input), meta, capability)
}

// metaHasCapability reports whether c is one of the provider's declared
// capabilities.
func metaHasCapability(meta ProviderMeta, c Capability) bool {
	for _, have := range meta.Capabilities {
		if have == c {
			return true
		}
	}
	return false
}

// contextError maps a nil or done context onto the subsystem's typed
// errors. A nil context is a caller bug and is rejected fail-closed rather
// than being allowed to panic. It returns nil while the context is live.
func contextError(ctx context.Context) error {
	if ctx == nil {
		return &InvalidConfigError{Provider: "executor", Field: "ctx", Reason: "nil context"}
	}
	err := ctx.Err()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %w", ErrCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrDeadlineExceeded, err)
	default:
		return err
	}
}

// finalizeResult enforces provenance on a successful Result: it must be
// internally valid AND describe exactly the provider and the request that
// produced it (ID, name, capability, activity class, disclosure class). A
// Result that already carries an error is returned unchanged.
func finalizeResult(res Result, meta ProviderMeta, requested Capability) Result {
	if res.Err != nil {
		return res
	}

	reject := func(reason string) Result {
		return Result{Err: &InvalidProvenanceError{Provider: meta.ID, Reason: reason}}
	}

	p := res.Provenance
	if err := p.Validate(); err != nil {
		return reject(err.Error())
	}
	if p.ProviderID != meta.ID {
		return reject(fmt.Sprintf("ProviderID %q does not match provider %q", p.ProviderID, meta.ID))
	}
	if p.ProviderName != meta.Name {
		return reject(fmt.Sprintf("ProviderName %q does not match provider %q", p.ProviderName, meta.Name))
	}
	if p.Capability != string(requested) {
		return reject(fmt.Sprintf("Capability %q does not match requested %q", p.Capability, requested))
	}
	if p.ActivityClass != meta.ActivityClass {
		return reject(fmt.Sprintf("ActivityClass %q does not match provider %q", p.ActivityClass, meta.ActivityClass))
	}
	if p.DisclosureClass != meta.DisclosureClass {
		return reject(fmt.Sprintf("DisclosureClass %q does not match provider %q", p.DisclosureClass, meta.DisclosureClass))
	}
	return res
}

// isNilProvider reports whether p is a nil interface or an interface holding
// a typed-nil pointer (var x *T; Register(x)) — both of which would panic
// on the first method call.
func isNilProvider(p Provider) bool {
	if p == nil {
		return true
	}
	switch v := reflect.ValueOf(p); v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return v.IsNil()
	default:
		return false
	}
}
