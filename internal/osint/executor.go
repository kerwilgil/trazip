// Package osint: the central execution gate.
//
// Executor is the only supported way to run a registered provider. Before
// any provider code runs it enforces, in order:
//
//   - the context is not already done;
//   - the passive pipeline rejects anything that is not a passive provider;
//   - the active pipeline requires an explicit, authorized ScopeGuard and
//     an in-scope target — a nil guard, an unauthorized guard, or an
//     out-of-scope target each reject the call fail-closed.
//
// After the provider returns, a successful Result that lacks valid
// provenance (or whose provenance does not describe this provider and
// pipeline) is converted to a fail-closed error. A Result that already
// carries an error is passed through untouched — a provider that failed
// before gathering intelligence owes no provenance.
package osint

import (
	"context"
	"errors"
	"fmt"
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

// ExecutePassive runs a passive provider by ID. An active provider, or one
// that does not implement PassiveRunner, is rejected before its code runs.
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
	runner, ok := p.(PassiveRunner)
	if !ok {
		return Result{Err: &InvalidConfigError{Provider: providerID, Field: "PassiveRunner", Reason: "passive provider does not implement PassiveRunner"}}
	}

	return finalizeResult(runner.Lookup(ctx, capability, input), meta)
}

// ExecuteActive runs an active provider by ID. It is fail-closed: guard nil,
// guard unauthorized, or target out of scope each reject the call before
// the provider's Probe is invoked.
func (e *Executor) ExecuteActive(ctx context.Context, guard *ScopeGuard, providerID string, capability Capability, target string, input any) Result {
	if err := contextError(ctx); err != nil {
		return Result{Err: err}
	}
	if guard == nil {
		return Result{Err: &ScopeRequiredError{Operation: string(capability), Provider: providerID}}
	}

	p, meta, ok := e.reg.provider(providerID)
	if !ok {
		return Result{Err: fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)}
	}
	if meta.ActivityClass != ActivityActive {
		return Result{Err: &ActivityViolationError{Provider: providerID, Pipeline: ActivityActive, Actual: meta.ActivityClass}}
	}
	runner, ok := p.(ActiveRunner)
	if !ok {
		return Result{Err: &InvalidConfigError{Provider: providerID, Field: "ActiveRunner", Reason: "active provider does not implement ActiveRunner"}}
	}

	// Authorization gate: no scope, or target outside it, stops here — the
	// provider is never invoked.
	if err := guard.RequireTarget(string(capability), providerID, target); err != nil {
		return Result{Err: err}
	}
	// The guard touches shared state; re-check the context before running.
	if err := contextError(ctx); err != nil {
		return Result{Err: err}
	}

	return finalizeResult(runner.Probe(ctx, capability, target, input), meta)
}

// contextError maps a done context onto the subsystem's typed sentinels so
// callers can use IsCanceled / IsDeadlineExceeded. It returns nil while the
// context is still live.
func contextError(ctx context.Context) error {
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

// finalizeResult enforces provenance on a successful Result. A Result that
// already carries an error is returned unchanged.
func finalizeResult(res Result, meta ProviderMeta) Result {
	if res.Err != nil {
		return res
	}
	if err := res.Provenance.Validate(); err != nil {
		return Result{Err: &InvalidProvenanceError{Provider: meta.ID, Reason: err.Error()}}
	}
	if res.Provenance.ProviderID != meta.ID {
		return Result{Err: &InvalidProvenanceError{
			Provider: meta.ID,
			Reason:   fmt.Sprintf("provenance ProviderID %q does not match provider %q", res.Provenance.ProviderID, meta.ID),
		}}
	}
	if res.Provenance.ActivityClass != meta.ActivityClass {
		return Result{Err: &InvalidProvenanceError{
			Provider: meta.ID,
			Reason:   fmt.Sprintf("provenance ActivityClass %q does not match provider %q", res.Provenance.ActivityClass, meta.ActivityClass),
		}}
	}
	return res
}
