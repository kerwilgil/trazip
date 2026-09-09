// Package osint: tests that the execution gate enforces the passive/active
// safety invariants regardless of provider cooperation.
package osint

import (
	"context"
	"testing"
	"time"
)

// ------------------------------------------------------------
// A deliberately unsafe active provider: it declares itself active and
// scope-requiring, returns success, and performs NO scope check of its own.
// It also counts how many times its code was actually entered.
// ------------------------------------------------------------

type maliciousActiveProvider struct {
	meta  ProviderMeta
	calls int
}

func newMaliciousActive() *maliciousActiveProvider {
	return &maliciousActiveProvider{meta: ProviderMeta{
		ID:              "mal.active",
		Name:            "Malicious Active",
		Capabilities:    []Capability{CapabilityPortScan},
		ActivityClass:   ActivityActive,
		DisclosureClass: DisclosureActive,
		RequiresScope:   true,
		RateLimit:       "n/a",
	}}
}

func (m *maliciousActiveProvider) Meta() ProviderMeta { return m.meta }

func (m *maliciousActiveProvider) Probe(ctx context.Context, capability Capability, target string, input any) Result {
	m.calls++ // records that provider code ran
	return Result{
		Data: map[string]string{"target": target, "status": "pwned"},
		Provenance: NewProvenance(
			m.meta.ID, m.meta.Name, string(capability),
			ActivityActive, DisclosureActive, target, "alta",
		),
	}
}

func mustRegister(t *testing.T, reg *Registry, p Provider) {
	t.Helper()
	if err := reg.Register(p); err != nil {
		t.Fatalf("register %T: %v", p, err)
	}
}

// TestExecutorActiveBypassPrevention is the mandatory bypass test: the
// FRAMEWORK, not the provider, must stop unauthorized active execution.
func TestExecutorActiveBypassPrevention(t *testing.T) {
	const id = "mal.active"
	const cap = CapabilityPortScan

	// A. active execution with NO guard -> reject, provider not invoked.
	t.Run("A_no_guard", func(t *testing.T) {
		reg := NewRegistry()
		mal := newMaliciousActive()
		mustRegister(t, reg, mal)
		ex := NewExecutor(reg)

		res := ex.ExecuteActive(context.Background(), nil, id, cap, "192.168.1.1", nil)
		if res.Err == nil || !IsScopeDenied(res.Err) {
			t.Errorf("want scope denied, got err=%v", res.Err)
		}
		if !res.IsOK() {
			// expected
		} else {
			t.Error("result must not be OK")
		}
		if mal.calls != 0 {
			t.Errorf("provider invoked %d times, want 0", mal.calls)
		}
	})

	// B. active execution with an UNAUTHORIZED guard -> reject.
	t.Run("B_unauthorized_guard", func(t *testing.T) {
		reg := NewRegistry()
		mal := newMaliciousActive()
		mustRegister(t, reg, mal)
		ex := NewExecutor(reg)

		guard := NewScopeGuard() // never Authorize()d
		res := ex.ExecuteActive(context.Background(), guard, id, cap, "192.168.1.1", nil)
		if res.Err == nil || !IsScopeDenied(res.Err) {
			t.Errorf("want scope denied, got err=%v", res.Err)
		}
		if mal.calls != 0 {
			t.Errorf("provider invoked %d times, want 0", mal.calls)
		}
	})

	// C. authorized guard but target OUT OF SCOPE -> reject.
	t.Run("C_target_out_of_scope", func(t *testing.T) {
		reg := NewRegistry()
		mal := newMaliciousActive()
		mustRegister(t, reg, mal)
		ex := NewExecutor(reg)

		guard := NewScopeGuard()
		if err := guard.Authorize("lab", []string{"10.0.0.0/24"}); err != nil {
			t.Fatal(err)
		}
		res := ex.ExecuteActive(context.Background(), guard, id, cap, "192.168.1.1", nil)
		if res.Err == nil || !IsScopeDenied(res.Err) {
			t.Errorf("want scope denied, got err=%v", res.Err)
		}
		if mal.calls != 0 {
			t.Errorf("provider invoked %d times, want 0", mal.calls)
		}
	})

	// D. authorized guard AND target in scope -> pass, provider invoked once.
	t.Run("D_authorized_in_scope", func(t *testing.T) {
		reg := NewRegistry()
		mal := newMaliciousActive()
		mustRegister(t, reg, mal)
		ex := NewExecutor(reg)

		guard := NewScopeGuard()
		if err := guard.Authorize("lab", []string{"192.168.1.0/24"}); err != nil {
			t.Fatal(err)
		}
		res := ex.ExecuteActive(context.Background(), guard, id, cap, "192.168.1.1", nil)
		if !res.IsOK() {
			t.Errorf("want success, got err=%v", res.Err)
		}
		if mal.calls != 1 {
			t.Errorf("provider invoked %d times, want 1", mal.calls)
		}
	})

	// E. active provider pushed through the PASSIVE pipeline -> reject.
	t.Run("E_active_via_passive_pipeline", func(t *testing.T) {
		reg := NewRegistry()
		mal := newMaliciousActive()
		mustRegister(t, reg, mal)
		ex := NewExecutor(reg)

		res := ex.ExecutePassive(context.Background(), id, cap, nil)
		if res.Err == nil || !IsActivityViolation(res.Err) {
			t.Errorf("want activity violation, got err=%v", res.Err)
		}
		if mal.calls != 0 {
			t.Errorf("provider invoked %d times, want 0", mal.calls)
		}
	})
}

// TestExecutorPassivePipelineRejectsActive is the mirror of case E via a
// well-behaved active provider.
func TestExecutorPassivePipelineRejectsActive(t *testing.T) {
	reg := NewRegistry()
	act := newTestActiveProvider()
	mustRegister(t, reg, act)
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "test.active", CapabilityPortScan, nil)
	if !IsActivityViolation(res.Err) {
		t.Errorf("want activity violation, got %v", res.Err)
	}
	if act.calls != 0 {
		t.Errorf("active provider invoked %d times via passive pipeline, want 0", act.calls)
	}
}

// TestExecutorActivePipelineRejectsPassive: a passive provider cannot be run
// through ExecuteActive even with a valid guard.
func TestExecutorActivePipelineRejectsPassive(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider()
	mustRegister(t, reg, pas)
	ex := NewExecutor(reg)

	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})

	res := ex.ExecuteActive(context.Background(), guard, "test.passive", CapabilityRDAP, "192.168.1.1", nil)
	if !IsActivityViolation(res.Err) {
		t.Errorf("want activity violation, got %v", res.Err)
	}
	if pas.calls != 0 {
		t.Errorf("passive provider invoked %d times via active pipeline, want 0", pas.calls)
	}
}

func TestExecutorPassiveHappyPath(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider()
	mustRegister(t, reg, pas)
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "test.passive", CapabilityRDAP, "1.1.1.1")
	if !res.IsOK() {
		t.Fatalf("passive execute: %v", res.Err)
	}
	if res.Provenance.ProviderID != "test.passive" || res.Provenance.ActivityClass != ActivityPassive {
		t.Errorf("bad provenance: %+v", res.Provenance)
	}
	if pas.calls != 1 {
		t.Errorf("provider calls = %d, want 1", pas.calls)
	}
}

func TestExecutorUnknownProvider(t *testing.T) {
	ex := NewExecutor(NewRegistry())
	if res := ex.ExecutePassive(context.Background(), "ghost", CapabilityRDAP, nil); res.Err == nil {
		t.Error("passive: unknown provider should error")
	}
	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})
	if res := ex.ExecuteActive(context.Background(), guard, "ghost", CapabilityPortScan, "192.168.1.1", nil); res.Err == nil {
		t.Error("active: unknown provider should error")
	}
}

// ------------------------------------------------------------
// P1-03 — provenance is enforced by the framework
// ------------------------------------------------------------

type noProvenanceProvider struct {
	meta  ProviderMeta
	calls int
}

func (p *noProvenanceProvider) Meta() ProviderMeta { return p.meta }

func (p *noProvenanceProvider) Lookup(ctx context.Context, capability Capability, input any) Result {
	p.calls++
	// Success (Err == nil), Data set, Provenance left zero-valued.
	return Result{Data: map[string]string{"x": "y"}}
}

func TestExecutorRejectsSuccessWithoutProvenance(t *testing.T) {
	reg := NewRegistry()
	p := &noProvenanceProvider{meta: ProviderMeta{
		ID:              "np.passive",
		Name:            "No Provenance",
		Capabilities:    []Capability{CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}}
	mustRegister(t, reg, p)
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "np.passive", CapabilityRDAP, nil)
	if res.Err == nil || !IsInvalidProvenance(res.Err) {
		t.Errorf("want invalid-provenance error, got %v", res.Err)
	}
	if res.IsOK() {
		t.Error("result must not be OK")
	}
	if res.Data != nil {
		t.Errorf("rejected result must not carry Data, got %v", res.Data)
	}
	if p.calls != 1 {
		t.Errorf("provider calls = %d, want 1 (it ran, framework rejected its output)", p.calls)
	}
}

// mismatchedProvenanceProvider returns provenance for a different provider.
type mismatchedProvenanceProvider struct{ meta ProviderMeta }

func (p *mismatchedProvenanceProvider) Meta() ProviderMeta { return p.meta }

func (p *mismatchedProvenanceProvider) Lookup(ctx context.Context, capability Capability, input any) Result {
	return Result{
		Data: "x",
		Provenance: NewProvenance(
			"someone.else", "Someone Else", string(capability),
			ActivityPassive, DisclosurePassive, "e", "alta",
		),
	}
}

func TestExecutorRejectsProvenanceIdentityMismatch(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, &mismatchedProvenanceProvider{meta: ProviderMeta{
		ID:              "mm.passive",
		Name:            "Mismatch",
		Capabilities:    []Capability{CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}})
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "mm.passive", CapabilityRDAP, nil)
	if !IsInvalidProvenance(res.Err) {
		t.Errorf("want invalid-provenance error, got %v", res.Err)
	}
}

// failingBeforeWorkProvider fails prior to any external work and returns no
// provenance — the framework must NOT convert this into a provenance error.
type failingBeforeWorkProvider struct{ meta ProviderMeta }

func (p *failingBeforeWorkProvider) Meta() ProviderMeta { return p.meta }

func (p *failingBeforeWorkProvider) Lookup(ctx context.Context, capability Capability, input any) Result {
	return Result{Err: &UnsupportedCapabilityError{Provider: p.meta.ID, Capability: capability}}
}

func TestExecutorPassesThroughPreExecutionFailure(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, &failingBeforeWorkProvider{meta: ProviderMeta{
		ID:              "fb.passive",
		Name:            "Fails Before Work",
		Capabilities:    []Capability{CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}})
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "fb.passive", CapabilityCVE, nil)
	if !IsUnsupportedCapability(res.Err) {
		t.Errorf("want the provider's own UnsupportedCapability error, got %v", res.Err)
	}
	if IsInvalidProvenance(res.Err) {
		t.Error("a pre-execution failure must not be reclassified as a provenance error")
	}
}

// ------------------------------------------------------------
// Context — the gate must not invoke the provider on a dead context
// ------------------------------------------------------------

func TestExecutorContextAlreadyCanceled(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider()
	act := newMaliciousActive()
	mustRegister(t, reg, pas)
	mustRegister(t, reg, act)
	ex := NewExecutor(reg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if res := ex.ExecutePassive(ctx, "test.passive", CapabilityRDAP, nil); !IsCanceled(res.Err) {
		t.Errorf("passive: want canceled, got %v", res.Err)
	}
	if pas.calls != 0 {
		t.Errorf("passive provider invoked %d times on canceled ctx, want 0", pas.calls)
	}

	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})
	if res := ex.ExecuteActive(ctx, guard, "mal.active", CapabilityPortScan, "192.168.1.1", nil); !IsCanceled(res.Err) {
		t.Errorf("active: want canceled, got %v", res.Err)
	}
	if act.calls != 0 {
		t.Errorf("active provider invoked %d times on canceled ctx, want 0", act.calls)
	}
}

func TestExecutorContextDeadlineExceeded(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider()
	act := newMaliciousActive()
	mustRegister(t, reg, pas)
	mustRegister(t, reg, act)
	ex := NewExecutor(reg)

	// A deadline already in the past: context.WithDeadline cancels the
	// context synchronously in its constructor, so ctx.Err() is
	// deterministically DeadlineExceeded with no timer-goroutine race.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	if res := ex.ExecutePassive(ctx, "test.passive", CapabilityRDAP, nil); !IsDeadlineExceeded(res.Err) {
		t.Errorf("passive: want deadline exceeded, got %v", res.Err)
	}
	if pas.calls != 0 {
		t.Errorf("passive provider invoked %d times past deadline, want 0", pas.calls)
	}

	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})
	if res := ex.ExecuteActive(ctx, guard, "mal.active", CapabilityPortScan, "192.168.1.1", nil); !IsDeadlineExceeded(res.Err) {
		t.Errorf("active: want deadline exceeded, got %v", res.Err)
	}
	if act.calls != 0 {
		t.Errorf("active provider invoked %d times past deadline, want 0", act.calls)
	}
}
