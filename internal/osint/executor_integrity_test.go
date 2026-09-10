// Package osint: integrity tests for the execution gate — capability
// enforcement, exact provenance matching, no fabricated data in the
// contract packages, and nil-input hardening.
package osint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ------------------------------------------------------------
// P1-04 — the contract packages ship no runnable, fabricating provider
// ------------------------------------------------------------

func TestNoFabricatedDataInContractPackages(t *testing.T) {
	// A runnable provider that returns a successful Result builds provenance
	// (NewProvenance) and/or a canned payload. The passive/ and active/
	// packages are contracts only and must contain neither.
	forbidden := []string{"NewProvenance(", "not implemented", "osint.Result{"}

	for _, dir := range []string{"passive", "active"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s/%s: %v", dir, name, err)
			}
			src := string(b)
			for _, f := range forbidden {
				if strings.Contains(src, f) {
					t.Errorf("%s/%s contains %q — contract packages must not embed a runnable provider that can fabricate a result", dir, name, f)
				}
			}
		}
	}
}

// ------------------------------------------------------------
// P1-05 — capability gate: the framework rejects an undeclared capability
// before the provider (or the ScopeGuard) is reached
// ------------------------------------------------------------

func TestExecutorPassiveUnsupportedCapability(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider() // declares RDAP, ASNMapping
	mustRegister(t, reg, pas)
	ex := NewExecutor(reg)

	res := ex.ExecutePassive(context.Background(), "test.passive", CapabilityCVE, nil)
	if !IsUnsupportedCapability(res.Err) {
		t.Errorf("want UnsupportedCapability, got %v", res.Err)
	}
	if pas.calls != 0 {
		t.Errorf("provider invoked %d times for undeclared capability, want 0", pas.calls)
	}
}

func TestExecutorActiveUnsupportedCapabilityWithValidScope(t *testing.T) {
	reg := NewRegistry()
	act := newTestActiveProvider() // declares PortScan only
	mustRegister(t, reg, act)
	ex := NewExecutor(reg)

	guard := NewScopeGuard()
	if err := guard.Authorize("lab", []string{"192.168.1.0/24"}); err != nil {
		t.Fatal(err)
	}

	res := ex.ExecuteActive(context.Background(), guard, "test.active", CapabilityTraceroute, "192.168.1.1", nil)
	if !IsUnsupportedCapability(res.Err) {
		t.Errorf("want UnsupportedCapability, got %v", res.Err)
	}
	if act.calls != 0 {
		t.Errorf("provider invoked %d times for undeclared capability, want 0", act.calls)
	}
}

// Documented order: capability support (step 4) is checked BEFORE the active
// scope gate (step 5). So an undeclared capability yields
// UnsupportedCapability even when the guard is nil — the ScopeGuard is
// never consulted for a capability the provider did not declare.
func TestExecutorActiveUnsupportedCapabilityNoGuard(t *testing.T) {
	reg := NewRegistry()
	mal := newMaliciousActive() // declares PortScan only
	mustRegister(t, reg, mal)
	ex := NewExecutor(reg)

	res := ex.ExecuteActive(context.Background(), nil, "mal.active", CapabilityActiveDNS, "192.168.1.1", nil)
	if !IsUnsupportedCapability(res.Err) {
		t.Errorf("want UnsupportedCapability (capability checked before scope), got %v", res.Err)
	}
	if mal.calls != 0 {
		t.Errorf("provider invoked %d times, want 0", mal.calls)
	}
}

// ------------------------------------------------------------
// P1-06 — provenance must describe the execution exactly
// ------------------------------------------------------------

// riggedProvider returns success with a provenance we fully control.
type riggedProvider struct {
	meta ProviderMeta
	prov Provenance
}

func (p *riggedProvider) Meta() ProviderMeta { return p.meta }

func (p *riggedProvider) Lookup(ctx context.Context, capability Capability, input any) Result {
	return Result{Data: map[string]string{"ok": "1"}, Provenance: p.prov}
}

func TestExecutorProvenanceMustMatchExecution(t *testing.T) {
	meta := ProviderMeta{
		ID:              "rig.passive",
		Name:            "Rigged Passive",
		Capabilities:    []Capability{CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}
	// A provenance that correctly describes an RDAP execution of this provider.
	good := NewProvenance(meta.ID, meta.Name, string(CapabilityRDAP), ActivityPassive, DisclosurePassive, "e", "alta")

	tests := []struct {
		name    string
		prov    Provenance
		wantErr bool
	}{
		{"correct", good, false},
		{
			name:    "provider id mismatch",
			prov:    NewProvenance("other.id", meta.Name, string(CapabilityRDAP), ActivityPassive, DisclosurePassive, "e", "alta"),
			wantErr: true,
		},
		{
			name:    "provider name mismatch",
			prov:    NewProvenance(meta.ID, "Wrong Name", string(CapabilityRDAP), ActivityPassive, DisclosurePassive, "e", "alta"),
			wantErr: true,
		},
		{
			name:    "capability mismatch",
			prov:    NewProvenance(meta.ID, meta.Name, string(CapabilityCVE), ActivityPassive, DisclosurePassive, "e", "alta"),
			wantErr: true,
		},
		{
			name:    "disclosure mismatch",
			prov:    NewProvenance(meta.ID, meta.Name, string(CapabilityRDAP), ActivityPassive, DisclosureLocal, "e", "alta"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewRegistry()
			mustRegister(t, reg, &riggedProvider{meta: meta, prov: tt.prov})
			ex := NewExecutor(reg)

			res := ex.ExecutePassive(context.Background(), meta.ID, CapabilityRDAP, nil)
			if tt.wantErr {
				if !IsInvalidProvenance(res.Err) {
					t.Errorf("want InvalidProvenance, got %v", res.Err)
				}
				if res.Data != nil {
					t.Errorf("rejected result must drop Data, got %v", res.Data)
				}
				if res.IsOK() {
					t.Error("result must not be OK")
				}
			} else if !res.IsOK() {
				t.Errorf("correct provenance must pass, got %v", res.Err)
			}
		})
	}
}

// The activity-class mismatch case for an active provider (covered for
// passive by TestExecutorProvenanceMustMatchExecution via disclosure).
type riggedActive struct {
	meta ProviderMeta
	prov Provenance
}

func (p *riggedActive) Meta() ProviderMeta { return p.meta }

func (p *riggedActive) Probe(ctx context.Context, capability Capability, target string, input any) Result {
	return Result{Data: "x", Provenance: p.prov}
}

func TestExecutorActiveProvenanceActivityMismatch(t *testing.T) {
	meta := ProviderMeta{
		ID:              "rig.active",
		Name:            "Rigged Active",
		Capabilities:    []Capability{CapabilityPortScan},
		ActivityClass:   ActivityActive,
		DisclosureClass: DisclosureActive,
		RequiresScope:   true,
	}
	// Internally-valid provenance (passive + DisclosurePassive) that still
	// does not describe THIS active provider's execution.
	prov := NewProvenance(meta.ID, meta.Name, string(CapabilityPortScan), ActivityPassive, DisclosurePassive, "t", "alta")

	reg := NewRegistry()
	mustRegister(t, reg, &riggedActive{meta: meta, prov: prov})
	ex := NewExecutor(reg)

	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})

	res := ex.ExecuteActive(context.Background(), guard, meta.ID, CapabilityPortScan, "192.168.1.1", nil)
	if !IsInvalidProvenance(res.Err) {
		t.Errorf("want InvalidProvenance for activity-class mismatch, got %v", res.Err)
	}
	if res.Data != nil {
		t.Errorf("rejected result must drop Data, got %v", res.Data)
	}
}

// ------------------------------------------------------------
// P1-08 — invalid / duplicate capabilities block registration, so the
// provider can never be reached
// ------------------------------------------------------------

func TestRegistryRejectsInvalidCapabilitiesAndProviderNeverRuns(t *testing.T) {
	reg := NewRegistry()

	// Passive provider, empty/unknown capability.
	np := &noProvenanceProvider{meta: ProviderMeta{
		ID:              "bad.caps",
		Name:            "Bad Caps",
		Capabilities:    []Capability{CapabilityUnknown},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}}
	if err := reg.Register(np); err == nil || !IsInvalidConfig(err) {
		t.Fatalf("Register with unknown capability must fail as InvalidConfig, got %v", err)
	}

	// Active provider, unknown capability.
	act := &maliciousActiveProvider{meta: ProviderMeta{
		ID:              "bad.active.caps",
		Name:            "Bad Active Caps",
		Capabilities:    []Capability{CapabilityUnknown},
		ActivityClass:   ActivityActive,
		DisclosureClass: DisclosureActive,
		RequiresScope:   true,
	}}
	if err := reg.Register(act); err == nil || !IsInvalidConfig(err) {
		t.Fatalf("active Register with unknown capability must fail, got %v", err)
	}

	// Duplicate capabilities.
	dup := &noProvenanceProvider{meta: ProviderMeta{
		ID:              "dup.caps",
		Name:            "Dup Caps",
		Capabilities:    []Capability{CapabilityRDAP, CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}}
	if err := reg.Register(dup); err == nil || !IsInvalidConfig(err) {
		t.Fatalf("Register with duplicate capability must fail, got %v", err)
	}

	// None registered → the Executor cannot reach any of them.
	ex := NewExecutor(reg)
	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})

	if res := ex.ExecutePassive(context.Background(), "bad.caps", CapabilityRDAP, nil); res.Err == nil {
		t.Error("passive: an unregistered provider must not be executable")
	}
	if res := ex.ExecuteActive(context.Background(), guard, "bad.active.caps", CapabilityPortScan, "192.168.1.1", nil); res.Err == nil {
		t.Error("active: an unregistered provider must not be executable")
	}
	if np.calls != 0 || act.calls != 0 || dup.calls != 0 {
		t.Errorf("providers with invalid metadata ran (np=%d act=%d dup=%d), want 0", np.calls, act.calls, dup.calls)
	}
}

// A provider that declares multiple unique capabilities registers and each
// declared capability is executable; an undeclared one is still gated.
func TestRegistryAcceptsMultipleUniqueCapabilities(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider() // declares RDAP + ASNMapping
	mustRegister(t, reg, pas)
	ex := NewExecutor(reg)

	for _, c := range []Capability{CapabilityRDAP, CapabilityASNMapping} {
		if res := ex.ExecutePassive(context.Background(), "test.passive", c, "x"); !res.IsOK() {
			t.Errorf("declared capability %q should execute, got %v", c, res.Err)
		}
	}
	if res := ex.ExecutePassive(context.Background(), "test.passive", CapabilityCVE, "x"); !IsUnsupportedCapability(res.Err) {
		t.Errorf("undeclared capability should be gated, got %v", res.Err)
	}
}

// ------------------------------------------------------------
// P2 — nil / typed-nil hardening
// ------------------------------------------------------------

func TestRegistryRejectsTypedNilProvider(t *testing.T) {
	reg := NewRegistry()

	var untyped Provider
	if err := reg.Register(untyped); err == nil {
		t.Error("Register(nil interface) should error")
	}

	var typedNil *testActiveProvider // nil pointer boxed into the interface
	if err := reg.Register(typedNil); err == nil {
		t.Error("Register(typed-nil provider) should error, not panic")
	}
}

func TestExecutorNilContextRejected(t *testing.T) {
	reg := NewRegistry()
	pas := newTestPassiveProvider()
	act := newMaliciousActive()
	mustRegister(t, reg, pas)
	mustRegister(t, reg, act)
	ex := NewExecutor(reg)

	var nilCtx context.Context

	res := ex.ExecutePassive(nilCtx, "test.passive", CapabilityRDAP, nil)
	if !IsInvalidConfig(res.Err) {
		t.Errorf("passive: nil context should yield InvalidConfig, got %v", res.Err)
	}
	if pas.calls != 0 {
		t.Errorf("passive provider invoked %d times with nil ctx, want 0", pas.calls)
	}

	guard := NewScopeGuard()
	_ = guard.Authorize("lab", []string{"192.168.1.0/24"})
	res = ex.ExecuteActive(nilCtx, guard, "mal.active", CapabilityPortScan, "192.168.1.1", nil)
	if !IsInvalidConfig(res.Err) {
		t.Errorf("active: nil context should yield InvalidConfig, got %v", res.Err)
	}
	if act.calls != 0 {
		t.Errorf("active provider invoked %d times with nil ctx, want 0", act.calls)
	}
}
