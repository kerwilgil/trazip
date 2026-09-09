// Package osint provides tests for the provider contracts and registry.
package osint

import (
	"context"
	"testing"
)

// ------------------------------------------------------------
// Well-behaved synthetic providers
// ------------------------------------------------------------

type testPassiveProvider struct {
	*BaseProvider
	calls int
}

func newTestPassiveProvider() *testPassiveProvider {
	return &testPassiveProvider{
		BaseProvider: &BaseProvider{
			MetaVal: ProviderMeta{
				ID:              "test.passive",
				Name:            "Test Passive",
				Capabilities:    []Capability{CapabilityRDAP, CapabilityASNMapping},
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   false,
				RateLimit:       "60/min",
			},
		},
	}
}

func (p *testPassiveProvider) Lookup(ctx context.Context, capability Capability, input any) Result {
	p.calls++
	if capability != CapabilityRDAP && capability != CapabilityASNMapping {
		return Result{Err: &UnsupportedCapabilityError{Provider: p.Meta().ID, Capability: capability}}
	}
	return Result{
		Data: map[string]string{"capability": string(capability)},
		Provenance: NewProvenance(
			p.Meta().ID, p.Meta().Name, string(capability),
			ActivityPassive, DisclosurePassive, "test", "alta",
		),
	}
}

type testActiveProvider struct {
	*BaseProvider
	calls int
}

func newTestActiveProvider() *testActiveProvider {
	return &testActiveProvider{
		BaseProvider: &BaseProvider{
			MetaVal: ProviderMeta{
				ID:              "test.active",
				Name:            "Test Active",
				Capabilities:    []Capability{CapabilityPortScan},
				ActivityClass:   ActivityActive,
				DisclosureClass: DisclosureActive,
				RequiresScope:   true,
				RateLimit:       "10/sec",
			},
		},
	}
}

func (p *testActiveProvider) Probe(ctx context.Context, capability Capability, target string, input any) Result {
	p.calls++
	if capability != CapabilityPortScan {
		return Result{Err: &UnsupportedCapabilityError{Provider: p.Meta().ID, Capability: capability}}
	}
	return Result{
		Data: map[string]any{"target": target, "ports": []int{80, 443}},
		Provenance: NewProvenance(
			p.Meta().ID, p.Meta().Name, string(capability),
			ActivityActive, DisclosureActive, target, "alta",
		),
	}
}

// ------------------------------------------------------------
// Registry
// ------------------------------------------------------------

func TestRegistryRegisterAndLookup(t *testing.T) {
	reg := NewRegistry()

	if err := reg.Register(newTestPassiveProvider()); err != nil {
		t.Fatalf("register passive: %v", err)
	}
	if err := reg.Register(newTestActiveProvider()); err != nil {
		t.Fatalf("register active: %v", err)
	}

	if err := reg.Register(newTestPassiveProvider()); err == nil {
		t.Error("duplicate provider ID should be rejected")
	}
	if err := reg.Register(nil); err == nil {
		t.Error("nil provider should be rejected")
	}

	meta, ok := reg.Lookup("test.passive")
	if !ok || meta.ID != "test.passive" || meta.ActivityClass != ActivityPassive {
		t.Errorf("Lookup(test.passive) = %+v, ok=%v", meta, ok)
	}
	if _, ok := reg.Lookup("nope"); ok {
		t.Error("Lookup of unknown ID should report not found")
	}

	if got := reg.MetasByCapability(CapabilityRDAP); len(got) != 1 || got[0].ID != "test.passive" {
		t.Errorf("MetasByCapability(RDAP) = %+v", got)
	}
	if got := reg.PassiveMetas(); len(got) != 1 || got[0].ID != "test.passive" {
		t.Errorf("PassiveMetas = %+v", got)
	}
	if got := reg.ActiveMetas(); len(got) != 1 || got[0].ID != "test.active" {
		t.Errorf("ActiveMetas = %+v", got)
	}
	if got := reg.AllMetas(); len(got) != 2 {
		t.Errorf("AllMetas len = %d, want 2", len(got))
	}

	seen := map[Capability]bool{}
	for _, c := range reg.Capabilities() {
		seen[c] = true
	}
	if !seen[CapabilityRDAP] || !seen[CapabilityPortScan] {
		t.Errorf("Capabilities missing entries: %v", reg.Capabilities())
	}
}

func TestRegistryRejectsInvalidMeta(t *testing.T) {
	reg := NewRegistry()
	bad := &testPassiveProvider{BaseProvider: &BaseProvider{MetaVal: ProviderMeta{
		Name:            "Bad",
		Capabilities:    []Capability{CapabilityRDAP},
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}}}
	err := reg.Register(bad)
	if err == nil || !IsInvalidConfig(err) {
		t.Errorf("register with missing ID should fail as InvalidConfig, got %v", err)
	}
}

// runnerlessActive declares ActivityActive but implements no ActiveRunner.
type runnerlessActive struct{ *BaseProvider }

func TestRegistryRejectsClassRunnerMismatch(t *testing.T) {
	reg := NewRegistry()
	p := &runnerlessActive{BaseProvider: &BaseProvider{MetaVal: ProviderMeta{
		ID:              "no.runner",
		Name:            "No Runner",
		Capabilities:    []Capability{CapabilityPortScan},
		ActivityClass:   ActivityActive,
		DisclosureClass: DisclosureActive,
		RequiresScope:   true,
	}}}
	err := reg.Register(p)
	if err == nil || !IsInvalidConfig(err) {
		t.Errorf("active provider without ActiveRunner should be rejected, got %v", err)
	}
}

// TestRegistryCapabilitiesDefensiveCopy proves a caller cannot mutate
// registry state through the Capabilities slice it passed in, nor through
// the slice it gets back.
func TestRegistryCapabilitiesDefensiveCopy(t *testing.T) {
	reg := NewRegistry()

	caps := []Capability{CapabilityRDAP, CapabilityASNMapping}
	p := &testPassiveProvider{BaseProvider: &BaseProvider{MetaVal: ProviderMeta{
		ID:              "copy.passive",
		Name:            "Copy Passive",
		Capabilities:    caps,
		ActivityClass:   ActivityPassive,
		DisclosureClass: DisclosurePassive,
	}}}
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}

	caps[0] = CapabilityPortScan // mutate the caller's original slice

	meta, _ := reg.Lookup("copy.passive")
	if meta.Capabilities[0] != CapabilityRDAP {
		t.Errorf("registry meta mutated via caller slice: %v", meta.Capabilities)
	}

	meta.Capabilities[0] = CapabilityCVE // mutate the returned copy
	again, _ := reg.Lookup("copy.passive")
	if again.Capabilities[0] != CapabilityRDAP {
		t.Errorf("registry meta mutated via returned slice: %v", again.Capabilities)
	}
}

func TestBaseProviderValidateMeta(t *testing.T) {
	if err := newTestPassiveProvider().ValidateMeta(); err != nil {
		t.Errorf("valid passive meta: %v", err)
	}
	if err := newTestActiveProvider().ValidateMeta(); err != nil {
		t.Errorf("valid active meta: %v", err)
	}
}
