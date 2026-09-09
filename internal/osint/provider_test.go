// Package osint provides tests for the provider contracts and registry.
package osint

import (
	"context"
	"testing"
)

// testPassiveProvider is a minimal passive provider for testing.
type testPassiveProvider struct {
	*BaseProvider
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

func (p *testPassiveProvider) Execute(ctx context.Context, capability Capability, input any) Result {
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

func (p *testPassiveProvider) PassiveCapabilities() []Capability {
	return p.Meta().Capabilities
}

// testActiveProvider is a minimal active provider for testing.
type testActiveProvider struct {
	*BaseProvider
	scopeGuard *ScopeGuard
}

func newTestActiveProvider(guard *ScopeGuard) *testActiveProvider {
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
		scopeGuard: guard,
	}
}

func (p *testActiveProvider) Execute(ctx context.Context, capability Capability, input any) Result {
	if p.scopeGuard == nil {
		return Result{Err: &ScopeRequiredError{Operation: string(capability), Provider: p.Meta().ID}}
	}
	if capability != CapabilityPortScan {
		return Result{Err: &UnsupportedCapabilityError{Provider: p.Meta().ID, Capability: capability}}
	}
	target, ok := input.(string)
	if !ok {
		return Result{Err: &InvalidConfigError{Provider: p.Meta().ID, Field: "input", Reason: "must be string"}}
	}
	if err := p.scopeGuard.RequireTarget(string(capability), p.Meta().ID, target); err != nil {
		return Result{Err: err}
	}
	return Result{
		Data: map[string]any{"target": target, "ports": []int{80, 443}},
		Provenance: NewProvenance(
			p.Meta().ID, p.Meta().Name, string(capability),
			ActivityActive, DisclosureActive, target, "high",
		),
	}
}

func (p *testActiveProvider) ActiveCapabilities() []Capability {
	return p.Meta().Capabilities
}

func (p *testActiveProvider) RequireScope() bool { return true }

func TestProviderMetaValidation(t *testing.T) {
	// Valid passive
	p := newTestPassiveProvider()
	if err := p.ValidateMeta(); err != nil {
		t.Errorf("Valid passive meta: %v", err)
	}

	// Valid active
	guard := NewScopeGuard()
	a := newTestActiveProvider(guard)
	if err := a.ValidateMeta(); err != nil {
		t.Errorf("Valid active meta: %v", err)
	}
}

func TestPassiveProviderExecution(t *testing.T) {
	p := newTestPassiveProvider()

	// Valid capability
	res := p.Execute(context.Background(), CapabilityRDAP, "1.1.1.1")
	if !res.IsOK() {
		t.Errorf("Execute RDAP: %v", res.Err)
	}
	if res.Provenance.ProviderID != "test.passive" {
		t.Errorf("Provenance ProviderID = %q, want test.passive", res.Provenance.ProviderID)
	}
	if res.Provenance.ActivityClass != ActivityPassive {
		t.Errorf("Provenance ActivityClass = %v, want passive", res.Provenance.ActivityClass)
	}
	if res.Provenance.DisclosureClass != DisclosurePassive {
		t.Errorf("Provenance DisclosureClass = %v, want passive", res.Provenance.DisclosureClass)
	}

	// Invalid capability
	res = p.Execute(context.Background(), CapabilityPortScan, "1.1.1.1")
	if res.IsOK() {
		t.Error("Execute unsupported capability should fail")
	}
	if !IsUnsupportedCapability(res.Err) {
		t.Errorf("Error should be UnsupportedCapability: %v", res.Err)
	}
}

func TestActiveProviderExecution(t *testing.T) {
	guard := NewScopeGuard()
	guard.Authorize("test scope", []string{"192.168.1.0/24"})

	p := newTestActiveProvider(guard)

	// In scope
	res := p.Execute(context.Background(), CapabilityPortScan, "192.168.1.1")
	if !res.IsOK() {
		t.Errorf("Execute in scope: %v", res.Err)
	}
	if res.Provenance.ActivityClass != ActivityActive {
		t.Errorf("Provenance ActivityClass = %v, want active", res.Provenance.ActivityClass)
	}
	if res.Provenance.DisclosureClass != DisclosureActive {
		t.Errorf("Provenance DisclosureClass = %v, want active", res.Provenance.DisclosureClass)
	}

	// Out of scope
	res = p.Execute(context.Background(), CapabilityPortScan, "10.0.0.1")
	if res.IsOK() {
		t.Error("Execute out of scope should fail")
	}
	if !IsScopeDenied(res.Err) {
		t.Errorf("Error should be ScopeDenied: %v", res.Err)
	}

	// No scope guard
	p2 := newTestActiveProvider(nil)
	res = p2.Execute(context.Background(), CapabilityPortScan, "192.168.1.1")
	if res.IsOK() {
		t.Error("Execute without scope guard should fail")
	}
	if !IsScopeDenied(res.Err) {
		t.Errorf("Error should be ScopeDenied: %v", res.Err)
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()

	passive := newTestPassiveProvider()
	guard := NewScopeGuard()
	active := newTestActiveProvider(guard)

	// Register
	if err := reg.Register(passive); err != nil {
		t.Errorf("Register passive: %v", err)
	}
	if err := reg.Register(active); err != nil {
		t.Errorf("Register active: %v", err)
	}

	// Duplicate ID should fail
	dup := newTestPassiveProvider()
	if err := reg.Register(dup); err == nil {
		t.Error("Register duplicate ID should fail")
	}

	// Get by ID
	p, ok := reg.GetByID("test.passive")
	if !ok || p.Meta().ID != "test.passive" {
		t.Errorf("GetByID passive: ok=%v, id=%v", ok, p.Meta().ID)
	}

	// Get by capability
	providers := reg.GetByCapability(CapabilityRDAP)
	if len(providers) != 1 || providers[0].Meta().ID != "test.passive" {
		t.Errorf("GetByCapability RDAP: len=%d", len(providers))
	}

	// Get passive
	passiveList := reg.GetPassive()
	if len(passiveList) != 1 || passiveList[0].Meta().ID != "test.passive" {
		t.Errorf("GetPassive: len=%d", len(passiveList))
	}

	// Get active
	activeList := reg.GetActive()
	if len(activeList) != 1 || activeList[0].Meta().ID != "test.active" {
		t.Errorf("GetActive: len=%d", len(activeList))
	}

	// All
	all := reg.All()
	if len(all) != 2 {
		t.Errorf("All: len=%d, want 2", len(all))
	}

	// Capabilities
	caps := reg.Capabilities()
	found := false
	for _, c := range caps {
		if c == CapabilityRDAP || c == CapabilityPortScan {
			found = true
		}
	}
	if !found {
		t.Errorf("Capabilities missing: %v", caps)
	}
}

func TestRegistryInvalidMeta(t *testing.T) {
	reg := NewRegistry()

	// Missing ID
	bad := &testPassiveProvider{}
	bad.BaseProvider = &BaseProvider{
		MetaVal: ProviderMeta{
			Name:            "Bad",
			Capabilities:    []Capability{CapabilityRDAP},
			ActivityClass:   ActivityPassive,
			DisclosureClass: DisclosurePassive,
			RequiresScope:   false,
		},
	}

	err := reg.Register(bad)
	if err == nil {
		t.Error("Register with invalid meta should fail")
	}
	if !IsInvalidConfig(err) {
		t.Errorf("Error should be InvalidConfig: %v", err)
	}
}

func TestProviderCapabilities(t *testing.T) {
	p := newTestPassiveProvider()
	caps := p.PassiveCapabilities()
	if len(caps) != 2 {
		t.Errorf("PassiveCapabilities = %d, want 2", len(caps))
	}

	guard := NewScopeGuard()
	a := newTestActiveProvider(guard)
	caps = a.ActiveCapabilities()
	if len(caps) != 1 {
		t.Errorf("ActiveCapabilities = %d, want 1", len(caps))
	}
	if !a.RequireScope() {
		t.Error("Active provider RequireScope should be true")
	}
}

func TestPassiveProviderRequiresScopeFalse(t *testing.T) {
	p := newTestPassiveProvider()
	if p.Meta().RequiresScope {
		t.Error("Passive provider RequiresScope should be false")
	}
}

func TestActiveProviderRequiresScopeTrue(t *testing.T) {
	guard := NewScopeGuard()
	a := newTestActiveProvider(guard)
	if !a.Meta().RequiresScope {
		t.Error("Active provider RequiresScope should be true")
	}
}
