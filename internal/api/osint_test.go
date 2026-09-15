package api

import (
	"context"
	"encoding/json"
	"testing"

	"trazip/internal/osint"
)

// The OSINT Intelligence UI (V1.5-3) consumes ListOSINTProviders as its only
// backend contract. These tests pin that contract: an array even when empty,
// exact metadata passthrough, deterministic ordering, and no field that could
// ever carry a runnable provider or a secret.

// fakeOSINTPassive / fakeOSINTActive are test-only providers. They implement
// the runner interfaces so Registry.Register accepts them, but their Lookup /
// Probe are never reached here — ListOSINTProviders only reads metadata.
type fakeOSINTPassive struct{ meta osint.ProviderMeta }

func (f *fakeOSINTPassive) Meta() osint.ProviderMeta { return f.meta }
func (f *fakeOSINTPassive) Lookup(context.Context, osint.Capability, any) osint.Result {
	return osint.Result{}
}

type fakeOSINTActive struct{ meta osint.ProviderMeta }

func (f *fakeOSINTActive) Meta() osint.ProviderMeta { return f.meta }
func (f *fakeOSINTActive) Probe(context.Context, osint.Capability, string, any) osint.Result {
	return osint.Result{}
}

func TestListOSINTProvidersEmptyRegistryIsArrayNotNull(t *testing.T) {
	s := NewService()
	defer s.Close()

	got := s.ListOSINTProviders()
	if got == nil {
		t.Fatal("ListOSINTProviders returned nil; the frontend contract requires an array")
	}
	// V1.5-6: infrastructure intelligence provider is registered by default
	if len(got) != 1 {
		t.Fatalf("a fresh registry must expose the infrastructure provider, got %d", len(got))
	}
	if got[0].ID != "infra.intelligence" {
		t.Fatalf("expected infrastructure provider, got %s", got[0].ID)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 provider in JSON array, got %d", len(arr))
	}
}

func TestListOSINTProvidersSerializesMetadataFaithfully(t *testing.T) {
	s := NewService()
	defer s.Close()

	passive := &fakeOSINTPassive{meta: osint.ProviderMeta{
		ID:              "rdap.example",
		Name:            "RDAP (example)",
		Capabilities:    []osint.Capability{osint.CapabilityRDAP, osint.CapabilityASNMapping},
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RequiresScope:   false,
		RateLimit:       "1 req/s",
	}}
	active := &fakeOSINTActive{meta: osint.ProviderMeta{
		ID:              "portscan.example",
		Name:            "Port scan (example)",
		Capabilities:    []osint.Capability{osint.CapabilityPortScan},
		ActivityClass:   osint.ActivityActive,
		DisclosureClass: osint.DisclosureActive,
		RequiresScope:   true,
	}}
	if err := s.osintRegistry.Register(passive); err != nil {
		t.Fatalf("register passive: %v", err)
	}
	if err := s.osintRegistry.Register(active); err != nil {
		t.Fatalf("register active: %v", err)
	}

	got := s.ListOSINTProviders()
	// V1.5-6: infrastructure provider + 2 test providers = 3 total
	if len(got) != 3 {
		t.Fatalf("got %d providers, want 3", len(got))
	}

	// Deterministic ordering: sorted by ID regardless of registration order
	// (AllMetas iterates a map).
	if got[0].ID != "infra.intelligence" || got[1].ID != "portscan.example" || got[2].ID != "rdap.example" {
		t.Fatalf("providers not sorted by ID: %s, %s, %s", got[0].ID, got[1].ID, got[2].ID)
	}

	rdapInfo, portInfo, infraInfo := got[2], got[1], got[0]

	if infraInfo.ID != "infra.intelligence" {
		t.Errorf("infrastructure provider missing: %s", infraInfo.ID)
	}
	if infraInfo.Name != "Internet Infrastructure Intelligence" {
		t.Errorf("infrastructure provider name not preserved: %q", infraInfo.Name)
	}
	if len(infraInfo.Capabilities) != 5 {
		t.Errorf("infrastructure provider capabilities count wrong: %v", infraInfo.Capabilities)
	}
	if infraInfo.ActivityClass != "passive" || infraInfo.DisclosureClass != "passive" {
		t.Errorf("infrastructure classes wrong: %s / %s", infraInfo.ActivityClass, infraInfo.DisclosureClass)
	}
	if infraInfo.RequiresScope {
		t.Error("infrastructure provider must not require scope")
	}
	if rdapInfo.ActivityClass != "passive" || rdapInfo.DisclosureClass != "passive" {
		t.Errorf("passive classes wrong: %s / %s", rdapInfo.ActivityClass, rdapInfo.DisclosureClass)
	}
	if rdapInfo.RequiresScope {
		t.Error("passive provider must not require scope")
	}
	if rdapInfo.RateLimit != "1 req/s" {
		t.Errorf("rateLimit not preserved: %q", rdapInfo.RateLimit)
	}

	if portInfo.ActivityClass != "active" || portInfo.DisclosureClass != "active" {
		t.Errorf("active classes wrong: %s / %s", portInfo.ActivityClass, portInfo.DisclosureClass)
	}
	if !portInfo.RequiresScope {
		t.Error("active provider must report requiresScope=true")
	}
	if len(portInfo.Capabilities) != 1 || portInfo.Capabilities[0] != "port_scan" {
		t.Errorf("active capabilities wrong: %v", portInfo.Capabilities)
	}
}

// The DTO must never grow a field that hands the frontend a runnable provider
// (or a raw domain object, or anything secret-shaped). Pin the exact JSON key
// set so such a field can't be added without this test failing.
func TestOSINTProviderInfoExposesOnlyMetadataKeys(t *testing.T) {
	s := NewService()
	defer s.Close()
	if err := s.osintRegistry.Register(&fakeOSINTPassive{meta: osint.ProviderMeta{
		ID:              "rdap.example",
		Name:            "RDAP (example)",
		Capabilities:    []osint.Capability{osint.CapabilityRDAP},
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
	}}); err != nil {
		t.Fatalf("register: %v", err)
	}

	raw, err := json.Marshal(s.ListOSINTProviders()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"id": true, "name": true, "capabilities": true,
		"activityClass": true, "disclosureClass": true,
		"requiresScope": true, "rateLimit": true,
	}
	for k := range obj {
		if !allowed[k] {
			t.Errorf("unexpected key %q in OSINTProviderInfo JSON — metadata-only contract broken", k)
		}
	}
}

// A provider whose metadata fails osint.ProviderMeta.Validate never registers,
// so it can never surface in the UI list (defence in depth over V1.5-2's own
// registry tests).
func TestListOSINTProvidersRejectsInvalidProviderMetadata(t *testing.T) {
	s := NewService()
	defer s.Close()

	err := s.osintRegistry.Register(&fakeOSINTPassive{meta: osint.ProviderMeta{
		ID:              "bad.example",
		Name:            "Bad",
		Capabilities:    []osint.Capability{osint.CapabilityUnknown},
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
	}})
	if err == nil {
		t.Fatal("registry accepted a provider with an empty capability")
	}
	// V1.5-6: infrastructure provider remains registered
	got := s.ListOSINTProviders()
	if len(got) != 1 {
		t.Fatalf("expected 1 provider (infrastructure) after failed registration, got %d", len(got))
	}
	if got[0].ID != "infra.intelligence" {
		t.Errorf("expected infrastructure provider, got %s", got[0].ID)
	}
}
