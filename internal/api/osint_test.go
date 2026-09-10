package api

import (
	"context"
	"encoding/json"
	"reflect"
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
	if len(got) != 0 {
		t.Fatalf("a fresh registry must expose no providers, got %d", len(got))
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != "[]" {
		t.Fatalf("empty provider list must serialize as [], got %s", raw)
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
	if len(got) != 2 {
		t.Fatalf("got %d providers, want 2", len(got))
	}

	// Deterministic ordering: sorted by ID regardless of registration order
	// (AllMetas iterates a map).
	if got[0].ID != "portscan.example" || got[1].ID != "rdap.example" {
		t.Fatalf("providers not sorted by ID: %s, %s", got[0].ID, got[1].ID)
	}

	rdapInfo, portInfo := got[1], got[0]

	if rdapInfo.Name != "RDAP (example)" {
		t.Errorf("name not preserved: %q", rdapInfo.Name)
	}
	if !reflect.DeepEqual(rdapInfo.Capabilities, []string{"rdap", "asn_mapping"}) {
		t.Errorf("capabilities not preserved in order: %v", rdapInfo.Capabilities)
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
	if len(s.ListOSINTProviders()) != 0 {
		t.Fatal("an unregistered provider surfaced in ListOSINTProviders")
	}
}
