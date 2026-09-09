// Package osint provides tests for the OSINT foundation.
package osint

import (
	"errors"
	"testing"
)

func TestActivityClass(t *testing.T) {
	tests := []struct {
		name      string
		class     ActivityClass
		wantStr   string
		wantValid bool
	}{
		{"unknown", ActivityUnknown, "unknown", false},
		{"passive", ActivityPassive, "passive", true},
		{"active", ActivityActive, "active", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.class.String() != tt.wantStr {
				t.Errorf("String() = %q, want %q", tt.class.String(), tt.wantStr)
			}
			if tt.class.IsValid() != tt.wantValid {
				t.Errorf("IsValid() = %v, want %v", tt.class.IsValid(), tt.wantValid)
			}
		})
	}
}

func TestDisclosureClass(t *testing.T) {
	tests := []struct {
		name      string
		class     DisclosureClass
		wantStr   string
		wantValid bool
	}{
		{"unknown", DisclosureUnknown, "unknown", false},
		{"local", DisclosureLocal, "local", true},
		{"passive", DisclosurePassive, "passive", true},
		{"active", DisclosureActive, "active", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.class.String() != tt.wantStr {
				t.Errorf("String() = %q, want %q", tt.class.String(), tt.wantStr)
			}
			if tt.class.IsValid() != tt.wantValid {
				t.Errorf("IsValid() = %v, want %v", tt.class.IsValid(), tt.wantValid)
			}
		})
	}
}

func TestProviderMetaValidate(t *testing.T) {
	tests := []struct {
		name    string
		meta    ProviderMeta
		wantErr bool
	}{
		{
			name: "valid passive",
			meta: ProviderMeta{
				ID:              "test.passive",
				Name:            "Test Passive",
				Capabilities:    []Capability{CapabilityRDAP},
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   false,
			},
			wantErr: false,
		},
		{
			name: "valid active",
			meta: ProviderMeta{
				ID:              "test.active",
				Name:            "Test Active",
				Capabilities:    []Capability{CapabilityPortScan},
				ActivityClass:   ActivityActive,
				DisclosureClass: DisclosureActive,
				RequiresScope:   true,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			meta: ProviderMeta{
				Name:            "Test",
				Capabilities:    []Capability{CapabilityRDAP},
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   false,
			},
			wantErr: true,
		},
		{
			name: "missing name",
			meta: ProviderMeta{
				ID:              "test",
				Capabilities:    []Capability{CapabilityRDAP},
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   false,
			},
			wantErr: true,
		},
		{
			name: "no capabilities",
			meta: ProviderMeta{
				ID:              "test",
				Name:            "Test",
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   false,
			},
			wantErr: true,
		},
		{
			name: "active without scope",
			meta: ProviderMeta{
				ID:              "test",
				Name:            "Test",
				Capabilities:    []Capability{CapabilityPortScan},
				ActivityClass:   ActivityActive,
				DisclosureClass: DisclosureActive,
				RequiresScope:   false,
			},
			wantErr: true,
		},
		{
			name: "passive with scope",
			meta: ProviderMeta{
				ID:              "test",
				Name:            "Test",
				Capabilities:    []Capability{CapabilityRDAP},
				ActivityClass:   ActivityPassive,
				DisclosureClass: DisclosurePassive,
				RequiresScope:   true,
			},
			wantErr: true,
		},

		// --- P1-02: activity / disclosure consistency ---
		{
			name: "active + DisclosurePassive rejected",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityPortScan},
				ActivityClass: ActivityActive, DisclosureClass: DisclosurePassive, RequiresScope: true,
			},
			wantErr: true,
		},
		{
			name: "active + DisclosureLocal rejected",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityPortScan},
				ActivityClass: ActivityActive, DisclosureClass: DisclosureLocal, RequiresScope: true,
			},
			wantErr: true,
		},
		{
			name: "active + DisclosureActive accepted",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityPortScan},
				ActivityClass: ActivityActive, DisclosureClass: DisclosureActive, RequiresScope: true,
			},
			wantErr: false,
		},
		{
			name: "passive + DisclosureActive rejected",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityRDAP},
				ActivityClass: ActivityPassive, DisclosureClass: DisclosureActive, RequiresScope: false,
			},
			wantErr: true,
		},
		{
			name: "passive + DisclosurePassive accepted",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityRDAP},
				ActivityClass: ActivityPassive, DisclosureClass: DisclosurePassive, RequiresScope: false,
			},
			wantErr: false,
		},
		{
			name: "passive + DisclosureLocal accepted",
			meta: ProviderMeta{
				ID: "t", Name: "t", Capabilities: []Capability{CapabilityRDAP},
				ActivityClass: ActivityPassive, DisclosureClass: DisclosureLocal, RequiresScope: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.meta.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestProvenanceValidate(t *testing.T) {
	base := func() Provenance {
		return NewProvenance("p.id", "P Name", "rdap", ActivityPassive, DisclosurePassive, "e", "alta")
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("a fresh NewProvenance must be valid: %v", err)
	}

	tests := []struct {
		name  string
		mutfn func(*Provenance)
	}{
		{"missing ProviderID", func(p *Provenance) { p.ProviderID = "" }},
		{"missing ProviderName", func(p *Provenance) { p.ProviderName = "" }},
		{"missing Capability", func(p *Provenance) { p.Capability = "" }},
		{"invalid ActivityClass", func(p *Provenance) { p.ActivityClass = ActivityUnknown }},
		{"invalid DisclosureClass", func(p *Provenance) { p.DisclosureClass = DisclosureUnknown }},
		{"missing RetrievedAt", func(p *Provenance) { p.RetrievedAt = "" }},
		{"active without DisclosureActive", func(p *Provenance) {
			p.ActivityClass = ActivityActive
			p.DisclosureClass = DisclosurePassive
		}},
		{"passive with DisclosureActive", func(p *Provenance) { p.DisclosureClass = DisclosureActive }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base()
			tt.mutfn(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error for %q", tt.name)
			}
		})
	}

	// Zero value must be rejected.
	if err := (Provenance{}).Validate(); err == nil {
		t.Error("zero-value Provenance must be invalid")
	}
}

func TestProvenanceCreation(t *testing.T) {
	prov := NewProvenance(
		"test.provider",
		"Test Provider",
		"rdap",
		ActivityPassive,
		DisclosurePassive,
		"rdap.example.com",
		"alta",
	)

	if prov.ProviderID != "test.provider" {
		t.Errorf("ProviderID = %q, want test.provider", prov.ProviderID)
	}
	if prov.ProviderName != "Test Provider" {
		t.Errorf("ProviderName = %q, want Test Provider", prov.ProviderName)
	}
	if prov.ActivityClass != ActivityPassive {
		t.Errorf("ActivityClass = %v, want passive", prov.ActivityClass)
	}
	if prov.DisclosureClass != DisclosurePassive {
		t.Errorf("DisclosureClass = %v, want passive", prov.DisclosureClass)
	}
	if prov.RetrievedAt == "" {
		t.Error("RetrievedAt should be set")
	}
	if prov.Endpoint != "rdap.example.com" {
		t.Errorf("Endpoint = %q, want rdap.example.com", prov.Endpoint)
	}
	if prov.Confidence != "alta" {
		t.Errorf("Confidence = %q, want alta", prov.Confidence)
	}
	if prov.Disclosure.Source != "Test Provider" {
		t.Errorf("Disclosure.Source = %q, want Test Provider", prov.Disclosure.Source)
	}
}

func TestResultIsOK(t *testing.T) {
	okResult := Result{Data: "ok", Err: nil}
	if !okResult.IsOK() {
		t.Error("Result with nil Err should be OK")
	}

	errResult := Result{Data: nil, Err: errors.New("fail")}
	if errResult.IsOK() {
		t.Error("Result with error should not be OK")
	}
}

func TestCapabilities(t *testing.T) {
	// Verify capability constants exist
	if CapabilityRDAP != "rdap" {
		t.Errorf("CapabilityRDAP = %q, want rdap", CapabilityRDAP)
	}
	if CapabilityCVE != "cve" {
		t.Errorf("CapabilityCVE = %q, want cve", CapabilityCVE)
	}
	if CapabilityPortScan != "port_scan" {
		t.Errorf("CapabilityPortScan = %q, want port_scan", CapabilityPortScan)
	}
}
