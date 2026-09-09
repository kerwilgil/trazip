// Package passive provides the base types for passive OSINT providers.
// Passive providers perform external lookups only — no packets sent to targets.
package passive

import (
	"context"

	"trazip/internal/osint"
)

// Provider is the interface for passive OSINT providers.
// Embed osint.BaseProvider and implement Execute.
type Provider interface {
	osint.Provider
	osint.PassiveProvider
}

// ============================================================
// Passive capabilities (for reference — providers declare these)
// ============================================================

// These are the passive capabilities defined in the foundation.
// Real providers in V1.5-3+ will implement these.

// CapabilityRDAP — WHOIS/RDAP lookup for IP/ASN/domain registration data.
const CapabilityRDAP = osint.CapabilityRDAP

// CapabilityCVE — CVE vulnerability lookup by ID or keyword.
const CapabilityCVE = osint.CapabilityCVE

// CapabilityCertificateTransparency — CT log search for certificates.
const CapabilityCertificateTransparency = osint.CapabilityCertificateTransparency

// CapabilityASNMapping — ASN to organization/prefix mapping.
const CapabilityASNMapping = osint.CapabilityASNMapping

// CapabilitySubdomain — Subdomain enumeration via passive sources.
const CapabilitySubdomain = osint.CapabilitySubdomain

// ============================================================
// Example passive provider skeleton (not functional — for reference)
// ============================================================

// ExampleProvider is a template for passive providers.
// Replace with real implementation in V1.5-3+.
type ExampleProvider struct {
	*osint.BaseProvider
}

func NewExampleProvider() *ExampleProvider {
	return &ExampleProvider{
		BaseProvider: &osint.BaseProvider{
			MetaVal: osint.ProviderMeta{
				ID:              "example.passive",
				Name:            "Example Passive Provider",
				Capabilities:    []osint.Capability{osint.CapabilityRDAP},
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RequiresScope:   false,
				RateLimit:       "60 req/min",
			},
		},
	}
}

func (p *ExampleProvider) Execute(ctx context.Context, capability osint.Capability, input any) osint.Result {
	if capability != osint.CapabilityRDAP {
		return osint.Result{
			Err: &osint.UnsupportedCapabilityError{
				Provider:   p.Meta().ID,
				Capability: capability,
			},
		}
	}
	// TODO: implement real RDAP lookup
	return osint.Result{
		Data: map[string]string{"status": "not implemented"},
		Provenance: osint.NewProvenance(
			p.Meta().ID,
			p.Meta().Name,
			string(capability),
			osint.ActivityPassive,
			osint.DisclosurePassive,
			"rdap.example.com",
			"media",
		),
	}
}

func (p *ExampleProvider) PassiveCapabilities() []osint.Capability {
	return []osint.Capability{osint.CapabilityRDAP}
}
