// Package passive provides the base types for passive OSINT providers.
// Passive providers perform external lookups only — no packets sent to
// targets. They run through osint.Executor.ExecutePassive, which rejects
// any non-passive provider before this code is reached.
package passive

import (
	"context"

	"trazip/internal/osint"
)

// Provider is the contract a passive OSINT provider satisfies: identity plus
// the Lookup method invoked only by the execution gate.
type Provider = osint.PassiveRunner

// ============================================================
// Passive capabilities (providers declare these in their metadata)
// ============================================================

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

// ExampleProvider is a template for passive providers. Replace with a real
// implementation in V1.5-3+.
type ExampleProvider struct {
	*osint.BaseProvider
}

// NewExampleProvider builds the reference skeleton.
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

// Lookup is invoked only by osint.Executor.ExecutePassive.
func (p *ExampleProvider) Lookup(ctx context.Context, capability osint.Capability, input any) osint.Result {
	if capability != osint.CapabilityRDAP {
		return osint.Result{
			Err: &osint.UnsupportedCapabilityError{
				Provider:   p.Meta().ID,
				Capability: capability,
			},
		}
	}
	if err := ctx.Err(); err != nil {
		return osint.Result{Err: err}
	}
	// TODO(v1.5-3): implement a real RDAP lookup.
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
