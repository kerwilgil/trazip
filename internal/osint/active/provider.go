// Package active provides the base types for active OSINT providers.
// Active providers send packets/probes directly to target infrastructure.
// They REQUIRE an authorized ScopeGuard to execute.
package active

import (
	"context"

	"trazip/internal/osint"
)

// Provider is the interface for active OSINT providers.
// Embed osint.BaseProvider and implement Execute.
type Provider interface {
	osint.Provider
	osint.ActiveProvider
}

// ============================================================
// Active capabilities (for reference — providers declare these)
// ============================================================

// CapabilityPortScan — TCP/UDP port scanning.
const CapabilityPortScan = osint.CapabilityPortScan

// CapabilityTraceroute — Network path tracing.
const CapabilityTraceroute = osint.CapabilityTraceroute

// CapabilityServiceDetection — Service/version detection on open ports.
const CapabilityServiceDetection = osint.CapabilityServiceDetection

// CapabilityActiveDNS — Active DNS queries (AXFR, brute force, etc).
const CapabilityActiveDNS = osint.CapabilityActiveDNS

// ============================================================
// Example active provider skeleton (not functional — for reference)
// ============================================================

// ExampleProvider is a template for active providers.
// Replace with real implementation in V1.5-3+.
// REQUIRES ScopeGuard to be authorized before Execute.
type ExampleProvider struct {
	*osint.BaseProvider
	// ScopeGuard is mandatory for active providers.
	// Must be set by caller before Execute.
	ScopeGuard *osint.ScopeGuard
}

func NewExampleProvider(scopeGuard *osint.ScopeGuard) *ExampleProvider {
	return &ExampleProvider{
		BaseProvider: &osint.BaseProvider{
			MetaVal: osint.ProviderMeta{
				ID:              "example.active",
				Name:            "Example Active Provider",
				Capabilities:    []osint.Capability{osint.CapabilityPortScan},
				ActivityClass:   osint.ActivityActive,
				DisclosureClass: osint.DisclosureActive,
				RequiresScope:   true,
				RateLimit:       "10 req/sec",
			},
		},
		ScopeGuard: scopeGuard,
	}
}

func (p *ExampleProvider) Execute(ctx context.Context, capability osint.Capability, input any) osint.Result {
	// Active providers MUST check scope first
	if p.ScopeGuard == nil {
		return osint.Result{
			Err: &osint.ScopeRequiredError{
				Operation: string(capability),
				Provider:  p.Meta().ID,
			},
		}
	}

	if capability != osint.CapabilityPortScan {
		return osint.Result{
			Err: &osint.UnsupportedCapabilityError{
				Provider:   p.Meta().ID,
				Capability: capability,
			},
		}
	}

	// Extract target from input
	target, ok := input.(string)
	if !ok {
		return osint.Result{
			Err: &osint.InvalidConfigError{
				Provider: p.Meta().ID,
				Field:    "input",
				Reason:   "active input must be string target",
			},
		}
	}

	// Check target against scope
	if err := p.ScopeGuard.RequireTarget(string(capability), p.Meta().ID, target); err != nil {
		return osint.Result{Err: err}
	}

	// TODO: implement real port scan
	return osint.Result{
		Data: map[string]any{
			"target": target,
			"ports":  []int{},
			"status": "not implemented",
		},
		Provenance: osint.NewProvenance(
			p.Meta().ID,
			p.Meta().Name,
			string(capability),
			osint.ActivityActive,
			osint.DisclosureActive,
			target,
			"high",
		),
	}
}

func (p *ExampleProvider) ActiveCapabilities() []osint.Capability {
	return []osint.Capability{osint.CapabilityPortScan}
}

func (p *ExampleProvider) RequireScope() bool {
	return true
}
