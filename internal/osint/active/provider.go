// Package active provides the base types for active OSINT providers.
// Active providers send packets/probes directly to target infrastructure.
//
// Authorization is NOT the provider's job: osint.Executor.ExecuteActive
// verifies an authorized ScopeGuard and an in-scope target before Probe is
// ever called. A provider here performs no scope checks of its own.
package active

import (
	"context"

	"trazip/internal/osint"
)

// Provider is the contract an active OSINT provider satisfies: identity plus
// the Probe method invoked only by the execution gate.
type Provider = osint.ActiveRunner

// ============================================================
// Active capabilities (providers declare these in their metadata)
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

// ExampleProvider is a template for active providers. Replace with a real
// implementation in V1.5-3+. It holds no ScopeGuard: the execution gate has
// already authorized the target by the time Probe runs.
type ExampleProvider struct {
	*osint.BaseProvider
}

// NewExampleProvider builds the reference skeleton.
func NewExampleProvider() *ExampleProvider {
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
	}
}

// Probe is invoked only by osint.Executor.ExecuteActive, which has already
// confirmed target is within an authorized scope.
func (p *ExampleProvider) Probe(ctx context.Context, capability osint.Capability, target string, input any) osint.Result {
	if capability != osint.CapabilityPortScan {
		return osint.Result{
			Err: &osint.UnsupportedCapabilityError{
				Provider:   p.Meta().ID,
				Capability: capability,
			},
		}
	}
	if target == "" {
		return osint.Result{
			Err: &osint.InvalidConfigError{
				Provider: p.Meta().ID,
				Field:    "target",
				Reason:   "active probe requires a non-empty target",
			},
		}
	}
	if err := ctx.Err(); err != nil {
		return osint.Result{Err: err}
	}
	// TODO(v1.5-3): implement a real port scan.
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
			"alta",
		),
	}
}
