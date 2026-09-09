// Package active holds the contract for active OSINT providers.
//
// Active providers send packets/probes directly to target infrastructure.
// Authorization is not the provider's job: osint.Executor.ExecuteActive
// verifies an authorized ScopeGuard and an in-scope target — and that the
// requested capability was declared — before Probe is ever called.
//
// This package intentionally ships no runnable provider — only the contract
// alias and the capability constants. A worked example lives in the tests
// and in docs/OSINT_FOUNDATION.md, never in the production tree, so nothing
// here can return a fabricated success (e.g. an empty "ports" list that
// could be mistaken for a real scan).
package active

import "trazip/internal/osint"

// Provider is the contract an active OSINT provider satisfies: identity plus
// the Probe method invoked only by the execution gate.
type Provider = osint.ActiveRunner

// Active capability identifiers (providers declare these in their metadata).
const (
	// CapabilityPortScan — TCP/UDP port scanning.
	CapabilityPortScan = osint.CapabilityPortScan
	// CapabilityTraceroute — Network path tracing.
	CapabilityTraceroute = osint.CapabilityTraceroute
	// CapabilityServiceDetection — Service/version detection on open ports.
	CapabilityServiceDetection = osint.CapabilityServiceDetection
	// CapabilityActiveDNS — Active DNS queries (AXFR, brute force, etc).
	CapabilityActiveDNS = osint.CapabilityActiveDNS
)
