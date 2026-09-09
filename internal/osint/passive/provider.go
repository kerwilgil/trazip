// Package passive holds the contract for passive OSINT providers.
//
// Passive providers perform external lookups only — no packets sent to
// targets. They are always run through osint.Executor.ExecutePassive, which
// enforces the pipeline, capability, context and provenance checks; a
// provider here never calls the ScopeGuard.
//
// This package intentionally ships no runnable provider — only the contract
// alias and the capability constants. A worked example lives in the tests
// and in docs/OSINT_FOUNDATION.md, never in the production tree, so nothing
// here can return a fabricated success.
package passive

import "trazip/internal/osint"

// Provider is the contract a passive OSINT provider satisfies: identity plus
// the Lookup method invoked only by the execution gate.
type Provider = osint.PassiveRunner

// Passive capability identifiers (providers declare these in their metadata).
const (
	// CapabilityRDAP — WHOIS/RDAP lookup for IP/ASN/domain registration data.
	CapabilityRDAP = osint.CapabilityRDAP
	// CapabilityCVE — CVE vulnerability lookup by ID or keyword.
	CapabilityCVE = osint.CapabilityCVE
	// CapabilityCertificateTransparency — CT log search for certificates.
	CapabilityCertificateTransparency = osint.CapabilityCertificateTransparency
	// CapabilityASNMapping — ASN to organization/prefix mapping.
	CapabilityASNMapping = osint.CapabilityASNMapping
	// CapabilitySubdomain — Subdomain enumeration via passive sources.
	CapabilitySubdomain = osint.CapabilitySubdomain
)
