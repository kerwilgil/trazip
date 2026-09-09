// Package osint provides the foundational contracts for TRAZIP's OSINT
// intelligence subsystem. This is V1.5-2: foundation only — no real
// providers, no UI, no active scanners, no releases.
package osint

import (
	"fmt"

	"trazip/internal/intel/external"
)

// ============================================================
// Activity Class — hard separation between passive and active
// ============================================================

// ActivityClass distinguishes the nature of an OSINT operation.
type ActivityClass int

const (
	// ActivityUnknown is an invalid sentinel.
	ActivityUnknown ActivityClass = iota
	// ActivityPassive — purely external lookups, no packets sent to target.
	// Examples: RDAP, CVE lookup, certificate transparency, ASN mapping.
	ActivityPassive
	// ActivityActive — sends packets/probes directly to target infrastructure.
	// Examples: port scan, traceroute, service detection, active DNS.
	ActivityActive
)

// String returns a stable representation for logging/UI.
func (a ActivityClass) String() string {
	switch a {
	case ActivityPassive:
		return "passive"
	case ActivityActive:
		return "active"
	default:
		return "unknown"
	}
}

// IsValid reports whether the activity class is defined.
func (a ActivityClass) IsValid() bool {
	return a == ActivityPassive || a == ActivityActive
}

// ============================================================
// Disclosure Class — what leaves the machine
// ============================================================

// DisclosureClass documents the external visibility of an operation.
type DisclosureClass int

const (
	// DisclosureUnknown is an invalid sentinel.
	DisclosureUnknown DisclosureClass = iota
	// DisclosureLocal — nothing leaves the machine (pure local computation).
	DisclosureLocal
	// DisclosurePassive — external passive lookup (DNS, HTTP to third party).
	DisclosurePassive
	// DisclosureActive — active network interaction with target.
	DisclosureActive
)

// String returns a stable representation.
func (d DisclosureClass) String() string {
	switch d {
	case DisclosureLocal:
		return "local"
	case DisclosurePassive:
		return "passive"
	case DisclosureActive:
		return "active"
	default:
		return "unknown"
	}
}

// IsValid reports whether the disclosure class is defined.
func (d DisclosureClass) IsValid() bool {
	return d >= DisclosureLocal && d <= DisclosureActive
}

// ============================================================
// Provenance — every result carries its origin
// ============================================================

// Provenance records where a result came from. Immutable after creation.
type Provenance struct {
	// ProviderID is the stable identifier of the source (e.g., "rdap.ripe",
	// "cve.nvd", "ct.crtsh", "asn.ripe").
	ProviderID string

	// ProviderName is a human-readable name (e.g., "RDAP via RIPE NCC").
	ProviderName string

	// Capability describes what the provider does (e.g., "rdap", "cve",
	// "certificate_transparency", "asn_mapping").
	Capability string

	// ActivityClass is the nature of the operation that produced this.
	ActivityClass ActivityClass

	// DisclosureClass is what left the machine during this operation.
	DisclosureClass DisclosureClass

	// RetrievedAt is when the result was obtained (RFC3339).
	RetrievedAt string

	// Endpoint is the specific endpoint/query used, sanitized (no secrets).
	Endpoint string

	// Confidence is the provider's self-assessment: "alta" | "media" | "baja".
	Confidence string

	// Disclosure is the full external.Disclosure envelope for passive ops.
	Disclosure external.Disclosure
}

// NewProvenance creates a provenance record with timestamp set to now.
func NewProvenance(providerID, providerName, capability string, activity ActivityClass, disclosure DisclosureClass, endpoint, confidence string) Provenance {
	now := external.Now()
	return Provenance{
		ProviderID:      providerID,
		ProviderName:    providerName,
		Capability:      capability,
		ActivityClass:   activity,
		DisclosureClass: disclosure,
		RetrievedAt:     now,
		Endpoint:        endpoint,
		Confidence:      confidence,
		Disclosure: external.Disclosure{
			Source:      providerName,
			QueriedAt:   now,
			DataSent:    endpoint,
			CachePolicy: "memory (TTL)",
			Confidence:  confidence,
			RateLimit:   "not specified",
		},
	}
}

// ============================================================
// Provider Metadata — identity & capabilities
// ============================================================

// Capability is a stable capability identifier.
type Capability string

const (
	CapabilityUnknown                 Capability = ""
	CapabilityRDAP                    Capability = "rdap"
	CapabilityCVE                     Capability = "cve"
	CapabilityCertificateTransparency Capability = "certificate_transparency"
	CapabilityASNMapping              Capability = "asn_mapping"
	CapabilitySubdomain               Capability = "subdomain"
	CapabilityPortScan                Capability = "port_scan"
	CapabilityTraceroute              Capability = "traceroute"
	CapabilityServiceDetection        Capability = "service_detection"
	CapabilityActiveDNS               Capability = "active_dns"
)

// ProviderMeta describes a provider's identity and capabilities.
// Immutable after creation — providers register once at startup.
type ProviderMeta struct {
	ID              string
	Name            string
	Capabilities    []Capability
	ActivityClass   ActivityClass
	DisclosureClass DisclosureClass
	// RequiresScope indicates whether this provider needs an active scope guard.
	// Passive providers: false. Active providers: true.
	RequiresScope bool
	// RateLimit is the provider's self-declared quota note.
	RateLimit string
}

// Validate checks that the metadata is well-formed.
func (m ProviderMeta) Validate() error {
	if m.ID == "" {
		return &InvalidConfigError{Provider: "unknown", Field: "ID", Reason: "missing ID"}
	}
	if m.Name == "" {
		return &InvalidConfigError{Provider: m.ID, Field: "Name", Reason: "missing name"}
	}
	if len(m.Capabilities) == 0 {
		return &InvalidConfigError{Provider: m.ID, Field: "Capabilities", Reason: "at least one capability required"}
	}
	if !m.ActivityClass.IsValid() {
		return &InvalidConfigError{Provider: m.ID, Field: "ActivityClass", Reason: fmt.Sprintf("invalid activity class %q", m.ActivityClass)}
	}
	if !m.DisclosureClass.IsValid() {
		return &InvalidConfigError{Provider: m.ID, Field: "DisclosureClass", Reason: fmt.Sprintf("invalid disclosure class %q", m.DisclosureClass)}
	}
	if m.ActivityClass == ActivityActive && !m.RequiresScope {
		return &InvalidConfigError{Provider: m.ID, Field: "RequiresScope", Reason: "active provider must require scope"}
	}
	if m.ActivityClass == ActivityPassive && m.RequiresScope {
		return &InvalidConfigError{Provider: m.ID, Field: "RequiresScope", Reason: "passive provider must not require scope"}
	}
	return nil
}

// ============================================================
// Result — generic carrier for provider output
// ============================================================

// Result is what a provider returns. It always carries provenance.
type Result struct {
	// Data is the provider-specific payload. Type depends on capability.
	// Consumers must type-assert based on capability.
	Data any

	// Provenance is mandatory — every result knows its origin.
	Provenance Provenance

	// Err is set if the provider failed. When Err != nil, Data may be nil.
	Err error
}

// IsOK reports whether the result is successful.
func (r Result) IsOK() bool { return r.Err == nil }
