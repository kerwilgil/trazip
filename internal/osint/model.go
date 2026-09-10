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

// Provenance records where a result came from. A provider fills it in once
// when it builds a Result; the framework and consumers treat it as
// read-only (it holds no pointers, slices, or maps, so a copy is a full
// copy). The execution gate refuses a successful Result whose Provenance
// does not pass Validate.
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

// Validate reports whether the provenance is complete and internally
// coherent enough to accompany a successful result. The execution gate
// calls this and converts a failure into a fail-closed error.
func (p Provenance) Validate() error {
	switch {
	case p.ProviderID == "":
		return fmt.Errorf("missing ProviderID")
	case p.ProviderName == "":
		return fmt.Errorf("missing ProviderName")
	case p.Capability == "":
		return fmt.Errorf("missing Capability")
	case !p.ActivityClass.IsValid():
		return fmt.Errorf("invalid ActivityClass %q", p.ActivityClass)
	case !p.DisclosureClass.IsValid():
		return fmt.Errorf("invalid DisclosureClass %q", p.DisclosureClass)
	case p.RetrievedAt == "":
		return fmt.Errorf("missing RetrievedAt")
	}
	if p.ActivityClass == ActivityActive && p.DisclosureClass != DisclosureActive {
		return fmt.Errorf("active activity requires DisclosureActive, got %q", p.DisclosureClass)
	}
	if p.ActivityClass == ActivityPassive && p.DisclosureClass == DisclosureActive {
		return fmt.Errorf("passive activity cannot use DisclosureActive")
	}
	return nil
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

// ProviderMeta describes a provider's identity and capabilities. A provider
// sets it once and returns an equivalent value from every Meta() call; the
// Registry stores a defensive snapshot (Capabilities copied) at
// registration and hands out copies, so a caller cannot mutate registry
// state through a retained slice.
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

// clone returns a copy with its own Capabilities backing array.
func (m ProviderMeta) clone() ProviderMeta {
	cp := m
	if m.Capabilities != nil {
		cp.Capabilities = append([]Capability(nil), m.Capabilities...)
	}
	return cp
}

// Validate checks that the metadata is well-formed and that the
// activity / disclosure / scope fields are mutually consistent:
//
//	ActivityActive  => RequiresScope == true  && DisclosureClass == DisclosureActive
//	ActivityPassive => RequiresScope == false && DisclosureClass in {Local, Passive}
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
	// Every capability must be a non-empty, unique identifier — the central
	// capability gate treats ProviderMeta.Capabilities as the authoritative
	// set. Custom string capabilities are allowed; there is no whitelist.
	seen := make(map[Capability]struct{}, len(m.Capabilities))
	for _, c := range m.Capabilities {
		if c == CapabilityUnknown { // Capability("")
			return &InvalidConfigError{Provider: m.ID, Field: "Capabilities", Reason: "capability must not be empty/unknown"}
		}
		if _, dup := seen[c]; dup {
			return &InvalidConfigError{Provider: m.ID, Field: "Capabilities", Reason: fmt.Sprintf("duplicate capability %q", c)}
		}
		seen[c] = struct{}{}
	}
	if !m.ActivityClass.IsValid() {
		return &InvalidConfigError{Provider: m.ID, Field: "ActivityClass", Reason: fmt.Sprintf("invalid activity class %q", m.ActivityClass)}
	}
	if !m.DisclosureClass.IsValid() {
		return &InvalidConfigError{Provider: m.ID, Field: "DisclosureClass", Reason: fmt.Sprintf("invalid disclosure class %q", m.DisclosureClass)}
	}

	switch m.ActivityClass {
	case ActivityActive:
		if !m.RequiresScope {
			return &InvalidConfigError{Provider: m.ID, Field: "RequiresScope", Reason: "active provider must require scope"}
		}
		if m.DisclosureClass != DisclosureActive {
			return &InvalidConfigError{Provider: m.ID, Field: "DisclosureClass", Reason: fmt.Sprintf("active provider must declare DisclosureActive, got %q", m.DisclosureClass)}
		}
	case ActivityPassive:
		if m.RequiresScope {
			return &InvalidConfigError{Provider: m.ID, Field: "RequiresScope", Reason: "passive provider must not require scope"}
		}
		if m.DisclosureClass == DisclosureActive {
			return &InvalidConfigError{Provider: m.ID, Field: "DisclosureClass", Reason: "passive provider must not declare DisclosureActive"}
		}
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
