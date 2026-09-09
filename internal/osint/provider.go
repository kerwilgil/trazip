// Package osint defines the provider contracts for the OSINT subsystem.
package osint

import (
	"context"
	"fmt"
	"sync"
)

// Provider is the base interface every OSINT provider must implement.
// It provides identity, capabilities, and the core execution method.
type Provider interface {
	// Meta returns the provider's immutable metadata.
	Meta() ProviderMeta

	// Execute runs the provider for a given capability with the provided input.
	// ctx must be respected for cancellation and deadlines.
	// Input is capability-specific (e.g., IP for RDAP, CVE ID for CVE).
	// Returns a Result carrying data and mandatory provenance.
	Execute(ctx context.Context, capability Capability, input any) Result
}

// ProviderFunc is an adapter to use a function as a Provider.
// Useful for test stubs and simple providers.
type ProviderFunc func(ctx context.Context, capability Capability, input any) Result

func (f ProviderFunc) Meta() ProviderMeta {
	return ProviderMeta{} // must be overridden via wrapper or separate meta
}

func (f ProviderFunc) Execute(ctx context.Context, capability Capability, input any) Result {
	return f(ctx, capability, input)
}

// Registry manages provider registration and lookup.
// Thread-safe for concurrent registration (init time) and lookup (runtime).
type Registry struct {
	mu         sync.RWMutex
	byID       map[string]Provider
	byCap      map[Capability][]Provider
	passiveIDs map[string]struct{}
	activeIDs  map[string]struct{}
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:       make(map[string]Provider),
		byCap:      make(map[Capability][]Provider),
		passiveIDs: make(map[string]struct{}),
		activeIDs:  make(map[string]struct{}),
	}
}

// Register adds a provider to the registry. Panics on duplicate ID.
// Must be called before concurrent lookups (typically at startup).
func (r *Registry) Register(p Provider) error {
	meta := p.Meta()
	if err := meta.Validate(); err != nil {
		return fmt.Errorf("registry: provider %q invalid: %w", meta.ID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byID[meta.ID]; exists {
		return fmt.Errorf("registry: duplicate provider ID %q", meta.ID)
	}

	r.byID[meta.ID] = p
	for _, cap := range meta.Capabilities {
		r.byCap[cap] = append(r.byCap[cap], p)
	}

	switch meta.ActivityClass {
	case ActivityPassive:
		r.passiveIDs[meta.ID] = struct{}{}
	case ActivityActive:
		r.activeIDs[meta.ID] = struct{}{}
	}

	return nil
}

// GetByID returns a provider by its ID, or nil if not found.
func (r *Registry) GetByID(id string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[id]
	return p, ok
}

// GetByCapability returns all providers supporting a capability.
// The returned slice is a copy — safe to iterate without lock.
func (r *Registry) GetByCapability(cap Capability) []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	providers := r.byCap[cap]
	result := make([]Provider, len(providers))
	copy(result, providers)
	return result
}

// GetPassive returns all passive providers.
func (r *Registry) GetPassive() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Provider, 0, len(r.passiveIDs))
	for id := range r.passiveIDs {
		if p, ok := r.byID[id]; ok {
			result = append(result, p)
		}
	}
	return result
}

// GetActive returns all active providers.
func (r *Registry) GetActive() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Provider, 0, len(r.activeIDs))
	for id := range r.activeIDs {
		if p, ok := r.byID[id]; ok {
			result = append(result, p)
		}
	}
	return result
}

// All returns all registered providers.
func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Provider, 0, len(r.byID))
	for _, p := range r.byID {
		result = append(result, p)
	}
	return result
}

// Capabilities returns all registered capabilities.
func (r *Registry) Capabilities() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	caps := make([]Capability, 0, len(r.byCap))
	for cap := range r.byCap {
		caps = append(caps, cap)
	}
	return caps
}

// ============================================================
// PassiveProvider — explicitly passive contract
// ============================================================

// PassiveProvider is the interface for passive OSINT providers.
// It embeds Provider and guarantees ActivityPassive / no scope required.
type PassiveProvider interface {
	Provider

	// PassiveCapabilities returns the passive capabilities this provider supports.
	PassiveCapabilities() []Capability
}

// ============================================================
// ActiveProvider — explicitly active contract
// ============================================================

// ActiveProvider is the interface for active reconnaissance providers.
// It embeds Provider and guarantees ActivityActive / requires scope.
type ActiveProvider interface {
	Provider

	// ActiveCapabilities returns the active capabilities this provider supports.
	ActiveCapabilities() []Capability

	// RequireScope returns true — active providers always need scope.
	RequireScope() bool
}

// ============================================================
// BaseProvider — common implementation helper
// ============================================================

// BaseProvider embeds common provider functionality.
// Use composition: embed BaseProvider in your provider struct.
type BaseProvider struct {
	MetaVal ProviderMeta
}

func (b *BaseProvider) Meta() ProviderMeta { return b.MetaVal }

// ValidateMeta checks the embedded meta is valid.
func (b *BaseProvider) ValidateMeta() error { return b.MetaVal.Validate() }
