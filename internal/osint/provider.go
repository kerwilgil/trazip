// Package osint defines the provider contracts for the OSINT subsystem.
package osint

import (
	"context"
	"fmt"
	"sync"
)

// Provider is the base identity contract every OSINT provider implements.
//
// It deliberately exposes NO execution method. Providers are never run by
// calling a method on this interface: all execution goes through Executor,
// which enforces the passive/active invariants before any provider code
// runs. A provider additionally implements PassiveRunner or ActiveRunner;
// those runner methods are invoked ONLY by Executor.
type Provider interface {
	// Meta returns the provider's metadata. It must return an equivalent
	// value on every call — providers register once and do not mutate.
	Meta() ProviderMeta
}

// PassiveRunner is implemented by passive providers. Lookup performs a
// purely external lookup (no packets to the target). It is invoked ONLY by
// Executor.ExecutePassive, after the gate has confirmed the provider's
// ActivityClass is ActivityPassive. Never call Lookup directly.
type PassiveRunner interface {
	Provider

	Lookup(ctx context.Context, capability Capability, input any) Result
}

// ActiveRunner is implemented by active providers. Probe sends packets or
// probes directly to target. It is invoked ONLY by Executor.ExecuteActive,
// after the gate has confirmed an authorized ScopeGuard and that target is
// within scope. Never call Probe directly — by design it performs no
// authorization of its own.
type ActiveRunner interface {
	Provider

	Probe(ctx context.Context, capability Capability, target string, input any) Result
}

// ============================================================
// Registry — registration and metadata lookup
// ============================================================

// registration is the stored record for one provider: the concrete
// provider plus a defensive snapshot of its metadata (Capabilities copied),
// so a slice the caller keeps and later mutates cannot alter the registry.
type registration struct {
	provider Provider
	meta     ProviderMeta
}

// Registry holds registered providers and answers metadata queries. It does
// NOT hand out runnable providers: the only route to execution is Executor,
// which reads the concrete provider through the package-private accessor.
// Safe for concurrent registration (startup) and lookup (runtime).
type Registry struct {
	mu    sync.RWMutex
	byID  map[string]registration
	byCap map[Capability][]string // capability -> provider IDs
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:  make(map[string]registration),
		byCap: make(map[Capability][]string),
	}
}

// Register validates and adds a provider. It rejects invalid metadata,
// duplicate IDs, and a provider whose declared ActivityClass does not match
// the runner interface it implements (passive => PassiveRunner, active =>
// ActiveRunner).
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return fmt.Errorf("registry: nil provider")
	}

	meta := p.Meta().clone()
	if err := meta.Validate(); err != nil {
		return fmt.Errorf("registry: provider %q invalid: %w", meta.ID, err)
	}

	switch meta.ActivityClass {
	case ActivityPassive:
		if _, ok := p.(PassiveRunner); !ok {
			return &InvalidConfigError{Provider: meta.ID, Field: "PassiveRunner", Reason: "passive provider must implement PassiveRunner"}
		}
	case ActivityActive:
		if _, ok := p.(ActiveRunner); !ok {
			return &InvalidConfigError{Provider: meta.ID, Field: "ActiveRunner", Reason: "active provider must implement ActiveRunner"}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byID[meta.ID]; exists {
		return fmt.Errorf("registry: duplicate provider ID %q", meta.ID)
	}

	r.byID[meta.ID] = registration{provider: p, meta: meta}
	for _, c := range meta.Capabilities {
		r.byCap[c] = append(r.byCap[c], meta.ID)
	}
	return nil
}

// Lookup returns a copy of the registered metadata for a provider ID.
func (r *Registry) Lookup(id string) (ProviderMeta, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byID[id]
	if !ok {
		return ProviderMeta{}, false
	}
	return reg.meta.clone(), true
}

// provider returns the concrete provider and its metadata snapshot for id.
// Package-private on purpose: Executor is the only caller, so there is no
// public route from the registry to a runnable provider.
func (r *Registry) provider(id string) (Provider, ProviderMeta, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byID[id]
	if !ok {
		return nil, ProviderMeta{}, false
	}
	return reg.provider, reg.meta.clone(), true
}

// MetasByCapability returns metadata copies for every provider that
// declares the given capability.
func (r *Registry) MetasByCapability(c Capability) []ProviderMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byCap[c]
	out := make([]ProviderMeta, 0, len(ids))
	for _, id := range ids {
		if reg, ok := r.byID[id]; ok {
			out = append(out, reg.meta.clone())
		}
	}
	return out
}

// PassiveMetas returns metadata copies for every registered passive provider.
func (r *Registry) PassiveMetas() []ProviderMeta { return r.metasByActivity(ActivityPassive) }

// ActiveMetas returns metadata copies for every registered active provider.
func (r *Registry) ActiveMetas() []ProviderMeta { return r.metasByActivity(ActivityActive) }

func (r *Registry) metasByActivity(a ActivityClass) []ProviderMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderMeta, 0, len(r.byID))
	for _, reg := range r.byID {
		if reg.meta.ActivityClass == a {
			out = append(out, reg.meta.clone())
		}
	}
	return out
}

// AllMetas returns metadata copies for every registered provider.
func (r *Registry) AllMetas() []ProviderMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderMeta, 0, len(r.byID))
	for _, reg := range r.byID {
		out = append(out, reg.meta.clone())
	}
	return out
}

// Capabilities returns every capability with at least one provider.
func (r *Registry) Capabilities() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	caps := make([]Capability, 0, len(r.byCap))
	for c := range r.byCap {
		caps = append(caps, c)
	}
	return caps
}

// ============================================================
// BaseProvider — common implementation helper
// ============================================================

// BaseProvider supplies Meta() for a provider by composition. Embed a
// *BaseProvider in your provider struct and implement Lookup or Probe.
type BaseProvider struct {
	MetaVal ProviderMeta
}

// Meta returns the embedded metadata.
func (b *BaseProvider) Meta() ProviderMeta { return b.MetaVal }

// ValidateMeta checks the embedded metadata is well-formed.
func (b *BaseProvider) ValidateMeta() error { return b.MetaVal.Validate() }
