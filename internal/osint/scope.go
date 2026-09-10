// Package osint provides the Scope Guard integration for active OSINT operations.
package osint

import (
	"fmt"

	"trazip/internal/scope"
)

// ScopeGuard wraps the core scope.Guard with OSINT-specific behavior.
// It enforces fail-closed authorization for active operations.
type ScopeGuard struct {
	guard *scope.Guard
}

// NewScopeGuard creates a new unauthorized scope guard.
func NewScopeGuard() *ScopeGuard {
	return &ScopeGuard{guard: scope.NewGuard()}
}

// Authorize declares the active scope. Must be called before any active operation.
// entries can be CIDRs (e.g., "192.168.1.0/24"), single IPs, or hostnames.
// Returns error if scope is empty or invalid.
func (g *ScopeGuard) Authorize(label string, entries []string) error {
	return g.guard.Authorize(label, entries)
}

// Authorized reports whether an active scope has been declared.
func (g *ScopeGuard) Authorized() bool {
	return g.guard.Authorized()
}

// Label returns the human description of the current scope.
func (g *ScopeGuard) Label() string {
	return g.guard.Label()
}

// CheckTarget verifies an IP address, hostname, or CIDR against the
// authorized scope, normalising through the underlying scope.Guard.
// Returns a ScopeDeniedError (wrapping ErrScopeDenied) if no scope is
// authorized or the target falls outside it.
func (g *ScopeGuard) CheckTarget(target string) error {
	if err := g.guard.CheckTarget(target); err != nil {
		return &ScopeDeniedError{Target: target, Reason: err.Error()}
	}
	return nil
}

// CheckAddr is a convenience alias of CheckTarget for callers that already
// know target is an IP address. The check performed is identical.
func (g *ScopeGuard) CheckAddr(addr string) error { return g.CheckTarget(addr) }

// CheckHost is a convenience alias of CheckTarget for callers that already
// know target is a hostname. The check performed is identical.
func (g *ScopeGuard) CheckHost(host string) error { return g.CheckTarget(host) }

// Guard returns the underlying scope.Guard for advanced use cases.
func (g *ScopeGuard) Guard() *scope.Guard {
	return g.guard
}

// ScopeRequiredError is returned when an active operation is attempted
// without an authorized scope.
type ScopeRequiredError struct {
	Operation string
	Provider  string
}

func (e *ScopeRequiredError) Error() string {
	return fmt.Sprintf("osint: operation %q from provider %q requires authorized scope", e.Operation, e.Provider)
}

func (e *ScopeRequiredError) Unwrap() error { return ErrScopeDenied }

// RequireScope returns a ScopeRequiredError if the guard is not authorized.
// The execution gate calls it before invoking any active provider.
func (g *ScopeGuard) RequireScope(operation, provider string) error {
	if !g.Authorized() {
		return &ScopeRequiredError{Operation: operation, Provider: provider}
	}
	return nil
}

// RequireTarget is a helper that checks a target against the scope.
// Returns ScopeDeniedError if not authorized or out of scope.
func (g *ScopeGuard) RequireTarget(operation, provider, target string) error {
	if err := g.RequireScope(operation, provider); err != nil {
		return err
	}
	if err := g.CheckTarget(target); err != nil {
		return err
	}
	return nil
}
