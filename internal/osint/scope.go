// Package osint provides the Scope Guard integration for active OSINT operations.
package osint

import (
	"context"
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

// CheckAddr verifies an IP address is within the authorized scope.
// Returns ErrScopeDenied if not authorized or out of scope.
func (g *ScopeGuard) CheckAddr(addr string) error {
	// Parse as netip.Addr
	// We need to import netip - let's use the guard's internal method
	return g.checkTarget(addr)
}

// CheckHost verifies a hostname is within the authorized scope.
// Returns ErrScopeDenied if not authorized or out of scope.
func (g *ScopeGuard) CheckHost(host string) error {
	return g.checkTarget(host)
}

// CheckTarget verifies an IP, hostname, or CIDR against the authorized scope.
// Returns ErrScopeDenied if not authorized or out of scope.
func (g *ScopeGuard) CheckTarget(target string) error {
	return g.checkTarget(target)
}

func (g *ScopeGuard) checkTarget(target string) error {
	err := g.guard.CheckTarget(target)
	if err != nil {
		return &ScopeDeniedError{Target: target, Reason: err.Error()}
	}
	return nil
}

// CheckPrefix verifies a CIDR prefix is within scope.
// target must be a valid CIDR string (e.g., "10.0.0.0/8").
func (g *ScopeGuard) CheckPrefix(target string) error {
	// Use the underlying guard's CheckPrefix via CheckTarget
	return g.checkTarget(target)
}

// Guard returns the underlying scope.Guard for advanced use cases.
func (g *ScopeGuard) Guard() *scope.Guard {
	return g.guard
}

// ============================================================
// Context-aware scope checking
// ============================================================

// WithScopeContext returns a context that will be canceled if the scope
// guard becomes unauthorized (e.g., scope revoked). Useful for long-running
// active operations that should stop if scope is withdrawn.
func (g *ScopeGuard) WithScopeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	// For V1.5-2, scope doesn't support dynamic revocation.
	// Return a no-op cancel for now.
	return ctx, func() {}
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

// RequireScope is a helper that returns ScopeRequiredError if the guard
// is not authorized. Use at the start of active provider Execute methods.
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
