// Package osint provides tests for the ScopeGuard.
package osint

import (
	"testing"
)

func TestScopeGuardFailClosed(t *testing.T) {
	guard := NewScopeGuard()

	// Not authorized
	if guard.Authorized() {
		t.Error("New guard should not be authorized")
	}

	err := guard.RequireScope("port_scan", "test.active")
	if err == nil {
		t.Error("RequireScope on unauthorized guard should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}

	// CheckTarget on unauthorized
	err = guard.CheckTarget("192.168.1.1")
	if err == nil {
		t.Error("CheckTarget on unauthorized guard should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}
}

func TestScopeGuardAuthorize(t *testing.T) {
	guard := NewScopeGuard()

	err := guard.Authorize("LAN audit", []string{"192.168.1.0/24", "10.0.0.1", "internal.example.com"})
	if err != nil {
		t.Errorf("Authorize: %v", err)
	}

	if !guard.Authorized() {
		t.Error("Guard should be authorized after Authorize")
	}
	if guard.Label() != "LAN audit" {
		t.Errorf("Label = %q, want LAN audit", guard.Label())
	}
}

func TestScopeGuardCheckAddr(t *testing.T) {
	guard := NewScopeGuard()
	guard.Authorize("test", []string{"192.168.1.0/24"})

	// In scope
	if err := guard.CheckAddr("192.168.1.1"); err != nil {
		t.Errorf("CheckAddr in scope: %v", err)
	}
	if err := guard.CheckAddr("192.168.1.254"); err != nil {
		t.Errorf("CheckAddr in scope (end): %v", err)
	}

	// Out of scope
	err := guard.CheckAddr("10.0.0.1")
	if err == nil {
		t.Error("CheckAddr out of scope should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}
}

func TestScopeGuardCheckHost(t *testing.T) {
	guard := NewScopeGuard()
	guard.Authorize("test", []string{"internal.example.com"})

	// Exact match (case insensitive)
	if err := guard.CheckHost("internal.example.com"); err != nil {
		t.Errorf("CheckHost exact: %v", err)
	}
	if err := guard.CheckHost("INTERNAL.EXAMPLE.COM"); err != nil {
		t.Errorf("CheckHost case insensitive: %v", err)
	}

	// Not in scope
	err := guard.CheckHost("external.example.com")
	if err == nil {
		t.Error("CheckHost not in scope should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}
}

func TestScopeGuardCheckTarget(t *testing.T) {
	guard := NewScopeGuard()
	guard.Authorize("test", []string{"192.168.1.0/24", "10.0.0.1", "internal.example.com"})

	// CIDR
	if err := guard.CheckTarget("192.168.1.0/24"); err != nil {
		t.Errorf("CheckTarget CIDR exact: %v", err)
	}

	// Subset CIDR
	if err := guard.CheckTarget("192.168.1.0/25"); err != nil {
		t.Errorf("CheckTarget CIDR subset: %v", err)
	}

	// Single IP
	if err := guard.CheckTarget("192.168.1.50"); err != nil {
		t.Errorf("CheckTarget IP in CIDR: %v", err)
	}

	// Exact IP authorized
	if err := guard.CheckTarget("10.0.0.1"); err != nil {
		t.Errorf("CheckTarget exact IP: %v", err)
	}

	// Hostname
	if err := guard.CheckTarget("internal.example.com"); err != nil {
		t.Errorf("CheckTarget hostname: %v", err)
	}

	// Out of scope CIDR
	err := guard.CheckTarget("10.0.0.0/8")
	if err == nil {
		t.Error("CheckTarget superset CIDR should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}

	// Out of scope IP
	err = guard.CheckTarget("172.16.0.1")
	if err == nil {
		t.Error("CheckTarget out of scope IP should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}

	// Out of scope host
	err = guard.CheckTarget("external.example.com")
	if err == nil {
		t.Error("CheckTarget out of scope host should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}
}

func TestScopeGuardRequireTarget(t *testing.T) {
	guard := NewScopeGuard()
	guard.Authorize("test", []string{"192.168.1.0/24"})

	// In scope - should pass
	err := guard.RequireTarget("port_scan", "test.active", "192.168.1.1")
	if err != nil {
		t.Errorf("RequireTarget in scope: %v", err)
	}

	// Out of scope - should fail with ScopeDeniedError
	err = guard.RequireTarget("port_scan", "test.active", "10.0.0.1")
	if err == nil {
		t.Error("RequireTarget out of scope should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}

	// Unauthorized guard
	guard2 := NewScopeGuard()
	err = guard2.RequireTarget("port_scan", "test.active", "192.168.1.1")
	if err == nil {
		t.Error("RequireTarget unauthorized should fail")
	}
	if !IsScopeDenied(err) {
		t.Errorf("Error should be ScopeDenied: %v", err)
	}
}

func TestScopeGuardEmptyScope(t *testing.T) {
	guard := NewScopeGuard()

	err := guard.Authorize("empty", []string{})
	if err == nil {
		t.Error("Authorize empty scope should fail")
	}
}

func TestScopeGuardInvalidEntries(t *testing.T) {
	guard := NewScopeGuard()

	// Mix of valid and invalid - should accept valid ones
	err := guard.Authorize("mixed", []string{"192.168.1.0/24", "invalid", "10.0.0.1"})
	if err != nil {
		t.Errorf("Authorize with some invalid: %v", err)
	}

	if err := guard.CheckTarget("192.168.1.1"); err != nil {
		t.Errorf("Valid CIDR should work: %v", err)
	}
	if err := guard.CheckTarget("10.0.0.1"); err != nil {
		t.Errorf("Valid IP should work: %v", err)
	}
}
