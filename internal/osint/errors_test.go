// Package osint provides tests for the typed error taxonomy.
package osint

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestErrorSentinels(t *testing.T) {
	// Verify all sentinels exist and are non-nil
	sentinels := map[string]error{
		"ErrInvalidConfig":         ErrInvalidConfig,
		"ErrUnsupportedCapability": ErrUnsupportedCapability,
		"ErrScopeDenied":           ErrScopeDenied,
		"ErrRateLimited":           ErrRateLimited,
		"ErrProviderUnavailable":   ErrProviderUnavailable,
		"ErrExternalLookupFailed":  ErrExternalLookupFailed,
		"ErrCanceled":              ErrCanceled,
		"ErrDeadlineExceeded":      ErrDeadlineExceeded,
		"ErrProviderNotFound":      ErrProviderNotFound,
		"ErrCacheMiss":             ErrCacheMiss,
		"ErrCacheFull":             ErrCacheFull,
	}

	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
		}
	}
}

func TestInvalidConfigError(t *testing.T) {
	err := &InvalidConfigError{Provider: "test", Field: "apiKey", Reason: "empty"}
	if err.Error() != "osint: invalid config for provider \"test\" field \"apiKey\": empty" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("Is(ErrInvalidConfig) should be true")
	}
	if !IsInvalidConfig(err) {
		t.Error("IsInvalidConfig should be true")
	}
}

func TestUnsupportedCapabilityError(t *testing.T) {
	err := &UnsupportedCapabilityError{Provider: "test", Capability: CapabilityPortScan}
	if err.Error() != "osint: provider \"test\" does not support capability \"port_scan\"" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Error("Is(ErrUnsupportedCapability) should be true")
	}
	if !IsUnsupportedCapability(err) {
		t.Error("IsUnsupportedCapability should be true")
	}
}

func TestScopeDeniedError(t *testing.T) {
	err := &ScopeDeniedError{Target: "10.0.0.1", Reason: "out of scope"}
	if err.Error() != "osint: scope denied for target \"10.0.0.1\": out of scope" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrScopeDenied) {
		t.Error("Is(ErrScopeDenied) should be true")
	}
	if !IsScopeDenied(err) {
		t.Error("IsScopeDenied should be true")
	}
}

func TestScopeRequiredError(t *testing.T) {
	err := &ScopeRequiredError{Operation: "port_scan", Provider: "test.active"}
	if err.Error() != "osint: operation \"port_scan\" from provider \"test.active\" requires authorized scope" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrScopeDenied) {
		t.Error("Is(ErrScopeDenied) should be true")
	}
	if !IsScopeDenied(err) {
		t.Error("IsScopeDenied should be true for ScopeRequiredError")
	}
}

func TestRateLimitedError(t *testing.T) {
	err := &RateLimitedError{Provider: "test", RetryAfter: 5 * time.Second}
	expected := "osint: provider \"test\" rate limited, retry after 5s"
	if err.Error() != expected {
		t.Errorf("Error string: %q, want %q", err.Error(), expected)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Error("Is(ErrRateLimited) should be true")
	}
	if !IsRateLimited(err) {
		t.Error("IsRateLimited should be true")
	}

	// Without retry after
	err2 := &RateLimitedError{Provider: "test"}
	if err2.Error() != "osint: provider \"test\" rate limited" {
		t.Errorf("Error string without retry: %q", err2.Error())
	}
}

func TestProviderUnavailableError(t *testing.T) {
	err := &ProviderUnavailableError{Provider: "test", Reason: "connection refused"}
	if err.Error() != "osint: provider \"test\" unavailable: connection refused" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Error("Is(ErrProviderUnavailable) should be true")
	}
	if !IsProviderUnavailable(err) {
		t.Error("IsProviderUnavailable should be true")
	}
}

func TestExternalLookupFailedError(t *testing.T) {
	err := &ExternalLookupFailedError{Provider: "test", Query: "1.1.1.1", Reason: "timeout"}
	if err.Error() != "osint: external lookup failed for provider \"test\" query \"1.1.1.1\": timeout" {
		t.Errorf("Error string: %q", err.Error())
	}
	if !errors.Is(err, ErrExternalLookupFailed) {
		t.Error("Is(ErrExternalLookupFailed) should be true")
	}
	if !IsExternalLookupFailed(err) {
		t.Error("IsExternalLookupFailed should be true")
	}
}

func TestIsCanceled(t *testing.T) {
	// Direct sentinel
	if !IsCanceled(ErrCanceled) {
		t.Error("IsCanceled(ErrCanceled) should be true")
	}

	// Wrapped context.Canceled
	wrapped := errors.Join(ErrExternalLookupFailed, context.Canceled)
	if !IsCanceled(wrapped) {
		t.Error("IsCanceled(wrapped context.Canceled) should be true")
	}

	// Not canceled
	if IsCanceled(ErrRateLimited) {
		t.Error("IsCanceled(ErrRateLimited) should be false")
	}
}

func TestIsDeadlineExceeded(t *testing.T) {
	if !IsDeadlineExceeded(ErrDeadlineExceeded) {
		t.Error("IsDeadlineExceeded(ErrDeadlineExceeded) should be true")
	}

	wrapped := errors.Join(ErrExternalLookupFailed, context.DeadlineExceeded)
	if !IsDeadlineExceeded(wrapped) {
		t.Error("IsDeadlineExceeded(wrapped context.DeadlineExceeded) should be true")
	}

	if IsDeadlineExceeded(ErrRateLimited) {
		t.Error("IsDeadlineExceeded(ErrRateLimited) should be false")
	}
}

func TestIsRetryable(t *testing.T) {
	retryable := []error{
		ErrRateLimited,
		&RateLimitedError{Provider: "test"},
		ErrProviderUnavailable,
		&ProviderUnavailableError{Provider: "test", Reason: "down"},
		ErrExternalLookupFailed,
		&ExternalLookupFailedError{Provider: "test", Query: "q", Reason: "timeout"},
		ErrDeadlineExceeded,
	}

	for _, err := range retryable {
		if !IsRetryable(err) {
			t.Errorf("IsRetryable(%v) should be true", err)
		}
	}

	permanent := []error{
		ErrInvalidConfig,
		&InvalidConfigError{Provider: "t", Field: "f", Reason: "r"},
		ErrUnsupportedCapability,
		&UnsupportedCapabilityError{Provider: "t", Capability: CapabilityRDAP},
		ErrScopeDenied,
		&ScopeDeniedError{Target: "t", Reason: "r"},
		&ScopeRequiredError{Operation: "o", Provider: "p"},
	}

	for _, err := range permanent {
		if IsRetryable(err) {
			t.Errorf("IsRetryable(%v) should be false", err)
		}
		if !IsPermanent(err) {
			t.Errorf("IsPermanent(%v) should be true", err)
		}
	}
}

func TestIsPermanent(t *testing.T) {
	if !IsPermanent(ErrInvalidConfig) {
		t.Error("IsPermanent(ErrInvalidConfig) should be true")
	}
	if !IsPermanent(ErrUnsupportedCapability) {
		t.Error("IsPermanent(ErrUnsupportedCapability) should be true")
	}
	if !IsPermanent(ErrScopeDenied) {
		t.Error("IsPermanent(ErrScopeDenied) should be true")
	}

	if IsPermanent(ErrRateLimited) {
		t.Error("IsPermanent(ErrRateLimited) should be false")
	}
	if IsPermanent(ErrProviderUnavailable) {
		t.Error("IsPermanent(ErrProviderUnavailable) should be false")
	}
}

func TestActivityViolationError(t *testing.T) {
	err := &ActivityViolationError{Provider: "p", Pipeline: ActivityPassive, Actual: ActivityActive}
	if !errors.Is(err, ErrActivityViolation) {
		t.Error("Is(ErrActivityViolation) should be true")
	}
	if !IsActivityViolation(err) {
		t.Error("IsActivityViolation should be true")
	}
	if !IsPermanent(err) || IsRetryable(err) {
		t.Error("activity violation should be permanent, not retryable")
	}
}

func TestInvalidProvenanceError(t *testing.T) {
	err := &InvalidProvenanceError{Provider: "p", Reason: "missing ProviderID"}
	if !errors.Is(err, ErrInvalidProvenance) {
		t.Error("Is(ErrInvalidProvenance) should be true")
	}
	if !IsInvalidProvenance(err) {
		t.Error("IsInvalidProvenance should be true")
	}
	if !IsPermanent(err) || IsRetryable(err) {
		t.Error("invalid provenance should be permanent, not retryable")
	}
}
