// Package osint provides typed errors for the OSINT subsystem.
package osint

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidConfig is returned when provider configuration is invalid.
var ErrInvalidConfig = errors.New("osint: invalid configuration")

// ErrUnsupportedCapability is returned when a provider doesn't support a requested capability.
var ErrUnsupportedCapability = errors.New("osint: unsupported capability")

// ErrScopeDenied is returned when an active operation is rejected by the scope guard.
var ErrScopeDenied = errors.New("osint: scope denied")

// ErrRateLimited is returned when a provider's rate limit is exceeded.
var ErrRateLimited = errors.New("osint: rate limited")

// ErrProviderUnavailable is returned when a provider cannot be reached.
var ErrProviderUnavailable = errors.New("osint: provider unavailable")

// ErrExternalLookupFailed is returned when an external lookup fails.
var ErrExternalLookupFailed = errors.New("osint: external lookup failed")

// ErrCanceled is returned when an operation is canceled via context.
var ErrCanceled = errors.New("osint: canceled")

// ErrDeadlineExceeded is returned when an operation exceeds its deadline.
var ErrDeadlineExceeded = errors.New("osint: deadline exceeded")

// ErrProviderNotFound is returned when a requested provider is not registered.
var ErrProviderNotFound = errors.New("osint: provider not found")

// ErrCacheMiss is returned when a cache lookup misses.
var ErrCacheMiss = errors.New("osint: cache miss")

// ErrCacheFull is returned when a bounded cache is at capacity.
var ErrCacheFull = errors.New("osint: cache full")

// ErrActivityViolation is returned when a provider is run through the wrong
// pipeline — e.g. an active provider submitted to ExecutePassive.
var ErrActivityViolation = errors.New("osint: activity class violation")

// ErrInvalidProvenance is returned when a successful result reaches the
// execution gate without valid, coherent provenance.
var ErrInvalidProvenance = errors.New("osint: invalid or missing provenance")

// InvalidConfigError wraps ErrInvalidConfig with details.
type InvalidConfigError struct {
	Provider string
	Field    string
	Reason   string
}

func (e *InvalidConfigError) Error() string {
	return fmt.Sprintf("osint: invalid config for provider %q field %q: %s", e.Provider, e.Field, e.Reason)
}

func (e *InvalidConfigError) Unwrap() error { return ErrInvalidConfig }

// IsInvalidConfig reports whether err is an ErrInvalidConfig (or wraps it).
func IsInvalidConfig(err error) bool {
	return errors.Is(err, ErrInvalidConfig)
}

// UnsupportedCapabilityError wraps ErrUnsupportedCapability with details.
type UnsupportedCapabilityError struct {
	Provider   string
	Capability Capability
}

func (e *UnsupportedCapabilityError) Error() string {
	return fmt.Sprintf("osint: provider %q does not support capability %q", e.Provider, e.Capability)
}

func (e *UnsupportedCapabilityError) Unwrap() error { return ErrUnsupportedCapability }

// IsUnsupportedCapability reports whether err is an ErrUnsupportedCapability (or wraps it).
func IsUnsupportedCapability(err error) bool {
	return errors.Is(err, ErrUnsupportedCapability)
}

// ScopeDeniedError wraps ErrScopeDenied with details.
type ScopeDeniedError struct {
	Target string
	Reason string
}

func (e *ScopeDeniedError) Error() string {
	return fmt.Sprintf("osint: scope denied for target %q: %s", e.Target, e.Reason)
}

func (e *ScopeDeniedError) Unwrap() error { return ErrScopeDenied }

// IsScopeDenied reports whether err is an ErrScopeDenied (or wraps it).
func IsScopeDenied(err error) bool {
	return errors.Is(err, ErrScopeDenied)
}

// RateLimitedError wraps ErrRateLimited with details.
type RateLimitedError struct {
	Provider   string
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("osint: provider %q rate limited, retry after %v", e.Provider, e.RetryAfter)
	}
	return fmt.Sprintf("osint: provider %q rate limited", e.Provider)
}

func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// IsRateLimited reports whether err is an ErrRateLimited (or wraps it).
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// ProviderUnavailableError wraps ErrProviderUnavailable with details.
type ProviderUnavailableError struct {
	Provider string
	Reason   string
}

func (e *ProviderUnavailableError) Error() string {
	return fmt.Sprintf("osint: provider %q unavailable: %s", e.Provider, e.Reason)
}

func (e *ProviderUnavailableError) Unwrap() error { return ErrProviderUnavailable }

// IsProviderUnavailable reports whether err is an ErrProviderUnavailable (or wraps it).
func IsProviderUnavailable(err error) bool {
	return errors.Is(err, ErrProviderUnavailable)
}

// ExternalLookupFailedError wraps ErrExternalLookupFailed with details.
type ExternalLookupFailedError struct {
	Provider string
	Query    string
	Reason   string
}

func (e *ExternalLookupFailedError) Error() string {
	return fmt.Sprintf("osint: external lookup failed for provider %q query %q: %s", e.Provider, e.Query, e.Reason)
}

func (e *ExternalLookupFailedError) Unwrap() error { return ErrExternalLookupFailed }

// IsExternalLookupFailed reports whether err is an ErrExternalLookupFailed (or wraps it).
func IsExternalLookupFailed(err error) bool {
	return errors.Is(err, ErrExternalLookupFailed)
}

// ActivityViolationError wraps ErrActivityViolation with details. It is
// returned by the execution gate when a provider is run through a pipeline
// that does not match its declared ActivityClass.
type ActivityViolationError struct {
	Provider string
	Pipeline ActivityClass // the pipeline the caller used
	Actual   ActivityClass // the provider's declared class
}

func (e *ActivityViolationError) Error() string {
	return fmt.Sprintf("osint: provider %q (%s) cannot run in the %s pipeline", e.Provider, e.Actual, e.Pipeline)
}

func (e *ActivityViolationError) Unwrap() error { return ErrActivityViolation }

// IsActivityViolation reports whether err is an ErrActivityViolation (or wraps it).
func IsActivityViolation(err error) bool {
	return errors.Is(err, ErrActivityViolation)
}

// InvalidProvenanceError wraps ErrInvalidProvenance with details. It is
// returned by the execution gate when a provider reports success but the
// accompanying provenance is missing or incoherent.
type InvalidProvenanceError struct {
	Provider string
	Reason   string
}

func (e *InvalidProvenanceError) Error() string {
	return fmt.Sprintf("osint: provider %q returned a successful result with invalid provenance: %s", e.Provider, e.Reason)
}

func (e *InvalidProvenanceError) Unwrap() error { return ErrInvalidProvenance }

// IsInvalidProvenance reports whether err is an ErrInvalidProvenance (or wraps it).
func IsInvalidProvenance(err error) bool {
	return errors.Is(err, ErrInvalidProvenance)
}

// IsCanceled reports whether err is due to context cancellation (including wrapped).
func IsCanceled(err error) bool {
	return errors.Is(err, ErrCanceled) || errors.Is(err, context.Canceled)
}

// IsDeadlineExceeded reports whether err is due to deadline exceeded (including wrapped).
func IsDeadlineExceeded(err error) bool {
	return errors.Is(err, ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

// IsRetryable reports whether an error is transient and worth retrying.
func IsRetryable(err error) bool {
	return IsRateLimited(err) || IsProviderUnavailable(err) || IsExternalLookupFailed(err) || IsDeadlineExceeded(err)
}

// IsPermanent reports whether an error is permanent and should not be retried.
func IsPermanent(err error) bool {
	return IsInvalidConfig(err) || IsUnsupportedCapability(err) || IsScopeDenied(err) ||
		IsActivityViolation(err) || IsInvalidProvenance(err)
}
