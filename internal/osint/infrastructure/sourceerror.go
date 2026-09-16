// Package infrastructure provides source error handling for infrastructure intelligence.
package infrastructure

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// ClassifyErrorType classifies an error into a standard error type.
// This is used for SourceError.ErrorType field.
func ClassifyErrorType(err error) string {
	if err == nil {
		return "unknown"
	}
	// Check for context sentinels FIRST before string matching
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	errStr := err.Error()
	return classifyErrorString(errStr)
}

// classifyErrorString classifies an error string into a standard error type.
func classifyErrorString(errStr string) string {
	switch {
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline"):
		return "timeout"
	case strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limited"):
		return "rate_limit"
	case strings.Contains(errStr, "500") || strings.Contains(errStr, "502") || strings.Contains(errStr, "503") || strings.Contains(errStr, "server error"):
		return "server_error"
	case strings.Contains(errStr, "decode") || strings.Contains(errStr, "unmarshal") || strings.Contains(errStr, "malformed"):
		return "malformed"
	case strings.Contains(errStr, "canceled") || strings.Contains(errStr, "cancelled"):
		return "cancelled"
	default:
		return "unknown"
	}
}

// SanitizeErrorMessage removes sensitive information from error messages.
// This prevents secrets like API keys, passwords, tokens from being logged.
func SanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return sanitizeErrorString(err.Error())
}

// sanitizeErrorString removes sensitive patterns from error strings.
func sanitizeErrorString(errStr string) string {
	// Pre-compiled regex patterns for sensitive data redaction
	// Each pattern uses capture group 1 for the prefix to preserve (including = or :)
	redactionPatterns := []*regexp.Regexp{
		// api_key=VALUE, apikey=VALUE, api-key=VALUE
		regexp.MustCompile(`(?i)(api[_-]?key\s*[:=]\s*)[^\s,}"']+`),
		// Authorization: Bearer VALUE, Authorization: Api-Key VALUE
		regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|api[_-]?key)\s+)[^\s,}"']+`),
		// password=VALUE, secret=VALUE, token=VALUE, credential=VALUE
		regexp.MustCompile(`(?i)((?:password|secret|token|credential)\s*[:=]\s*)[^\s,}"']+`),
		// access_key=VALUE, secret_key=VALUE
		regexp.MustCompile(`(?i)((?:access[_-]?key|secret[_-]?key)\s*[:=]\s*)[^\s,}"']+`),
	}

	result := errStr
	for _, re := range redactionPatterns {
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			// Get capture group 1 (the prefix)
			matches := re.FindStringSubmatch(match)
			if len(matches) >= 2 && matches[1] != "" {
				return matches[1] + "***"
			}
			// Fallback: find last = or : or space
			lastDelim := -1
			for i := len(match) - 1; i >= 0; i-- {
				if match[i] == '=' || match[i] == ':' || match[i] == ' ' {
					lastDelim = i
					break
				}
			}
			if lastDelim >= 0 {
				return match[:lastDelim+1] + "***"
			}
			return "***"
		})
	}

	return result
}

// NewSourceError creates a SourceError with classified and sanitized error.
func NewSourceError(provider, operation string, err error) SourceError {
	sanitizedMsg := SanitizeErrorMessage(err)
	errorType := ClassifyErrorType(err)
	return SourceError{
		Provider:  provider,
		Operation: operation,
		Message:   sanitizedMsg,
		ErrorType: errorType,
	}
}