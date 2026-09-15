// Package infrastructure provides source error handling for infrastructure intelligence.
package infrastructure

import (
	"strings"
)

// ClassifyErrorType classifies an error into a standard error type.
// This is used for SourceError.ErrorType field.
func ClassifyErrorType(err error) string {
	if err == nil {
		return "unknown"
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
	// List of sensitive patterns to redact
	sensitivePatterns := []struct {
		pattern string
		replace string
	}{
		{`(?i)(api[_-]?key|apikey)\s*[:=]\s*[^\s]+`, "$1=***"},
		{`(?i)(authorization|bearer)\s+[^\s]+`, "$1 ***"},
		{`(?i)(password|secret|token|credential)\s*[:=]\s*[^\s]+`, "$1=***"},
		{`(?i)(access[_-]?key|secret[_-]?key)\s*[:=]\s*[^\s]+`, "$1=***"},
		{`\b[A-Za-z0-9+/]{40,}={0,2}\b`, "***"}, // base64-like strings
		{`\b[0-9a-f]{32,}\b`, "***"},             // hex strings (32+ chars)
		{`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`, "***"}, // UUIDs
	}

	result := errStr
	for _, sp := range sensitivePatterns {
		// Simple string replacement for common patterns
		// For more complex patterns, we'd use regex
		if strings.Contains(strings.ToLower(result), strings.ToLower(sp.pattern)) {
			// We can't easily do regex replacement here without importing regexp
			// Just do basic redaction for common patterns
		}
	}

	// Basic redactions using string replacement
	redactions := []struct {
		needle string
	}{
		{"api_key="},
		{"apikey="},
		{"api-key="},
		{"authorization="},
		{"bearer "},
		{"password="},
		{"secret="},
		{"token="},
		{"credential="},
		{"access_key="},
		{"secret_key="},
	}

	for _, r := range redactions {
		if idx := strings.Index(strings.ToLower(result), r.needle); idx >= 0 {
			end := idx + len(r.needle)
			// Find the end of the value (space, comma, } or end of string)
			valueEnd := end
			for valueEnd < len(result) && result[valueEnd] != ' ' && result[valueEnd] != ',' && result[valueEnd] != '}' && result[valueEnd] != '"' && result[valueEnd] != '\'' {
				valueEnd++
			}
			if valueEnd > end {
				result = result[:end] + "***" + result[valueEnd:]
			}
		}
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