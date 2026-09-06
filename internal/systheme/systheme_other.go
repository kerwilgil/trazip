//go:build !windows

package systheme

// Preference always reports Unknown outside Windows — there is no
// equivalent registry or API integration for other platforms yet.
// Reporting Light here would be wrong in a different way than reporting
// Dark: either one asserts a specific OS preference TRAZIP has no way to
// know, so the frontend must treat Unknown as "fall back to the browser's
// own prefers-color-scheme", never silently pick one.
func Preference() string {
	return Unknown
}
