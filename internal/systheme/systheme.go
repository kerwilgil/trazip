// Package systheme reports Windows' own light/dark app theme preference.
// It exists because WebView2's content-side prefers-color-scheme media
// query does not reliably track this OS setting — see
// frontend/src/lib/theme.ts, where TRAZIP's "system" theme choice needs
// an authoritative source instead of trusting the webview alone.
package systheme

// Preference is always one of Dark, Light, or Unknown — never a bool.
// A bool would make "false" mean two different things at once: "Windows
// is set to light" and "this platform has no way to know", which the
// frontend must handle differently (the first is a real answer to trust,
// the second must fall back to the browser's own media query).
const (
	Dark    = "dark"
	Light   = "light"
	Unknown = ""
)
