package update

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// stableChannel is the only Manifest.Channel value this build trusts.
	stableChannel = "stable"

	// updaterAssetName is the ONLY filename ever accepted for the helper
	// binary — fixed, never taken from the manifest as free text, exactly
	// like expectedAppAssetName below.
	updaterAssetName = "trazip-updater.exe"
)

var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// expectedAppAssetName is the ONLY filename TRAZIP will ever accept for
// the app executable asset on this platform — an exact match against a
// name derived entirely from the manifest's own (already signature- and
// format-verified) Version field, never accepted as free text from the
// manifest itself. This is what actually blocks path traversal, absolute
// paths, and UNC paths: an attacker-controlled string can never equal
// this fixed, locally-computed name, so there's no sanitization to get
// wrong — filepath.Base or similar would behave differently for "/" and
// "\" across platforms and is exactly the kind of check that looks safe
// and isn't.
func expectedAppAssetName(version string) string {
	return "TRAZIP-" + version + ".exe"
}

// validateManifest checks every field of an Ed25519-verified manifest
// before ANY of it is trusted for a network request or filesystem
// operation. A verified signature only proves who published the bytes; it
// says nothing about whether the bytes themselves are well-formed, so this
// still fails closed on anything that doesn't look right — a manifest
// that verifies but is malformed is exactly as untrustworthy as one that
// doesn't verify at all. Returns the two validated asset identities the
// caller actually needs (app + updater) for the requested arch.
func validateManifest(m *Manifest, arch string) (app, updater ManifestAsset, err error) {
	if m.Channel != stableChannel {
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("manifest channel %q is not %q", m.Channel, stableChannel)
	}
	v, err := parseVersion(m.Version)
	if err != nil {
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("manifest version %q: %w", m.Version, err)
	}
	if v.dev {
		// parseVersion accepts a "-dev" suffix so a locally built dev binary
		// can order itself against stable releases, but the distribution
		// channel is stable-only: a signed manifest declaring a dev version
		// has no legitimate meaning here. Reject it outright rather than lean
		// on the tag/version cross-check in checkRelease alone.
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("manifest version %q is a development version; the stable channel does not accept it", m.Version)
	}
	if m.NotesURL != "" {
		if err := validateNotesURL(m.NotesURL); err != nil {
			return ManifestAsset{}, ManifestAsset{}, err
		}
	}

	platform, ok := m.Windows[arch]
	if !ok {
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("manifest has no windows/%s entry", arch)
	}
	appName := expectedAppAssetName(m.Version)
	if err := validateManifestAsset(platform.App, appName); err != nil {
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("app asset: %w", err)
	}
	if err := validateManifestAsset(platform.Updater, updaterAssetName); err != nil {
		return ManifestAsset{}, ManifestAsset{}, fmt.Errorf("updater asset: %w", err)
	}
	return platform.App, platform.Updater, nil
}

// validateManifestAsset requires an EXACT match against want.
func validateManifestAsset(a ManifestAsset, want string) error {
	if a.Asset != want {
		return fmt.Errorf("asset name %q does not match the expected %q", a.Asset, want)
	}
	if !sha256HexPattern.MatchString(a.SHA256) {
		return fmt.Errorf("sha256 %q is not 64 hex characters", a.SHA256)
	}
	if a.Size <= 0 {
		return fmt.Errorf("size %d must be positive", a.Size)
	}
	if a.Size > maxDownloadBytes {
		return fmt.Errorf("size %d exceeds the %d byte limit", a.Size, maxDownloadBytes)
	}
	return nil
}

// validateNotesURL keeps "Ver novedades" from ever being handed a
// javascript:, data:, file:, or arbitrary-host URL to open in the user's
// browser — restricted to TRAZIP's own official releases channel.
func validateNotesURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notesUrl %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("notesUrl %q must use https", raw)
	}
	if u.Host != "github.com" {
		return fmt.Errorf("notesUrl %q must be on github.com", raw)
	}
	// Accept both legacy and new repository URLs for backward compatibility.
	if strings.HasPrefix(u.Path, "/kerwilgil/trazip-releases/") ||
		strings.HasPrefix(u.Path, "/kerwilgil/trazip/") {
		return nil
	}
	return fmt.Errorf("notesUrl %q is not under the official releases channel (legacy: /kerwilgil/trazip-releases/, new: /kerwilgil/trazip/)", raw)
}