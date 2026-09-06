// Package update checks TRAZIP's official distribution channel for a newer
// release, verifies it (Ed25519-signed manifest + SHA-256 asset hash), and
// prepares it for installation by a separate helper process
// (cmd/trazip-updater) — because Windows cannot replace a running .exe's own
// bytes. This package owns none of that final replace/relaunch step; it only
// gets verified files safely onto disk and hands the helper paths plus
// hashes it re-checks independently.
//
// Deliberately ignorant of React/Wails: internal/api wraps Manager for the
// GUI, the same way every other long-running operation in this codebase
// (Live Capture, Throughput, VoIP analysis) keeps its domain logic separate
// from the binding layer.
package update

import "time"

// Status is the update lifecycle's own explicit state machine — never
// several independent bools, which can combine into states that don't
// correspond to anything real (e.g. "downloading" and "error" both true).
type Status string

const (
	StatusIdle        Status = "idle"
	StatusChecking    Status = "checking"
	StatusAvailable   Status = "available"
	StatusDownloading Status = "downloading"
	StatusVerifying   Status = "verifying"
	StatusReady       Status = "ready"
	StatusInstalling  Status = "installing"
	StatusError       Status = "error"
)

// Asset is one downloadable, verified file named in a signed update
// manifest.
type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ReleaseInfo is the answer to "is there an update, and what is it" — built
// only from a manifest that has already passed Ed25519 verification and
// full field validation (see validate.go). Asset and UpdaterAsset are
// always both populated together when Available is true: installing an
// update always needs the new TRAZIP executable AND a matching
// trazip-updater.exe, since a standalone .exe download has no other way
// to get the helper it needs to install itself.
type ReleaseInfo struct {
	CurrentVersion string    `json:"currentVersion"`
	LatestVersion  string    `json:"latestVersion"`
	Available      bool      `json:"available"`
	PublishedAt    time.Time `json:"publishedAt"`
	NotesURL       string    `json:"notesUrl"`
	Asset          Asset     `json:"asset"`
	UpdaterAsset   Asset     `json:"updaterAsset"`
}

// Manifest is update.json's own shape, published alongside every release —
// see internal/update/sign.go for why nothing here is trusted until its
// companion update.json.sig verifies against the embedded public key, and
// validate.go for why a verified signature alone still isn't enough to
// trust the fields themselves.
type Manifest struct {
	Version     string                    `json:"version"`
	Channel     string                    `json:"channel"`
	PublishedAt time.Time                 `json:"publishedAt"`
	NotesURL    string                    `json:"notesUrl"`
	Windows     map[string]PlatformAssets `json:"windows"` // key: GOARCH, e.g. "amd64"
}

// PlatformAssets is one platform/arch entry inside a Manifest: the app
// executable and the updater helper that must ship together, since
// installing an update always requires both, regardless of whether the
// running TRAZIP is a portable or standalone install.
type PlatformAssets struct {
	App     ManifestAsset `json:"app"`
	Updater ManifestAsset `json:"updater"`
}

// ManifestAsset is one asset's verified identity inside a manifest.
type ManifestAsset struct {
	Asset  string `json:"asset"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// StatusSnapshot is what the GUI polls — Manager's entire externally visible
// state at one instant.
type StatusSnapshot struct {
	Status      Status       `json:"status"`
	Info        *ReleaseInfo `json:"info,omitempty"`
	Downloaded  int64        `json:"downloaded,omitempty"`
	Total       int64        `json:"total,omitempty"`
	Error       string       `json:"error,omitempty"`
	InstallPath string       `json:"installPath,omitempty"` // set once Status == StatusReady
	UpdaterPath string       `json:"updaterPath,omitempty"` // set once Status == StatusReady
	LastCheck   time.Time    `json:"lastCheck,omitempty"`
}
