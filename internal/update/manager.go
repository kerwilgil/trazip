package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// checkInterval bounds how often Check actually hits the network unless the
	// caller forces it (the user pressing "Buscar actualizaciones") — see §7 of
	// the design this implements: at most once at startup, not repeatedly.
	checkInterval = 24 * time.Hour

	// LegacyReleaseRepo is the v1.4 distribution channel — kept for bridge
	// compatibility only. v1.5+ uses StableReleaseRepo.
	LegacyReleaseRepo = "kerwilgil/trazip-releases"

	// StableReleaseRepo is the v1.5+ official distribution channel.
	StableReleaseRepo = "kerwilgil/trazip"
)

const (
	// stableChannel is the only Manifest.Channel value this build trusts.
	stableChannel = "stable"

	// updaterAssetName is the ONLY filename ever accepted for the helper
	// binary — fixed, never taken from the manifest as free text, exactly
	// like expectedAppAssetName below.
	updaterAssetName = "trazip-updater.exe"
)

// validateChannelConfig validates a ChannelConfig for production use.
// Returns an error if the configuration is invalid.
func validateChannelConfig(cfg ChannelConfig) error {
	// Name: must be "stable" (only supported channel for now)
	if cfg.Name != stableChannel {
		return fmt.Errorf("channel name %q is not supported; only %q is allowed", cfg.Name, stableChannel)
	}

	// Repository: must be in owner/repo format (GitHub repository format)
	if cfg.Repository == "" {
		return fmt.Errorf("repository is required")
	}
	if err := validateRepositoryFormat(cfg.Repository); err != nil {
		return err
	}

	// APIBase: if empty, defaults to GitHub; if provided, must be valid HTTPS URL
	if cfg.APIBase != "" {
		u, err := url.Parse(cfg.APIBase)
		if err != nil {
			return fmt.Errorf("APIBase %q is not a valid URL: %w", cfg.APIBase, err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("APIBase %q must use https scheme", cfg.APIBase)
		}
		if u.Host == "" {
			return fmt.Errorf("APIBase %q must have a host", cfg.APIBase)
		}
		if u.User != nil {
			return fmt.Errorf("APIBase %q must not contain user credentials", cfg.APIBase)
		}
		if u.RawQuery != "" {
			return fmt.Errorf("APIBase %q must not contain query parameters", cfg.APIBase)
		}
		if u.Fragment != "" {
			return fmt.Errorf("APIBase %q must not contain a fragment", cfg.APIBase)
		}
	}
	return nil
}

// normalizeChannelConfig normalizes a ChannelConfig for production use.
// Returns the normalized config or an error if invalid.
func normalizeChannelConfig(cfg ChannelConfig) (ChannelConfig, error) {
	if err := validateChannelConfig(cfg); err != nil {
		return ChannelConfig{}, err
	}
	// Normalize APIBase: remove trailing slash
	if cfg.APIBase != "" {
		u, _ := url.Parse(cfg.APIBase)
		cfg.APIBase = strings.TrimRight(u.String(), "/")
	}
	return cfg, nil
}

// repositoryPattern validates GitHub repository format (owner/repo)
var repositoryPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*\/[a-zA-Z0-9_\-\.]+$`)

// validateRepositoryFormat validates the repository format strictly.
// Rejects: empty, missing slash, extra slashes, dot segments, traversal, URLs, whitespace, etc.
func validateRepositoryFormat(repo string) error {
	if repo == "" {
		return fmt.Errorf("repository is required")
	}
	// Must be exactly owner/repo format (one slash, no extra slashes)
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return fmt.Errorf("repository %q must be in owner/repo format (exactly one slash)", repo)
	}
	owner, repoName := parts[0], parts[1]
	// Owner and repo must not be empty
	if owner == "" || repoName == "" {
		return fmt.Errorf("repository %q has empty owner or repo", repo)
	}
	// Reject dot segments (current/parent directory)
	if owner == "." || owner == ".." || repoName == "." || repoName == ".." {
		return fmt.Errorf("repository %q contains invalid dot segment", repo)
	}
	// Reject dot segments anywhere
	for _, part := range parts {
		if part == "." || part == ".." {
			return fmt.Errorf("repository %q contains invalid dot segment", repo)
		}
	}
	// Validate characters (GitHub owner/repo format)
	if !repositoryPattern.MatchString(repo) {
		return fmt.Errorf("repository %q must be in owner/repo format (e.g., owner/repo)", repo)
	}
return nil
}

// ChannelConfig represents the configuration for an update channel.
type ChannelConfig struct {
	// Name is the human-readable name of the channel (always "stable" for now).
	Name string `json:"name"`

	// Repository is the GitHub repository (owner/repo) that hosts the releases.
	Repository string `json:"repository"`

	// APIBase is the base URL for the GitHub API. Defaults to GitHub's public API.
	APIBase string `json:"apiBase,omitempty"`
}

// DefaultStableChannelConfig returns the configuration for the stable channel.
// This is the v1.5+ official channel pointing to the new repository.
func DefaultStableChannelConfig() ChannelConfig {
	return ChannelConfig{
		Name:       stableChannel,
		Repository: StableReleaseRepo,
		APIBase:    githubAPIBase,
	}
}

// ChannelConfigForLegacy returns the channel configuration for v1.4 bridge compatibility.
// This is used only for bridge testing and v1.4 compatibility testing.
// The bridge release published in trazip-releases must use this repository.
func ChannelConfigForLegacy() ChannelConfig {
	return ChannelConfig{
		Name:       stableChannel, // v1.4 only accepts "stable"
		Repository: LegacyReleaseRepo,
		APIBase:    githubAPIBase,
	}
}

// UpdateConfig holds the configuration for the update client.
type UpdateConfig struct {
	// CurrentVersion is the currently installed version.
	CurrentVersion string

	// DownloadDir is the directory where verified updates are downloaded.
	DownloadDir string

	// SettingsPath is the path where update settings are persisted.
	SettingsPath string

	// Channel is the update channel to use. Defaults to the stable channel.
	Channel ChannelConfig

	// HTTPClient is the HTTP client to use. If nil, a default client is created.
	HTTPClient *http.Client

	// UserAgent is the User-Agent string to use for requests.
	UserAgent string
}

// settings is the only thing this package persists to disk on its own — no
// license keys or credentials involved, so unlike internal/intel/geoupdate
// it needs no encryption, just enough state that the 24h cadence, the
// user's auto-check preference, and replay protection survive a restart.
type settings struct {
	AutoCheck   bool         `json:"autoCheck"`
	LastCheck   time.Time    `json:"lastCheck,omitempty"`
	Info        *ReleaseInfo `json:"info,omitempty"`
	HighestSeen string       `json:"highestSeen,omitempty"`
	// Note: Channel field is not present in v1.4 settings. It is added by v1.5+.
	// v1.4 settings files will not have this field and will be handled gracefully.
	Channel string `json:"channel,omitempty"`
}

// Manager owns the update lifecycle's state machine and enforces its safety
// rules in one place: never more than one network check per checkInterval
// unless forced, never download without an explicit call, never reach
// StatusReady unless both files on disk actually hashed to what the signed
// manifest promised, never install without a separate explicit call, and
// never move Status to Installing until the updater process has actually
// started (see MarkInstalling).
type Manager struct {
	currentVersion string
	channel        ChannelConfig
	apiBase        string
	userAgent      string
	downloadDir    string
	settingsPath   string
	httpClient     *http.Client

	mu          sync.Mutex
	status      Status
	info        *ReleaseInfo
	downloaded  int64
	total       int64
	installPath string
	updaterPath string
	autoCheck   bool
	lastCheck   time.Time
	lastErr     error
	highestSeen string
	cancel      context.CancelFunc
}

// NewManager builds a Manager for the given installed version, downloading
// verified updates into downloadDir (a caller-owned scratch directory —
// internal/api passes paths.Sub("updates")) and persisting its auto-check
// toggle, last-check time, and replay protection state at settingsPath
// (paths.Sub("update-settings.json")). AutoCheck defaults to on when no
// settings file exists yet — see SetAutoCheck's doc comment for the
// disclosure that default requires.
func NewManager(currentVersion, downloadDir, settingsPath string) *Manager {
	m, _ := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: currentVersion,
		DownloadDir:    downloadDir,
		SettingsPath:   settingsPath,
		Channel:        DefaultStableChannelConfig(),
	})
	return m
}

// NewManagerWithConfig builds a Manager with explicit configuration.
// This allows v1.5+ to use a configurable update channel while maintaining
// backward compatibility with v1.4's hardcoded defaults.
func NewManagerWithConfig(config UpdateConfig) (*Manager, error) {
	if config.HTTPClient == nil {
		config.HTTPClient = newHTTPClient()
	}
	if config.Channel.Name == "" {
		config.Channel = DefaultStableChannelConfig()
	}
	if config.Channel.APIBase == "" {
		config.Channel.APIBase = githubAPIBase
	}
	if config.UserAgent == "" {
		config.UserAgent = "TRAZIP/" + config.CurrentVersion
	}

	// Normalize and validate the channel configuration before creating the manager
	normalizedChannel, err := normalizeChannelConfig(config.Channel)
	if err != nil {
		return nil, fmt.Errorf("invalid channel configuration: %w", err)
	}

	m := &Manager{
		currentVersion: config.CurrentVersion,
		channel:        normalizedChannel,
		apiBase:        normalizedChannel.APIBase,
		userAgent:      config.UserAgent,
		downloadDir:    config.DownloadDir,
		settingsPath:   config.SettingsPath,
		httpClient:     config.HTTPClient,
		status:         StatusIdle,
		autoCheck:      true,
		highestSeen:    config.CurrentVersion,
	}
	if s, err := loadSettings(config.SettingsPath); err == nil {
		m.autoCheck = s.AutoCheck
		// Preserve highestSeen from settings if it's greater than current,
		// OR if we're migrating from a legacy channel (preserve replay protection state).
		preserveHighestSeen := false
		if cmp, err := compareVersions(s.HighestSeen, m.highestSeen); err == nil && cmp > 0 {
			preserveHighestSeen = true
		}
		// Do NOT preserve highestSeen if it's lower than currentVersion —
		// the floor must never be lowered (replay protection invariant).
		if preserveHighestSeen {
			m.highestSeen = s.HighestSeen
		}
		// Only trust a cached result written for the version currently
		// installed — if TRAZIP was updated since, a stale "0.7.4 is
		// available" would wrongly re-offer the version already running.
		if s.Info != nil && s.Info.CurrentVersion == config.CurrentVersion {
			m.lastCheck = s.LastCheck
			m.info = s.Info
		}
		// If the persisted channel differs from the current one (e.g., v1.4
		// settings loaded by v1.5), migrate the channel. v1.4 settings have
		// no Channel field, so s.Channel will be empty — no migration needed.
		// If a future version adds a channel field, this logic will handle it.
	}
	return m, nil
}

// ChannelConfig returns the current channel configuration.
func (m *Manager) ChannelConfig() ChannelConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.channel
}

// AutoCheck reports the user's current preference for automatic
// startup/background update checks.
func (m *Manager) AutoCheck() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.autoCheck
}

// SetAutoCheck persists the user's choice for whether TRAZIP may check the
// distribution channel automatically. An update check is itself a network
// call — it must never happen silently without this being a visible,
// user-controlled setting (Settings → Actualizaciones), even though the
// check alone sends nothing about the user, the capture, or the network
// being analyzed.
func (m *Manager) SetAutoCheck(enabled bool) error {
	m.mu.Lock()
	m.autoCheck = enabled
	s := m.settingsLocked()
	m.mu.Unlock()
	return saveSettings(m.settingsPath, s)
}

// settingsLocked snapshots persisted state — caller must hold m.mu.
func (m *Manager) settingsLocked() settings {
	return settings{
		AutoCheck:   m.autoCheck,
		LastCheck:   m.lastCheck,
		Info:        m.info,
		HighestSeen: m.highestSeen,
		Channel:     m.channel.Name,
	}
}

// StartAuto performs at most one background check per 24 hours (see
// checkInterval), and only while the user has left auto-check enabled.
// Safe to call unconditionally at startup — it's Check's own persisted
// lastCheck and AutoCheck's own persisted flag that decide whether
// anything actually happens, not the caller.
func (m *Manager) StartAuto(ctx context.Context) {
	go func() {
		m.autoCheckOnce(ctx)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.autoCheckOnce(ctx)
			}
		}
	}()
}

func (m *Manager) autoCheckOnce(ctx context.Context) {
	if !m.AutoCheck() {
		return
	}
	_, _ = m.Check(ctx, false)
}

func loadSettings(path string) (settings, error) {
	var s settings
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return settings{}, err
	}
	return s, nil
}

func saveSettings(path string, s settings) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-settings-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Snapshot returns Manager's entire externally visible state at one
// instant — what the GUI polls.
func (m *Manager) Snapshot() StatusSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := StatusSnapshot{
		Status: m.status, Downloaded: m.downloaded, Total: m.total,
		InstallPath: m.installPath, UpdaterPath: m.updaterPath, LastCheck: m.lastCheck,
	}
	if m.info != nil {
		info := *m.info
		snap.Info = &info
	}
	if m.lastErr != nil {
		snap.Error = m.lastErr.Error()
	}
	return snap
}

// Check queries the distribution channel, skipping the network call
// entirely if the last check succeeded within checkInterval — unless force
// is true. Network failures (no internet, GitHub down, timeout, repository
// not created yet) return an error but leave Status at Idle, never Error:
// a routine check failing is not the same as a verified update failing,
// and must never greet the user with an alarming state on ordinary startup
// — see internal/api's caller for why this matters.
func (m *Manager) Check(ctx context.Context, force bool) (ReleaseInfo, error) {
	m.mu.Lock()
	if !force && !m.lastCheck.IsZero() && time.Since(m.lastCheck) < checkInterval && m.info != nil {
		info := *m.info
		m.mu.Unlock()
		return info, nil
	}
	m.status = StatusChecking
	m.mu.Unlock()

	info, err := checkRelease(ctx, m.httpClient, m.apiBase, m.channel.Repository, m.currentVersion, m.userAgent)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastCheck = time.Now()
	if err != nil {
		m.status = StatusIdle
		m.lastErr = err
		// Best-effort: a failed persist here must not turn a routine
		// network hiccup into a reported Check failure.
		_ = saveSettings(m.settingsPath, m.settingsLocked())
		return ReleaseInfo{}, err
	}

	// Replay protection: a signed manifest is authentic (it verified), but
	// authenticity alone doesn't rule out a network attacker replaying an
	// OLDER signed release than one this exact installation already
	// observed — e.g. current=0.7.4, this client already saw a genuine
	// 0.7.6 manifest, and a replay now serves a genuine-but-stale 0.7.5.
	// 0.7.5 > current, so the ordinary downgrade check wouldn't catch it;
	// comparing against the highest version ever actually seen does.
	if info.Available {
		if cmp, cErr := compareVersions(info.LatestVersion, m.highestSeen); cErr == nil {
			if cmp < 0 {
				m.status = StatusIdle
				m.lastErr = fmt.Errorf("release %s is older than a previously observed signed release %s — refusing as a possible replay", info.LatestVersion, m.highestSeen)
				_ = saveSettings(m.settingsPath, m.settingsLocked())
				return ReleaseInfo{}, m.lastErr
			}
			if cmp > 0 {
				m.highestSeen = info.LatestVersion
			}
		}
	}

	m.lastErr = nil
	m.info = &info
	if info.Available {
		m.status = StatusAvailable
	} else {
		m.status = StatusIdle
	}
	_ = saveSettings(m.settingsPath, m.settingsLocked())
	return info, nil
}

// Download fetches and verifies BOTH the update asset and its matching
// trazip-updater.exe from the last successful Check. Requires
// Status == Available; reaches StatusReady only after both downloaded
// files have been independently re-hashed and matched against the signed
// manifest's SHA-256 — "the HTTP request succeeded" is never treated as
// "safe to install", and a standalone install can't assume any updater
// already exists on disk, so both must come from the verified download.
func (m *Manager) Download(ctx context.Context) error {
	m.mu.Lock()
	if m.status != StatusAvailable || m.info == nil {
		status := m.status
		m.mu.Unlock()
		return fmt.Errorf("no update available to download (status=%s)", status)
	}
	info := *m.info
	dctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.status = StatusDownloading
	m.downloaded, m.total = 0, info.Asset.Size+info.UpdaterAsset.Size
	m.mu.Unlock()

	appPath, err := m.downloadAndVerify(dctx, info.Asset)
	if err != nil {
		return m.downloadFailed(err)
	}
	updaterPath, err := m.downloadAndVerify(dctx, info.UpdaterAsset)
	if err != nil {
		os.Remove(appPath)
		return m.downloadFailed(err)
	}

	m.mu.Lock()
	m.status = StatusReady
	m.installPath = appPath
	m.updaterPath = updaterPath
	m.lastErr = nil
	m.mu.Unlock()
	return nil
}

// downloadAndVerify downloads one asset (progress accumulated across both
// app+updater into the Manager's single Downloaded/Total pair, since the
// GUI shows one combined progress bar) and independently re-verifies its
// hash before returning the final path.
func (m *Manager) downloadAndVerify(ctx context.Context, asset Asset) (string, error) {
	m.mu.Lock()
	client := m.httpClient
	downloadDir := m.downloadDir
	baseDownloaded := m.downloaded
	total := m.total
	m.mu.Unlock()

	partialPath, err := downloadAsset(ctx, client, asset.URL, downloadDir, asset.Name, asset.Size,
		func(downloaded, _ int64) {
			m.mu.Lock()
			m.downloaded = baseDownloaded + downloaded
			m.total = total
			m.mu.Unlock()
		})
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	m.status = StatusVerifying
	m.mu.Unlock()

	if err := verifyFileSHA256(partialPath, asset.SHA256); err != nil {
		os.Remove(partialPath)
		return "", err
	}

	finalPath := filepath.Join(m.downloadDir, asset.Name)
	os.Remove(finalPath) // clear any stale leftover from a previous attempt before the rename
	if err := os.Rename(partialPath, finalPath); err != nil {
		os.Remove(partialPath)
		return "", err
	}
	return finalPath, nil
}

// downloadFailed resets to the retryable Available state. A deliberate
// user cancellation (Cancel) is not an error worth showing — only a real
// failure (network, hash mismatch, disk) leaves a message behind for the
// UI, so Settings can distinguish "you cancelled" from "this actually
// failed and here's why", per the audit's explicit requirement.
func (m *Manager) downloadFailed(err error) error {
	m.mu.Lock()
	m.cancel = nil
	m.status = StatusAvailable
	if errors.Is(err, context.Canceled) {
		m.lastErr = nil
	} else {
		m.lastErr = err
	}
	m.mu.Unlock()
	return err
}

// Cancel aborts an in-flight Download. A no-op if nothing is downloading.
func (m *Manager) Cancel() {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// UpdaterArgs are the exact, LOCALLY-constructed arguments TRAZIP passes to
// cmd/trazip-updater to perform the actual file replacement — see that
// command's own doc comment for why this happens out-of-process. Every
// field here comes from a value TRAZIP itself already trusts (the verified
// download path, its own running executable's path); nothing is copied
// from a remote server, so the updater never needs to parse or trust
// anything network-sourced itself.
type UpdaterArgs struct {
	PID            int
	Source         string // the verified, downloaded new executable
	Final          string // where the running app should be after the update
	Cleanup        string // optional: a stale file to remove after success ("" = none)
	ExpectedSHA256 string
	UpdaterPath    string // the verified, downloaded trazip-updater.exe to spawn
}

// PrepareInstall returns the updater invocation once Download has reached
// StatusReady. It does NOT change Status — see MarkInstalling, which the
// caller invokes only after actually spawning the updater process
// successfully, so a helper that fails to start leaves Status at Ready
// (retryable) instead of stuck at Installing. currentExePath is the
// running process's own os.Executable() result. portable distinguishes
// the two replacement strategies (see cmd/trazip-updater's doc comment):
//
//   - portable (or any fixed-name install): the running exe's own path IS
//     the permanent location — replace it in place.
//   - standalone: never silently rewrite a file the user downloaded under
//     one version's name to secretly contain another version. Place the
//     new, correctly-named exe next to the old one and launch that
//     instead, then clean up the old one.
func (m *Manager) PrepareInstall(currentExePath string, portable bool) (UpdaterArgs, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != StatusReady || m.info == nil {
		return UpdaterArgs{}, fmt.Errorf("no verified update ready to install (status=%s)", m.status)
	}
	args := UpdaterArgs{
		PID:            os.Getpid(),
		Source:         m.installPath,
		ExpectedSHA256: m.info.Asset.SHA256,
		UpdaterPath:    m.updaterPath,
	}
	if portable {
		args.Final = currentExePath
	} else {
		args.Final = filepath.Join(filepath.Dir(currentExePath), m.info.Asset.Name)
		if filepath.Clean(args.Final) != filepath.Clean(currentExePath) {
			args.Cleanup = currentExePath
		}
	}
	return args, nil
}

// MarkInstalling transitions Status to Installing. Call only after the
// updater process spawned by PrepareInstall's result has actually started
// successfully (cmd.Start() returned nil) — never before, so a failure to
// even launch the helper leaves Status at Ready (retryable) instead of
// stuck at Installing.
func (m *Manager) MarkInstalling() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == StatusReady {
		m.status = StatusInstalling
	}
}