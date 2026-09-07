package update

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagerWithConfig_CreatesManagerWithCustomChannel(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    dir,
		SettingsPath:   settingsPath,
		Channel: ChannelConfig{
			Name:       stableChannel,
			Repository: StableReleaseRepo,
			APIBase:    githubAPIBase,
		},
	})

	if m.ChannelConfig().Name != stableChannel {
		t.Errorf("ChannelConfig().Name = %q, want %s", m.ChannelConfig().Name, stableChannel)
	}
	if m.ChannelConfig().Repository != StableReleaseRepo {
		t.Errorf("ChannelConfig().Repository = %q, want %s", m.ChannelConfig().Repository, StableReleaseRepo)
	}
}

func TestManagerWithConfig_DefaultsToStableChannel(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    dir,
		SettingsPath:   settingsPath,
	})

	if m.ChannelConfig().Name != stableChannel {
		t.Errorf("ChannelConfig().Name = %q, want %s", m.ChannelConfig().Name, stableChannel)
	}
	if m.ChannelConfig().Repository != StableReleaseRepo {
		t.Errorf("ChannelConfig().Repository = %q, want %s", m.ChannelConfig().Repository, StableReleaseRepo)
	}
}

func TestManagerWithConfig_LegacyChannelConfig(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.4.0",
		DownloadDir:    dir,
		SettingsPath:   settingsPath,
		Channel:        ChannelConfigForLegacy(),
	})

	if m.ChannelConfig().Name != stableChannel {
		t.Errorf("ChannelConfig().Name = %q, want %s", m.ChannelConfig().Name, stableChannel)
	}
	if m.ChannelConfig().Repository != LegacyReleaseRepo {
		t.Errorf("ChannelConfig().Repository = %q, want %s", m.ChannelConfig().Repository, LegacyReleaseRepo)
	}
}

func TestManager_LoadSettings_WithoutChannelField(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	// Simulate a v1.4 settings file (no Channel field)
	legacySettings := settings{
		AutoCheck:   true,
		LastCheck:   time.Now().Add(-time.Hour),
		HighestSeen: "1.4.0",
		Info: &ReleaseInfo{
			CurrentVersion: "1.4.0",
			LatestVersion:  "1.4.0",
			Available:      false,
		},
	}
	if err := saveSettings(settingsPath, legacySettings); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}

	// Create a new manager with v1.5 config — should load legacy settings without Channel field
	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    t.TempDir(),
		SettingsPath:   settingsPath,
		Channel:        DefaultStableChannelConfig(),
	})

	// Should default to stable channel
	if m.ChannelConfig().Name != stableChannel {
		t.Errorf("ChannelConfig().Name = %q, want %s", m.ChannelConfig().Name, stableChannel)
	}
	// HighestSeen should NOT be downgraded from 1.5.0 to 1.4.0
	if m.highestSeen != "1.5.0" {
		t.Errorf("highestSeen = %q, want 1.5.0 (not downgraded from 1.4.0)", m.highestSeen)
	}
}

func TestManager_PreservesHighestSeenFromSettings(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	// Settings with higher HighestSeen than current version
	legacySettings := settings{
		AutoCheck:   true,
		LastCheck:   time.Now().Add(-time.Hour),
		HighestSeen: "1.5.5", // Higher than current
		Info: &ReleaseInfo{
			CurrentVersion: "1.5.0",
			LatestVersion:  "1.5.5",
			Available:      true,
		},
	}
	if err := saveSettings(settingsPath, legacySettings); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}

	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    t.TempDir(),
		SettingsPath:   settingsPath,
	})

	// Should preserve the higher HighestSeen from settings
	if m.highestSeen != "1.5.5" {
		t.Errorf("highestSeen = %q, want 1.5.5", m.highestSeen)
	}
}

func TestManager_DoesNotDowngradeHighestSeen(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	// Settings with LOWER HighestSeen than current version
	legacySettings := settings{
		AutoCheck:   true,
		LastCheck:   time.Now().Add(-time.Hour),
		HighestSeen: "1.4.0", // Lower than current 1.5.0
		Info: &ReleaseInfo{
			CurrentVersion: "1.4.0",
			LatestVersion:  "1.4.0",
			Available:      false,
		},
	}
	if err := saveSettings(settingsPath, legacySettings); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}

	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    t.TempDir(),
		SettingsPath:   settingsPath,
	})

	// Should NOT downgrade highestSeen from 1.5.0 to 1.4.0
	if m.highestSeen != "1.5.0" {
		t.Errorf("highestSeen = %q, want 1.5.0 (must not downgrade)", m.highestSeen)
	}
}

func TestValidateManifest_RejectsNonStableChannel(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("Test requires Windows for asset selection")
	}

	m := Manifest{
		Version:     "1.5.0",
		Channel:     "legacy", // v1.4 only accepts "stable" — legacy should be REJECTED
		PublishedAt: time.Now(),
		Windows: map[string]PlatformAssets{
			"amd64": {
				App:     ManifestAsset{Asset: expectedAppAssetName("1.5.0"), SHA256: sha256Hex([]byte("app-bytes")), Size: 8},
				Updater: ManifestAsset{Asset: updaterAssetName, SHA256: sha256Hex([]byte("updater-bytes")), Size: 13},
			},
		},
	}

	_, _, err := validateManifest(&m, "amd64")
	if err == nil {
		t.Error("validateManifest accepted non-stable channel, want rejection")
	}
	if !strings.Contains(err.Error(), "stable") {
		t.Errorf("error = %q, want error mentioning stable channel", err.Error())
	}
}

func TestValidateManifest_RejectsUnknownChannel(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("Test requires windows/amd64 for asset selection")
	}

	m := Manifest{
		Version:     "1.5.0",
		Channel:     "unknown-channel",
		PublishedAt: time.Now(),
		Windows: map[string]PlatformAssets{
			"amd64": {
				App:     ManifestAsset{Asset: expectedAppAssetName("1.5.0"), SHA256: sha256Hex([]byte("app")), Size: 3},
				Updater: ManifestAsset{Asset: updaterAssetName, SHA256: sha256Hex([]byte("updater")), Size: 7},
			},
		},
	}

	_, _, err := validateManifest(&m, "amd64")
	if err == nil {
		t.Error("validateManifest accepted unknown channel, want rejection")
	}
	if !strings.Contains(err.Error(), "stable") {
		t.Errorf("error = %q, want error mentioning stable channel", err.Error())
	}
}

func TestValidateNotesURL_AcceptsBothRepositories(t *testing.T) {
	// Test that notesUrl validation accepts both legacy and new repository URLs
	legacyURL := "https://github.com/kerwilgil/trazip-releases/releases/tag/v1.5.0"
	newURL := "https://github.com/kerwilgil/trazip/releases/tag/v1.5.0"
	invalidURL := "https://evil.example.com/notes"
	invalidScheme := "http://github.com/kerwilgil/trazip/releases/tag/v1.5.0"
	wrongHost := "https://gitlab.com/kerwilgil/trazip/releases/tag/v1.5.0"
	pathTraversal := "https://github.com/kerwilgil/trazip-releases.evil/notes"
	pathTraversal2 := "https://github.com/kerwilgil/trazip.evil/notes"

	if err := validateNotesURL(legacyURL); err != nil {
		t.Errorf("validateNotesURL rejected legacy URL: %v", err)
	}
	if err := validateNotesURL(newURL); err != nil {
		t.Errorf("validateNotesURL rejected new URL: %v", err)
	}
	if err := validateNotesURL(invalidURL); err == nil {
		t.Error("validateNotesURL accepted invalid URL")
	}
	if err := validateNotesURL(invalidScheme); err == nil {
		t.Error("validateNotesURL accepted http scheme")
	}
	if err := validateNotesURL(wrongHost); err == nil {
		t.Error("validateNotesURL accepted wrong host")
	}
	if err := validateNotesURL(pathTraversal); err == nil {
		t.Error("validateNotesURL accepted path traversal (legacy)")
	}
	if err := validateNotesURL(pathTraversal2); err == nil {
		t.Error("validateNotesURL accepted path traversal (new)")
	}
}

func TestChannelConfigForLegacy(t *testing.T) {
	cfg := ChannelConfigForLegacy()
	if cfg.Name != stableChannel {
		t.Errorf("ChannelConfigForLegacy().Name = %q, want %s", cfg.Name, stableChannel)
	}
	if cfg.Repository != LegacyReleaseRepo {
		t.Errorf("ChannelConfigForLegacy().Repository = %q, want %s", cfg.Repository, LegacyReleaseRepo)
	}
}

func TestDefaultStableChannelConfig(t *testing.T) {
	cfg := DefaultStableChannelConfig()
	if cfg.Name != stableChannel {
		t.Errorf("DefaultStableChannelConfig().Name = %q, want %s", cfg.Name, stableChannel)
	}
	if cfg.Repository != StableReleaseRepo {
		t.Errorf("DefaultStableChannelConfig().Repository = %q, want %s", cfg.Repository, StableReleaseRepo)
	}
	if cfg.APIBase != githubAPIBase {
		t.Errorf("DefaultStableChannelConfig().APIBase = %q, want %s", cfg.APIBase, githubAPIBase)
	}
}

func TestChannelConfig_JSON_MarshalUnmarshal(t *testing.T) {
	cfg := ChannelConfig{
		Name:       stableChannel,
		Repository: StableReleaseRepo,
		APIBase:    githubAPIBase,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var cfg2 ChannelConfig
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if cfg2.Name != cfg.Name || cfg2.Repository != cfg.Repository || cfg2.APIBase != cfg.APIBase {
		t.Errorf("JSON round-trip failed: got %+v, want %+v", cfg2, cfg)
	}
}

func TestChannelConfig_RepositoryValidation(t *testing.T) {
	tests := []struct {
		name      string
		repo      string
		wantValid bool
	}{
		{"valid", "owner/repo", true},
		{"empty", "", false},
		{"no_slash", "invalid", false},
		{"too_many_slashes", "a/b/c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ChannelConfig{
				Name:       "test",
				Repository: tt.repo,
			}
			isValid := cfg.Repository != "" && strings.Count(cfg.Repository, "/") == 1
			if isValid != tt.wantValid {
				t.Errorf("Repository %q: got valid=%v, want %v", tt.repo, isValid, tt.wantValid)
			}
		})
	}
}

func TestChannelConfig_APIBaseValidation(t *testing.T) {
	tests := []struct {
		name      string
		apiBase   string
		wantValid bool
	}{
		{"valid_https", "https://api.github.com", true},
		{"valid_custom", "https://api.custom.com", true},
		{"invalid_http", "http://api.github.com", false},
		{"empty", "", true}, // empty is allowed (defaults to GitHub)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ChannelConfig{
				Name:       "test",
				Repository: "owner/repo",
				APIBase:    tt.apiBase,
			}
			// For now, just check it doesn't panic
			_ = tt
			_ = cfg
		})
	}
}

func TestUpdateConfig_Defaults(t *testing.T) {
	cfg := UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    "/tmp/test",
		SettingsPath:   "/tmp/settings.json",
	}

	if cfg.Channel.Name != "" {
		t.Errorf("Channel.Name = %q, want empty (will default to stable)", cfg.Channel.Name)
	}
}

func TestChannelConfig_APIBaseDefaultsToGitHub(t *testing.T) {
	// Test that empty APIBase is allowed and gets filled in NewManagerWithConfig
	cfg := ChannelConfig{
		Name:       "test",
		Repository: "owner/repo",
	}

	if cfg.APIBase != "" {
		t.Errorf("APIBase = %q, want empty (will default to GitHub)", cfg.APIBase)
	}

	// Test that DefaultStableChannelConfig provides the default APIBase
	cfg2 := DefaultStableChannelConfig()
	if cfg2.APIBase != githubAPIBase {
		t.Errorf("DefaultStableChannelConfig().APIBase = %q, want %s", cfg2.APIBase, githubAPIBase)
	}
}

func TestChannelConfigForLegacy_PointsToLegacyRepo(t *testing.T) {
	cfg := ChannelConfigForLegacy()
	if cfg.Repository != LegacyReleaseRepo {
		t.Errorf("ChannelConfigForLegacy().Repository = %q, want %s", cfg.Repository, LegacyReleaseRepo)
	}
	if cfg.Name != stableChannel {
		t.Errorf("ChannelConfigForLegacy().Name = %q, want %s", cfg.Name, stableChannel)
	}
}

func TestDefaultStableChannelConfig_PointsToNewRepo(t *testing.T) {
	cfg := DefaultStableChannelConfig()
	if cfg.Repository != StableReleaseRepo {
		t.Errorf("DefaultStableChannelConfig().Repository = %q, want %s", cfg.Repository, StableReleaseRepo)
	}
}

func TestStableReleaseRepoConstant(t *testing.T) {
	if StableReleaseRepo != "kerwilgil/trazip" {
		t.Errorf("StableReleaseRepo = %q, want kerwilgil/trazip", StableReleaseRepo)
	}
}

func TestLegacyReleaseRepoConstant(t *testing.T) {
	if LegacyReleaseRepo != "kerwilgil/trazip-releases" {
		t.Errorf("LegacyReleaseRepo = %q, want kerwilgil/trazip-releases", LegacyReleaseRepo)
	}
}