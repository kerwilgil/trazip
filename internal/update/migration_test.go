package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			Name:       "stable",
			Repository: "kerwilgil/trazip",
			APIBase:    "https://api.github.com",
		},
	})

	if m.ChannelConfig().Name != "stable" {
		t.Errorf("ChannelConfig().Name = %q, want stable", m.ChannelConfig().Name)
	}
	if m.ChannelConfig().Repository != "kerwilgil/trazip" {
		t.Errorf("ChannelConfig().Repository = %q, want kerwilgil/trazip", m.ChannelConfig().Repository)
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
		t.Errorf("ChannelConfig().Name = %q, want %q", m.ChannelConfig().Name, stableChannel)
	}
	if m.ChannelConfig().Repository != DefaultRepo {
		t.Errorf("ChannelConfig().Repository = %q, want %q", m.ChannelConfig().Repository, DefaultRepo)
	}
}

func TestManager_MigrateChannel_LegacyToStable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Test requires Windows for asset selection")
	}

	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	// Create a settings file with legacy channel (simulating v1.4 settings)
	legacySettings := settings{
		AutoCheck:   true,
		Channel:     "legacy",
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

	// Create a new manager with v1.5 config — should migrate the channel
	m := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "1.5.0",
		DownloadDir:    t.TempDir(),
		SettingsPath:   settingsPath,
		Channel: ChannelConfig{
			Name:       "stable",
			Repository: "kerwilgil/trazip",
		},
	})

	if m.ChannelConfig().Name != "stable" {
		t.Errorf("ChannelConfig().Name = %q, want stable", m.ChannelConfig().Name)
	}
	// HighestSeen should be preserved
	if m.highestSeen != "1.4.0" {
		t.Errorf("highestSeen = %q, want 1.4.0", m.highestSeen)
	}
}

func TestValidateManifest_AcceptsLegacyChannel(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("Test requires Windows for asset selection")
	}

	m := Manifest{
		Version:     "1.5.0",
		Channel:     "legacy", // legacy channel should be accepted for backward compatibility
		PublishedAt: time.Now(),
		Windows: map[string]PlatformAssets{
			"amd64": {
				App:     ManifestAsset{Asset: expectedAppAssetName("1.5.0"), SHA256: sha256Hex([]byte("app-bytes")), Size: 8},
				Updater: ManifestAsset{Asset: updaterAssetName, SHA256: sha256Hex([]byte("updater-bytes")), Size: 13},
			},
		},
	}

	app, updater, err := validateManifest(&m, "amd64")
	if err != nil {
		t.Fatalf("validateManifest with legacy channel: %v", err)
	}
	if app.Asset != "TRAZIP-1.5.0.exe" {
		t.Errorf("app asset = %q, want TRAZIP-1.5.0.exe", app.Asset)
	}
	if updater.Asset != updaterAssetName {
		t.Errorf("updater asset = %q, want %q", updater.Asset, updaterAssetName)
	}
}

func TestValidateManifest_RejectsUnknownChannel(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("Test requires windows/amd64 for asset selection")
	}

	m := Manifest{
		Version:     "1.5.0",
		Channel:     "unknown-channel", // should be rejected
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
	if !strings.Contains(err.Error(), "unknown-channel") {
		t.Errorf("error = %q, want error mentioning unknown channel", err.Error())
	}
}

func TestValidateNotesURL_AcceptsNewRepository(t *testing.T) {
	// Test that notesUrl validation accepts both legacy and new repository URLs
	legacyURL := "https://github.com/kerwilgil/trazip-releases/releases/tag/v1.5.0"
	newURL := "https://github.com/kerwilgil/trazip/releases/tag/v1.5.0"
	invalidURL := "https://evil.example.com/notes"

	if err := validateNotesURL(legacyURL); err != nil {
		t.Errorf("validateNotesURL rejected legacy URL: %v", err)
	}
	if err := validateNotesURL(newURL); err != nil {
		t.Errorf("validateNotesURL rejected new URL: %v", err)
	}
	if err := validateNotesURL(invalidURL); err == nil {
		t.Error("validateNotesURL accepted invalid URL")
	}
}

func TestChannelConfigForLegacy(t *testing.T) {
	cfg := ChannelConfigForLegacy()
	if cfg.Name != "legacy" {
		t.Errorf("ChannelConfigForLegacy().Name = %q, want legacy", cfg.Name)
	}
	if cfg.Repository != DefaultRepo {
		t.Errorf("ChannelConfigForLegacy().Repository = %q, want %q", cfg.Repository, DefaultRepo)
	}
}

func TestDefaultStableChannelConfig(t *testing.T) {
	cfg := DefaultStableChannelConfig()
	if cfg.Name != stableChannel {
		t.Errorf("DefaultStableChannelConfig().Name = %q, want %q", cfg.Name, stableChannel)
	}
	if cfg.Repository != DefaultRepo {
		t.Errorf("DefaultStableChannelConfig().Repository = %q, want %q", cfg.Repository, DefaultRepo)
	}
	if cfg.APIBase != githubAPIBase {
		t.Errorf("DefaultStableChannelConfig().APIBase = %q, want %q", cfg.APIBase, githubAPIBase)
	}
}

func TestChannelConfig_JSON_MarshalUnmarshal(t *testing.T) {
	cfg := ChannelConfig{
		Name:       "stable",
		Repository: "kerwilgil/trazip",
		APIBase:    "https://api.github.com",
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

func TestMigrationManifest_JSON_MarshalUnmarshal(t *testing.T) {
	mm := MigrationManifest{
		SchemaVersion: 1,
		V1_5_Channel:  "kerwilgil/trazip",
		V1_5_Manifest: "https://github.com/kerwilgil/trazip/releases/download/v1.5.0/update.json",
		V1_5_PubKey:   "a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149",
		MinVersion:    "1.4.1",
	}

	data, err := json.Marshal(mm)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var mm2 MigrationManifest
	if err := json.Unmarshal(data, &mm2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if mm2.V1_5_Channel != mm.V1_5_Channel || mm2.V1_5_Manifest != mm.V1_5_Manifest || mm2.V1_5_PubKey != mm.V1_5_PubKey || mm2.MinVersion != mm.MinVersion {
		t.Errorf("JSON round-trip failed: got %+v, want %+v", mm2, mm)
	}
}

func TestLoadMigrationManifest_Success(t *testing.T) {
	// Create a test server that serves the migration.json
	migration := MigrationManifest{
		SchemaVersion: 1,
		V1_5_Channel:  "kerwilgil/trazip",
		V1_5_Manifest: "https://github.com/kerwilgil/trazip/releases/download/v1.5.0/update.json",
		V1_5_PubKey:   "a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149",
		MinVersion:    "1.4.1",
	}

	_, _ = json.Marshal(migration)

	mux := http.NewServeMux()
	// Migration manifest asset
	mux.HandleFunc("/assets/migration.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schemaVersion":1,"v1_5_channel":"kerwilgil/trazip","v1_5_manifest":"https://github.com/kerwilgil/trazip/releases/download/v1.5.0/update.json","v1_5_pubkey":"a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149","min_version":"1.4.1"}`))
	})
	// Legacy repository releases/latest endpoint - serves release with migration.json asset
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		release := map[string]interface{}{
			"tag_name": "v1.4.1-bridge",
			"assets": []map[string]string{
				{"name": "migration.json", "browser_download_url": ""},
			},
		}
		json.NewEncoder(w).Encode(release)
	})

srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// Create a combined server that serves the release with the correct migration URL
	combinedMux2 := http.NewServeMux()
	combinedMux2.HandleFunc("/assets/migration.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schemaVersion":1,"v1_5_channel":"kerwilgil/trazip","v1_5_manifest":"https://github.com/kerwilgil/trazip/releases/download/v1.5.0/update.json","v1_5_pubkey":"a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149","min_version":"1.4.1"}`))
	})
	combinedMux2.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		release := map[string]interface{}{
			"tag_name": "v1.4.1-bridge",
			"assets": []map[string]string{
				{"name": "migration.json", "browser_download_url": srv.URL + "/assets/migration.json"},
			},
		}
		json.NewEncoder(w).Encode(release)
	})

	combinedSrv := httptest.NewTLSServer(combinedMux2)
	defer combinedSrv.Close()

	client := newTestHTTPClient()
	ctx := context.Background()

	mm, err := LoadMigrationManifest(ctx, client, combinedSrv.URL, DefaultRepo)
	if err != nil {
		t.Fatalf("LoadMigrationManifest: %v", err)
	}

	if mm.V1_5_Channel != "kerwilgil/trazip" {
		t.Errorf("V1_5_Channel = %q, want kerwilgil/trazip", mm.V1_5_Channel)
	}
	if mm.V1_5_PubKey != "a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149" {
		t.Errorf("V1_5_PubKey mismatch")
	}
	if mm.MinVersion != "1.4.1" {
		t.Errorf("MinVersion = %q, want 1.4.1", mm.MinVersion)
	}
}

func TestLoadMigrationManifest_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		release := map[string]interface{}{
			"tag_name": "v1.4.1-bridge",
			"assets":  []map[string]string{}, // no migration.json
		}
		json.NewEncoder(w).Encode(release)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestHTTPClient()
	ctx := context.Background()

	_, err := LoadMigrationManifest(ctx, client, srv.URL, DefaultRepo)
	if err == nil {
		t.Error("expected error when migration.json not found")
	}
}