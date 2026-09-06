package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveRootInstalled verifies the default (no marker) path lands under
// the user config dir, not next to the exe.
func TestResolveRootInstalled(t *testing.T) {
	// resolveRoot reads os.Executable()/portable.txt; in the test binary that
	// marker won't exist, so it must fall back to the config-dir layout.
	got := resolveRoot()
	cfg, err := os.UserConfigDir()
	if err == nil && cfg != "" {
		want := filepath.Join(cfg, "TRAZIP")
		if got != want {
			t.Fatalf("resolveRoot() = %q, want %q", got, want)
		}
	}
}

func TestDatasetDirInstalledIsUnderUserRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "TRAZIP")
	got := datasetDir(root)
	want := filepath.Join(root, "geolite")
	if got != want {
		t.Fatalf("datasetDir() = %q, want %q", got, want)
	}
	if got == "data" || !filepath.IsAbs(got) {
		t.Fatalf("installed dataset dir must be an absolute per-user path, got %q", got)
	}
	if err := os.MkdirAll(got, 0o700); err != nil {
		t.Fatalf("creating canonical dataset dir: %v", err)
	}
}

// TestPortableDataDirDetectsMarker verifies the marker check keys off a
// portable.txt sitting next to the executable.
func TestPortableDataDirDetectsMarker(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("os.Executable unavailable")
	}
	marker := filepath.Join(filepath.Dir(exe), "portable.txt")
	if _, err := os.Stat(marker); err == nil {
		t.Skip("a real portable.txt exists next to the test binary; skipping")
	}
	if err := os.WriteFile(marker, []byte("portable"), 0o644); err != nil {
		t.Skipf("cannot write marker next to test binary: %v", err)
	}
	defer os.Remove(marker)

	dir, ok := portableDataDir()
	if !ok {
		t.Fatal("portableDataDir() did not detect the marker")
	}
	want := filepath.Join(filepath.Dir(exe), "data")
	if dir != want {
		t.Fatalf("portableDataDir() = %q, want %q", dir, want)
	}
	if got := datasetDir(dir); got != filepath.Join(filepath.Dir(exe), "data", "geolite") {
		t.Fatalf("portable datasetDir = %q", got)
	}
}

func TestLegacyMigrationCopiesWithoutOverwriting(t *testing.T) {
	legacy := t.TempDir()
	target := filepath.Join(t.TempDir(), "TRAZIP", "geolite")
	if err := os.WriteFile(filepath.Join(legacy, "oui.json"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrateLegacyDatasetFiles(target, []string{legacy})
	got, err := os.ReadFile(filepath.Join(target, "oui.json"))
	if err != nil || string(got) != "legacy" {
		t.Fatalf("migrated file = %q, err = %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(target, "oui.json"), []byte("canonical"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrateLegacyDatasetFiles(target, []string{legacy})
	got, err = os.ReadFile(filepath.Join(target, "oui.json"))
	if err != nil || string(got) != "canonical" {
		t.Fatalf("canonical file was overwritten: %q, err = %v", got, err)
	}
}
