package geoip

import (
	"path/filepath"
	"testing"

	"trazip/internal/paths"
)

func TestFindDataDirUsesCanonicalPathsDatasetDir(t *testing.T) {
	got := FindDataDir()
	want := paths.DatasetDir()
	if got != want {
		t.Fatalf("FindDataDir() = %q, want %q", got, want)
	}
	if got == "data" || !filepath.IsAbs(got) {
		t.Fatalf("FindDataDir must never return a relative data fallback: %q", got)
	}
}
