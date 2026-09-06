// Package paths resolves where TRAZIP keeps its per-user data (config,
// monitor history, VoIP quality history, lab runs, GeoLite2 datasets).
//
// Two modes:
//
//   - Installed/default: os.UserConfigDir()/TRAZIP — survives moving the exe,
//     one store per Windows user. This is what an installed copy wants.
//   - Portable: if a file named "portable.txt" sits next to the executable,
//     everything lives in "<exe dir>/data" instead. Nothing is written
//     outside that folder, so the whole tool + its state travels on a USB
//     stick and leaves no trace on a borrowed machine — the field-use case.
//
// The portable check is done once at process start (the exe doesn't move
// while running) and cached.
package paths

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	once                 sync.Once
	root                 string
	datasetMigrationOnce sync.Once
)

// Root returns the base directory for all persistent TRAZIP data, creating
// nothing itself — callers MkdirAll their own subdirectory as before.
func Root() string {
	once.Do(func() { root = resolveRoot() })
	return root
}

// Sub returns Root() joined with the given subdirectory names.
func Sub(elem ...string) string {
	return filepath.Join(append([]string{Root()}, elem...)...)
}

// DatasetDir is the one writable dataset directory shared by GeoLite2 and
// the opt-in offline feeds. In installed mode it is per-user; in portable
// mode Root keeps it beside the executable under data/.
func DatasetDir() string {
	dir := datasetDir(Root())
	datasetMigrationOnce.Do(func() { migrateLegacyDatasetFiles(dir, legacyDatasetDirs()) })
	return dir
}

func datasetDir(root string) string { return filepath.Join(root, "geolite") }

// Portable reports whether TRAZIP is running in portable mode (a
// "portable.txt" marker sits next to the executable).
func Portable() bool {
	dir, ok := portableDataDir()
	return ok && dir != ""
}

func resolveRoot() string {
	if dir, ok := portableDataDir(); ok {
		return dir
	}
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
			configDir = filepath.Join(home, ".config")
		} else {
			configDir = filepath.Join(os.TempDir(), "TRAZIP-user")
		}
	}
	return filepath.Join(configDir, "TRAZIP")
}

// portableDataDir returns "<exe dir>/data" when a portable.txt marker exists
// next to the executable.
func portableDataDir() (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	exeDir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(exeDir, "portable.txt")); err != nil {
		return "", false
	}
	return filepath.Join(exeDir, "data"), true
}

var legacyDatasetFiles = []string{
	"GeoLite2-City.mmdb",
	"GeoLite2-ASN.mmdb",
	"netclass.json",
	"threatfeed.json",
	"oui.json",
}

// legacyDatasetDirs lists former data locations only for a one-way,
// best-effort copy into DatasetDir. Portable mode never looks outside its
// own folder; installed mode may recover the old executable- or CWD-relative
// layout without ever continuing to write there.
func legacyDatasetDirs() []string {
	if Portable() {
		return []string{Root()}
	}
	dirs := make([]string, 0, 2)
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "data"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "data"))
	}
	return dirs
}

func migrateLegacyDatasetFiles(target string, sources []string) {
	for _, sourceDir := range sources {
		if filepath.Clean(sourceDir) == filepath.Clean(target) {
			continue
		}
		for _, name := range legacyDatasetFiles {
			copyLegacyDatasetFile(filepath.Join(sourceDir, name), filepath.Join(target, name))
		}
	}
}

// copyLegacyDatasetFile never overwrites or removes the source. A failed copy
// leaves the canonical path untouched so users can redownload cleanly.
func copyLegacyDatasetFile(source, target string) {
	if _, err := os.Stat(target); err == nil {
		return
	}
	in, err := os.Open(source)
	if err != nil {
		return
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".trazip-legacy-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpName, target)
}
