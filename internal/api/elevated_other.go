//go:build !windows

package api

import "os"

// detectElevated reports whether the process runs as root (uid 0) on Unix-like
// systems. macOS live capture generally requires this.
func detectElevated() bool {
	return os.Geteuid() == 0
}
