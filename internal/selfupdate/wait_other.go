//go:build !windows

package selfupdate

import "time"

// WaitForExit is a no-op outside Windows — TRAZIP only ships a Windows
// build; this fallback exists solely so the package compiles during this
// repo's cross-platform `go build ./...` validation.
func WaitForExit(pid int, timeout time.Duration) error {
	return nil
}
