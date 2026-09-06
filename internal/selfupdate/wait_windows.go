//go:build windows

package selfupdate

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// WaitForExit blocks until pid exits or timeout elapses. If the process is
// already gone (or the PID never existed — OpenProcess fails), it returns
// immediately with no error: there is nothing left to wait for.
func WaitForExit(pid int, timeout time.Duration) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	event, err := windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
	if err != nil {
		return fmt.Errorf("waiting on process handle: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("timed out after %s", timeout)
	}
	return nil
}
