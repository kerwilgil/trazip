//go:build windows

package portscan

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Windows reports a refused TCP connect as WSAECONNREFUSED (10061), not the
// POSIX ECONNREFUSED value. errors.Is walks net.OpError and os.SyscallError
// wrappers without depending on the localized Winsock message.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}
