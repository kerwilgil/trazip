//go:build windows

package webintel

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// WSAECONNREFUSED is the typed Winsock error returned for a refused TCP
// connect. errors.Is preserves support for url.Error/net.OpError wrapping.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}
