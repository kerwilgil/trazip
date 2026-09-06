//go:build !windows && !darwin

package wifi

import "fmt"

// Available reports WiFi scan support. Not implemented on this build (the
// WLAN API interop is Windows-specific).
func Available() bool { return false }

// Scan is unsupported on this build.
func Scan() ([]Network, error) {
	return nil, fmt.Errorf("escaneo de redes WiFi no disponible en esta build")
}

// Status is unsupported on this build (returns no interfaces, no error, so
// the UI simply omits the WiFi-connectivity hint).
func Status() ([]IfaceStatus, error) {
	return nil, nil
}
