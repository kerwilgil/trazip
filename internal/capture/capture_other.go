//go:build !windows && !darwin

package capture

import (
	"context"
	"fmt"

	"trazip/internal/packet"
)

// Available reports capture support. The pure-Go build has no live capture on
// Unix yet (would need libpcap/cgo or AF_PACKET); PCAP file analysis still works.
func Available() bool { return false }

// Devices is unsupported on this build.
func Devices() ([]Device, error) {
	return nil, fmt.Errorf("captura en vivo no disponible en esta build (usa análisis de PCAP)")
}

// Capture is unsupported on this build.
func Capture(_ context.Context, _ string, _ int, _, _ bool, _ func(packet.Summary)) error {
	return fmt.Errorf("captura en vivo no disponible en esta build")
}

// CaptureRaw is unsupported on this build.
func CaptureRaw(_ context.Context, _ string, _ int, _ bool, _ func(data []byte)) error {
	return fmt.Errorf("captura en vivo no disponible en esta build")
}
