// Package capture implements live packet capture (prompt maestro §9 Fase 2 #9).
// On Windows it binds Npcap's wpcap.dll dynamically at runtime (no cgo, keeping
// the build pure-Go) and degrades clearly when Npcap is absent. Packet decoding
// reuses internal/packet so live and PCAP views look identical.
package capture

// Device is a capturable network interface.
type Device struct {
	Name        string `json:"name"`        // OS device path (e.g. \Device\NPF_{GUID})
	Description string `json:"description"` // human-friendly name
}
