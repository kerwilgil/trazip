// Package connmon lists the local machine's own active TCP/UDP sockets and,
// where the platform allows it, which process owns each one (prompt maestro
// module "Conexiones" — not in the original §9 list, added at Kerwil's
// request). This is entirely passive: it reads OS-provided socket tables, it
// never sends a packet, so unlike Scanner/LAN Scan/Capture it needs no Scope
// Guard target authorization.
package connmon

// Connection is one local socket, with its owning process when resolvable.
// PID/Process are best-effort: on Linux a socket owned by another user's
// process resolves to PID 0 / empty name (no permission to read its /proc
// entry) rather than failing the whole snapshot.
type Connection struct {
	Proto      string `json:"proto"` // tcp | udp
	LocalAddr  string `json:"localAddr"`
	LocalPort  int    `json:"localPort"`
	RemoteAddr string `json:"remoteAddr"`
	RemotePort int    `json:"remotePort"`
	State      string `json:"state,omitempty"` // TCP only (established, listen, ...)
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
}
