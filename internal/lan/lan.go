// Package lan implements the LAN Explorer (prompt maestro §9 Fase 2 #11). It
// enumerates local interfaces and reads the system neighbor (ARP/NDP) table — a
// passive discovery that never sends ARP or spoofs, per the security scope (§3).
package lan

import (
	"net"
	"sort"
)

// Interface is a local network interface.
type NetworkInterface struct {
	Name     string   `json:"name"`
	MAC      string   `json:"mac,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	Addrs    []string `json:"addrs"`
	Up       bool     `json:"up"`
	Loopback bool     `json:"loopback"`
	MTU      int      `json:"mtu"`
}

// Neighbor is an entry from the system ARP/NDP table.
type Neighbor struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor,omitempty"`
	Type   string `json:"type,omitempty"` // dynamic | static | other
}

// Report bundles the LAN discovery result.
type Report struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	Neighbors  []Neighbor         `json:"neighbors"`
	Note       string             `json:"note,omitempty"`
}

// Interfaces enumerates local interfaces (cross-platform via the stdlib).
func Interfaces() []NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]NetworkInterface, 0, len(ifaces))
	for _, ifi := range ifaces {
		it := NetworkInterface{
			Name:     ifi.Name,
			MTU:      ifi.MTU,
			Up:       ifi.Flags&net.FlagUp != 0,
			Loopback: ifi.Flags&net.FlagLoopback != 0,
		}
		if len(ifi.HardwareAddr) > 0 {
			it.MAC = ifi.HardwareAddr.String()
			it.Vendor = Vendor(it.MAC)
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			it.Addrs = append(it.Addrs, a.String())
		}
		out = append(out, it)
	}
	return out
}

// Discover builds the full LAN report: interfaces plus the system neighbor table.
func Discover() Report {
	r := Report{Interfaces: Interfaces()}
	nb, note := neighbors()
	for i := range nb {
		nb[i].Vendor = Vendor(nb[i].MAC)
	}
	sort.SliceStable(nb, func(i, j int) bool { return less(nb[i].IP, nb[j].IP) })
	r.Neighbors = nb
	r.Note = note
	return r
}

// less orders IPs numerically when possible, else lexically.
func less(a, b string) bool {
	ai, aok := net.ParseIP(a), true
	bi, bok := net.ParseIP(b), true
	_ = aok
	_ = bok
	if ai != nil && bi != nil {
		a4, b4 := ai.To4(), bi.To4()
		if a4 != nil && b4 != nil {
			for k := 0; k < 4; k++ {
				if a4[k] != b4[k] {
					return a4[k] < b4[k]
				}
			}
			return false
		}
	}
	return a < b
}
