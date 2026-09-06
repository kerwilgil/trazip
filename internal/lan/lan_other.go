//go:build !windows && !darwin

package lan

import (
	"bufio"
	"os"
	"strings"
)

// neighbors reads the ARP table on Linux from /proc/net/arp. On systems without
// it (e.g. macOS) it returns an empty set with a note; a native reader can be
// added later.
func neighbors() ([]Neighbor, string) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, "lectura de tabla ARP no disponible en esta plataforma (pendiente)"
	}
	defer f.Close()

	var out []Neighbor
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		flags := fields[2]
		mac := fields[3]
		if flags == "0x0" || mac == "00:00:00:00:00:00" {
			continue // incomplete entry
		}
		out = append(out, Neighbor{IP: ip, MAC: mac, Type: "dynamic"})
	}
	return out, ""
}
