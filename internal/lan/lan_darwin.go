//go:build darwin

package lan

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"time"
)

// neighbors reads the ARP table on macOS by parsing arp -an, whose format is
// stable BSD output: "? (192.168.1.1) at a0:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]".
// There is no /proc equivalent on Darwin and the sysctl route dump would need
// cgo, so the bundled tool is the pragmatic reader.
func neighbors() ([]Neighbor, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/arp", "-an").Output()
	if err != nil {
		return nil, "lectura de tabla ARP no disponible (arp -an falló)"
	}

	var res []Neighbor
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// ? (ip) at mac on ifname ...
		if len(fields) < 4 || fields[2] != "at" {
			continue
		}
		ip := strings.Trim(fields[1], "()")
		mac := fields[3]
		if mac == "(incomplete)" {
			continue
		}
		if parsed := net.ParseIP(ip); parsed == nil || parsed.IsMulticast() {
			continue
		}
		typ := "dynamic"
		if strings.Contains(line, " permanent ") {
			typ = "static"
		}
		res = append(res, Neighbor{IP: ip, MAC: padMACOctets(mac), Type: typ})
	}
	return res, ""
}

// padMACOctets pads BSD arp's single-digit hex bytes (1:0:5e:0:0:fb) to the
// canonical two-digit form the OUI lookup and the UI expect.
func padMACOctets(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return mac
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
