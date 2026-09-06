//go:build darwin

package connmon

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// List shells out to the system `lsof -i -n -P` (same technique tapmap uses
// on macOS — there is no cgo-free native socket-table API on this platform,
// and lsof ships with the OS, so this needs no new dependency). -n/-P skip
// DNS and port-name resolution so it stays fast and fully offline.
func List() ([]Connection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-i", "-n", "-P").Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && len(out) > 0 {
			// lsof exits non-zero when some processes it can't inspect exist
			// (permissions) but still prints everything it *could* read.
		} else {
			return nil, fmt.Errorf("lsof: %w", err)
		}
	}
	return parseLsof(string(out)), nil
}

func parseLsof(output string) []Connection {
	var out []Connection
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header / trailing blank
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		proto := strings.ToLower(fields[7]) // NODE column: TCP | UDP
		if proto != "tcp" && proto != "udp" {
			continue
		}
		pid, _ := strconv.Atoi(fields[1])

		rest := fields[8:]
		addrPart := rest[0]
		state := ""
		if len(rest) > 1 {
			state = strings.ToLower(strings.Trim(rest[len(rest)-1], "()"))
		}

		c := Connection{Proto: proto, PID: pid, Process: fields[0], State: state}
		if local, remote, ok := strings.Cut(addrPart, "->"); ok {
			c.LocalAddr, c.LocalPort = splitHostPort(local)
			c.RemoteAddr, c.RemotePort = splitHostPort(remote)
		} else {
			c.LocalAddr, c.LocalPort = splitHostPort(addrPart)
		}
		out = append(out, c)
	}
	return out
}

// splitHostPort parses lsof's "host:port" NAME fields — a plain LastIndex
// split works for both IPv4 ("1.2.3.4:443") and lsof's IPv6 rendering
// ("fe80::1:443"), since lsof always writes a single ':' before the port
// regardless of how many colons the address itself has.
func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	host, portStr := s[:i], s[i+1:]
	if host == "*" {
		host = "0.0.0.0"
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	port, _ := strconv.Atoi(portStr)
	return host, port
}
