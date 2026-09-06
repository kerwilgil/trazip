//go:build linux

package connmon

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var tcpStateNames = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv",
	"04": "fin_wait1", "05": "fin_wait2", "06": "time_wait",
	"07": "close", "08": "close_wait", "09": "last_ack",
	"0A": "listen", "0B": "closing",
}

// rawConn pairs a parsed Connection with the socket inode /proc/net/* reports
// — needed only transiently to cross-reference against buildInodeIndex, so it
// stays local to this file instead of growing the shared Connection struct.
type rawConn struct {
	Connection
	inode int
}

// List reads /proc/net/{tcp,tcp6,udp,udp6} for local sockets, then resolves
// each socket's inode to an owning PID by scanning /proc/*/fd — the same
// unprivileged approach `ss`/`netstat -p` use. Sockets owned by another
// user's process resolve with PID 0 (permission denied reading their fd
// directory) rather than failing the whole snapshot.
func List() ([]Connection, error) {
	inodeToPID := buildInodeIndex()

	var raw []rawConn
	for _, src := range []struct {
		path, proto string
	}{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		rows, err := parseProcNet(src.path, src.proto)
		if err != nil {
			continue // missing file (unsupported kernel config) — skip, not fatal
		}
		raw = append(raw, rows...)
	}

	nameCache := map[int]string{}
	out := make([]Connection, len(raw))
	for i, r := range raw {
		c := r.Connection
		if pid, ok := inodeToPID[r.inode]; ok {
			c.PID = pid
			if name, ok := nameCache[pid]; ok {
				c.Process = name
			} else {
				name := processComm(pid)
				nameCache[pid] = name
				c.Process = name
			}
		}
		out[i] = c
	}
	return out, nil
}

func parseProcNet(path, proto string) ([]rawConn, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []rawConn
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort := decodeHexAddr(fields[1])
		remoteAddr, remotePort := decodeHexAddr(fields[2])
		inode, _ := strconv.Atoi(fields[9])
		c := Connection{
			Proto:      proto,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
		}
		if proto == "tcp" {
			c.State = tcpStateNames[strings.ToUpper(fields[3])]
		}
		out = append(out, rawConn{Connection: c, inode: inode})
	}
	return out, nil
}

// decodeHexAddr parses the "IP:PORT" pairs /proc/net/{tcp,udp}[6] use — the
// address is little-endian hex words (see kernel's tcp_ipv4.c seq_printf),
// the port is plain big-endian hex.
func decodeHexAddr(field string) (string, int) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0
	}
	port64, _ := strconv.ParseUint(parts[1], 16, 32)
	port := int(port64)

	switch len(raw) {
	case 4: // IPv4
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), port
	case 16: // IPv6, four little-endian 32-bit words
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			ip[w*4+0] = raw[w*4+3]
			ip[w*4+1] = raw[w*4+2]
			ip[w*4+2] = raw[w*4+1]
			ip[w*4+3] = raw[w*4+0]
		}
		return ip.String(), port
	default:
		return "", port
	}
}

// buildInodeIndex walks /proc/*/fd once and maps each socket's inode to its
// owning PID (one pass, shared by all four /proc/net/* tables).
func buildInodeIndex() map[int]int {
	out := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue // exited or no permission — best-effort
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			var inode int
			if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err == nil {
				out[inode] = pid
			}
		}
	}
	return out
}

func processComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
