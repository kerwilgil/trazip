//go:build windows

package connmon

import (
	"net"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")

	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess           = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImage = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle           = kernel32.NewProc("CloseHandle")
)

const (
	afInet              = 2
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID

	processQueryLimitedInformation = 0x1000
)

// mibTcpRowOwnerPid mirrors MIB_TCPROW_OWNER_PID.
type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibUdpRowOwnerPid mirrors MIB_UDPROW_OWNER_PID.
type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

var tcpStateNames = map[uint32]string{
	1: "closed", 2: "listen", 3: "syn_sent", 4: "syn_rcvd", 5: "established",
	6: "fin_wait1", 7: "fin_wait2", 8: "close_wait", 9: "closing",
	10: "last_ack", 11: "time_wait", 12: "delete_tcb",
}

// List reads the system's IPv4 TCP and UDP tables via the IP Helper API (no
// packets sent, same unprivileged family of calls as lan.Discover's ARP
// read). IPv6 is left for later, same documented gap as internal/lan.
func List() ([]Connection, error) {
	procCache := map[uint32]string{}
	resolve := func(pid uint32) string {
		if pid == 0 {
			return ""
		}
		if name, ok := procCache[pid]; ok {
			return name
		}
		name := processName(pid)
		procCache[pid] = name
		return name
	}

	var out []Connection

	tcpRows, err := getExtendedTcpTable()
	if err == nil {
		for _, row := range tcpRows {
			out = append(out, Connection{
				Proto:      "tcp",
				LocalAddr:  ipv4String(row.LocalAddr),
				LocalPort:  swapPort(row.LocalPort),
				RemoteAddr: ipv4String(row.RemoteAddr),
				RemotePort: swapPort(row.RemotePort),
				State:      tcpStateNames[row.State],
				PID:        int(row.OwningPid),
				Process:    resolve(row.OwningPid),
			})
		}
	}

	udpRows, err2 := getExtendedUdpTable()
	if err2 == nil {
		for _, row := range udpRows {
			out = append(out, Connection{
				Proto:     "udp",
				LocalAddr: ipv4String(row.LocalAddr),
				LocalPort: swapPort(row.LocalPort),
				PID:       int(row.OwningPid),
				Process:   resolve(row.OwningPid),
			})
		}
	}

	if err != nil && err2 != nil {
		return nil, err
	}
	return out, nil
}

func getExtendedTcpTable() ([]mibTcpRowOwnerPid, error) {
	var size uint32
	procGetExtTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	base := unsafe.Pointer(&buf[0])
	out := make([]mibTcpRowOwnerPid, 0, num)
	for i := uint32(0); i < num; i++ {
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(uintptr(base) + 4 + uintptr(i)*rowSize))
		out = append(out, *row)
	}
	return out, nil
}

func getExtendedUdpTable() ([]mibUdpRowOwnerPid, error) {
	var size uint32
	procGetExtUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPid, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPid, 0)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUdpRowOwnerPid{})
	base := unsafe.Pointer(&buf[0])
	out := make([]mibUdpRowOwnerPid, 0, num)
	for i := uint32(0); i < num; i++ {
		row := (*mibUdpRowOwnerPid)(unsafe.Pointer(uintptr(base) + 4 + uintptr(i)*rowSize))
		out = append(out, *row)
	}
	return out, nil
}

// ipv4String decodes a MIB row address the same way lan_windows.go decodes
// GetIpNetTable rows: the raw uint32 already holds the dotted-quad octets in
// byte order, no additional swap needed (unlike the port fields below).
func ipv4String(addr uint32) string {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24)).String()
}

// swapPort undoes the network-byte-order packing the MIB tables use for the
// port fields (the low 16 bits of the DWORD, big-endian) — a well-documented
// quirk of GetExtendedTcpTable/UdpTable distinct from the address fields.
func swapPort(raw uint32) int {
	lo := raw & 0xFFFF
	return int((lo>>8)&0xFF | (lo&0xFF)<<8)
}

// processName resolves a PID to its executable's base name via the same
// unprivileged (PROCESS_QUERY_LIMITED_INFORMATION) handle class Task Manager
// uses for other users' processes; returns "" if the process exited between
// the table read and this call, or access is denied.
func processName(pid uint32) string {
	h, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandle.Call(h)

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImage.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "PID " + strconv.Itoa(int(pid))
	}
	return filepath.Base(windows.UTF16ToString(buf[:size]))
}
