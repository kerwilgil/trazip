//go:build windows

package lan

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

// mibIpNetRow mirrors MIB_IPNETROW (IPv4 ARP entry).
type mibIpNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

const errInsufficientBuffer = 122

// neighbors reads the system IPv4 ARP table via the IP Helper API (no packets
// sent). IPv6 NDP would use GetIpNetTable2 (future).
func neighbors() ([]Neighbor, string) {
	var size uint32
	// First call sizes the buffer.
	procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return nil, "tabla ARP vacía"
	}
	buf := make([]byte, size)
	ret, _, _ := procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		if ret == errInsufficientBuffer {
			return nil, "tabla ARP cambió de tamaño; reintentar"
		}
		return nil, "no se pudo leer la tabla ARP del sistema"
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIpNetRow{})
	base := unsafe.Pointer(&buf[0])

	out := make([]Neighbor, 0, num)
	for i := uint32(0); i < num; i++ {
		row := (*mibIpNetRow)(unsafe.Pointer(uintptr(base) + 4 + uintptr(i)*rowSize))
		if row.Type == 2 || row.PhysAddrLen == 0 { // invalid / incomplete
			continue
		}
		ip := net.IPv4(byte(row.Addr), byte(row.Addr>>8), byte(row.Addr>>16), byte(row.Addr>>24))
		mac := net.HardwareAddr(row.PhysAddr[:row.PhysAddrLen]).String()
		out = append(out, Neighbor{IP: ip.String(), MAC: mac, Type: arpType(row.Type)})
	}
	return out, ""
}

func arpType(t uint32) string {
	switch t {
	case 3:
		return "dynamic"
	case 4:
		return "static"
	default:
		return "other"
	}
}
