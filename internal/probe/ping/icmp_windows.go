//go:build windows

package ping

import (
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION.
type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY (64-bit layout).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// IP_STATUS success value.
const ipStatusSuccess = 0

type winSession struct {
	handle windows.Handle
	dstV4  uint32
}

// newICMPSession opens an ICMP handle. IPv4 uses the unprivileged IP Helper API.
func newICMPSession(dst netip.Addr) (icmpSession, error) {
	if !dst.Is4() {
		return nil, fmt.Errorf("ping IPv6 en Windows aún no soportado (IPv4 disponible)")
	}
	r, _, err := procIcmpCreateFile.Call()
	h := windows.Handle(r)
	if h == windows.InvalidHandle || h == 0 {
		return nil, fmt.Errorf("IcmpCreateFile falló: %v", err)
	}
	b := dst.As4()
	// Destination is an IPAddr in network byte order, stored little-endian.
	v4 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return &winSession{handle: h, dstV4: v4}, nil
}

func (s *winSession) send(seq int, payload []byte, timeout time.Duration) (time.Duration, int, netip.Addr, error) {
	replySize := uint32(unsafe.Sizeof(icmpEchoReply{})) + uint32(len(payload)) + 8
	reply := make([]byte, replySize)

	var reqData *byte
	if len(payload) > 0 {
		reqData = &payload[0]
	}
	timeoutMs := uint32(timeout.Milliseconds())
	if timeoutMs == 0 {
		timeoutMs = 1000
	}

	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(
		uintptr(s.handle),
		uintptr(s.dstV4),
		uintptr(unsafe.Pointer(reqData)),
		uintptr(uint16(len(payload))),
		0, // request options
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)
	elapsed := time.Since(start)

	if n == 0 {
		return 0, 0, netip.Addr{}, fmt.Errorf("sin respuesta (timeout)")
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if r.Status != ipStatusSuccess {
		return 0, 0, netip.Addr{}, fmt.Errorf("%s", icmpStatusText(r.Status))
	}
	var ab [4]byte
	ab[0] = byte(r.Address)
	ab[1] = byte(r.Address >> 8)
	ab[2] = byte(r.Address >> 16)
	ab[3] = byte(r.Address >> 24)
	from := netip.AddrFrom4(ab)
	return elapsed, int(r.Options.TTL), from, nil
}

func (s *winSession) close() error {
	if s.handle != 0 {
		procIcmpCloseHandle.Call(uintptr(s.handle))
		s.handle = 0
	}
	return nil
}

// icmpStatusText maps common IP_STATUS codes to a readable message.
func icmpStatusText(status uint32) string {
	switch status {
	case 11001:
		return "buffer too small"
	case 11002:
		return "destination network unreachable"
	case 11003:
		return "destination host unreachable"
	case 11004:
		return "destination protocol unreachable"
	case 11005:
		return "destination port unreachable"
	case 11010:
		return "request timed out"
	case 11013:
		return "TTL expired in transit"
	default:
		return fmt.Sprintf("icmp status %d", status)
	}
}
