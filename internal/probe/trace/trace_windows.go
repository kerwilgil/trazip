//go:build windows

package trace

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

type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

const (
	ipSuccess           = 0
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013
)

type winTrace struct {
	handle windows.Handle
	dst    netip.Addr
	dstV4  uint32
}

// NewSession opens an unprivileged ICMP TTL prober (shared by Traceroute and MTR).
func NewSession(dst netip.Addr) (Session, error) {
	if !dst.Is4() {
		return nil, fmt.Errorf("IPv6 en Windows aún no soportado (IPv4 disponible)")
	}
	r, _, err := procIcmpCreateFile.Call()
	h := windows.Handle(r)
	if h == windows.InvalidHandle || h == 0 {
		return nil, fmt.Errorf("IcmpCreateFile falló: %v", err)
	}
	b := dst.As4()
	v4 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return &winTrace{handle: h, dst: dst, dstV4: v4}, nil
}

func (s *winTrace) Probe(ttl, _ int, payload []byte, timeout time.Duration) ProbeResult {
	opt := ipOptionInformation{TTL: uint8(ttl)}
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
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)
	elapsed := time.Since(start)

	if n == 0 {
		return ProbeResult{TimedOut: true}
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	from := addrFromU32(r.Address)

	switch r.Status {
	case ipSuccess:
		return ProbeResult{Addr: from, RTT: elapsed, Reached: true}
	case ipReqTimedOut:
		return ProbeResult{TimedOut: true}
	case ipTTLExpiredTransit:
		return ProbeResult{Addr: from, RTT: elapsed}
	default:
		// Destination-unreachable and similar: the replier is a real hop; if it
		// is the destination itself, treat as reached.
		return ProbeResult{Addr: from, RTT: elapsed, Reached: from == s.dst}
	}
}

func (s *winTrace) Close() error {
	if s.handle != 0 {
		procIcmpCloseHandle.Call(uintptr(s.handle))
		s.handle = 0
	}
	return nil
}

func addrFromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}
