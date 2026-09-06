//go:build !windows

package ping

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type unixSession struct {
	conn *icmp.PacketConn
	dst  netip.Addr
	isV6 bool
	id   int
	udp  bool // datagram (unprivileged) vs raw socket
}

// newICMPSession opens a datagram ICMP socket (unprivileged on macOS/Linux),
// falling back to a raw socket when the OS requires privileges.
func newICMPSession(dst netip.Addr) (icmpSession, error) {
	s := &unixSession{dst: dst, isV6: !dst.Is4(), id: os.Getpid() & 0xffff}
	if !s.isV6 {
		if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
			s.conn, s.udp = c, true
			return s, nil
		}
		c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("no se pudo abrir socket ICMP (¿privilegios?): %w", err)
		}
		s.conn = c
		return s, nil
	}
	if c, err := icmp.ListenPacket("udp6", "::"); err == nil {
		s.conn, s.udp = c, true
		return s, nil
	}
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir socket ICMPv6 (¿privilegios?): %w", err)
	}
	s.conn = c
	return s, nil
}

func (s *unixSession) send(seq int, payload []byte, timeout time.Duration) (time.Duration, int, netip.Addr, error) {
	var typ icmp.Type
	var proto int
	if s.isV6 {
		typ, proto = ipv6.ICMPTypeEchoRequest, 58
	} else {
		typ, proto = ipv4.ICMPTypeEcho, 1
	}
	msg := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: s.id, Seq: seq, Data: payload}}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return 0, 0, netip.Addr{}, err
	}

	var dstAddr net.Addr
	ipSlice := s.dst.AsSlice()
	if s.udp {
		dstAddr = &net.UDPAddr{IP: net.IP(ipSlice)}
	} else {
		dstAddr = &net.IPAddr{IP: net.IP(ipSlice)}
	}

	if err := s.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, 0, netip.Addr{}, err
	}
	start := time.Now()
	if _, err := s.conn.WriteTo(wb, dstAddr); err != nil {
		return 0, 0, netip.Addr{}, err
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := s.conn.ReadFrom(rb)
		if err != nil {
			return 0, 0, netip.Addr{}, fmt.Errorf("sin respuesta (timeout)")
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		// On macOS, datagram ICMP sockets receive a copy of every echo reply
		// that reaches the host (there is no per-socket ID demux like Linux),
		// so type, peer and sequence must all be validated or concurrent
		// sessions cross-match each other's replies.
		if rm.Type != ipv4.ICMPTypeEchoReply && rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		if from := peerAddr(peer); from.IsValid() && from != s.dst {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// In datagram mode the kernel rewrites the ID; match on sequence only.
		if echo.Seq != seq {
			continue
		}
		// Raw sockets keep the original ID — verify it there.
		if !s.udp && echo.ID != s.id {
			continue
		}
		elapsed := time.Since(start)
		from := peerAddr(peer)
		return elapsed, 0, from, nil // TTL not available in datagram mode
	}
}

func (s *unixSession) close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func peerAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		if ad, ok := netip.AddrFromSlice(v.IP); ok {
			return ad.Unmap()
		}
	case *net.IPAddr:
		if ad, ok := netip.AddrFromSlice(v.IP); ok {
			return ad.Unmap()
		}
	}
	return netip.Addr{}
}
