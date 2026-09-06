//go:build !windows

package trace

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type unixTrace struct {
	conn *icmp.PacketConn
	dst  netip.Addr
	isV6 bool
	udp  bool
	id   int
}

// NewSession opens an ICMP TTL prober (shared by Traceroute and MTR).
func NewSession(dst netip.Addr) (Session, error) {
	t := &unixTrace{dst: dst, isV6: !dst.Is4(), id: 0xB1}
	var networks []string
	if t.isV6 {
		networks = []string{"udp6", "ip6:ipv6-icmp"}
	} else {
		networks = []string{"udp4", "ip4:icmp"}
	}
	for i, nw := range networks {
		c, err := icmp.ListenPacket(nw, anyAddr(t.isV6))
		if err == nil {
			t.conn = c
			t.udp = i == 0
			return t, nil
		}
	}
	return nil, fmt.Errorf("no se pudo abrir socket ICMP para traceroute (¿privilegios?)")
}

func anyAddr(v6 bool) string {
	if v6 {
		return "::"
	}
	return "0.0.0.0"
}

func (s *unixTrace) Probe(ttl, seq int, payload []byte, timeout time.Duration) ProbeResult {
	if s.isV6 {
		_ = s.conn.IPv6PacketConn().SetHopLimit(ttl)
	} else {
		_ = s.conn.IPv4PacketConn().SetTTL(ttl)
	}

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
		return ProbeResult{TimedOut: true}
	}

	var dstAddr net.Addr
	ipSlice := s.dst.AsSlice()
	if s.udp {
		dstAddr = &net.UDPAddr{IP: net.IP(ipSlice)}
	} else {
		dstAddr = &net.IPAddr{IP: net.IP(ipSlice)}
	}

	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := s.conn.WriteTo(wb, dstAddr); err != nil {
		return ProbeResult{TimedOut: true}
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := s.conn.ReadFrom(rb)
		if err != nil {
			return ProbeResult{TimedOut: true}
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		from := peerAddr(peer)
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			return ProbeResult{Addr: from, RTT: time.Since(start), Reached: true}
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			return ProbeResult{Addr: from, RTT: time.Since(start)}
		case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
			return ProbeResult{Addr: from, RTT: time.Since(start), Reached: from == s.dst}
		default:
			continue
		}
	}
}

func (s *unixTrace) Close() error {
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
