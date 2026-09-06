package voip

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type callPCAPSpec struct {
	CallID, CallerIP, CalleeIP, Profile, Codec, RTPMap string
	CallerMediaPort, CalleeMediaPort                   uint16
	PT                                                 uint8
	SSRC                                               uint32
	Ptime                                              int
	Start                                              time.Time
	RTP                                                []rtpPacketSpec
}
type rtpPacketSpec struct {
	FromCaller bool
	Seq        uint16
	Timestamp  uint32
	PT         uint8
	Payload    []byte
	Offset     time.Duration
}

func writeCallsPCAP(t *testing.T, specs []callPCAPSpec) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.pcap")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if e = w.WriteFileHeader(65535, layers.LinkTypeEthernet); e != nil {
		t.Fatal(e)
	}
	write := func(src, dst string, sp, dp uint16, b []byte, at time.Time) {
		si := net.ParseIP(src)
		di := net.ParseIP(dst)
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: si, DstIP: di}
		u := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
		_ = u.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if e := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, u, gopacket.Payload(b)); e != nil {
			t.Fatal(e)
		}
		d := buf.Bytes()
		if e := w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(d), Length: len(d)}, d); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range specs {
		sdp := fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d %s %d\r\na=rtpmap:%d %s/%d\r\na=ptime:%d\r\n", s.CallerIP, s.CallerMediaPort, s.Profile, s.PT, s.PT, s.RTPMap, 8000, s.Ptime)
		sip := fmt.Sprintf("INVITE sip:x@%s SIP/2.0\r\nFrom: <sip:a@%s>;tag=a\r\nTo: <sip:b@%s>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", s.CalleeIP, s.CallerIP, s.CalleeIP, s.CallID, len(sdp), sdp)
		write(s.CallerIP, s.CalleeIP, 5060, 5060, []byte(sip), s.Start)
		for _, r := range s.RTP {
			src, dst, sp, dp := s.CallerIP, s.CalleeIP, s.CallerMediaPort, s.CalleeMediaPort
			if !r.FromCaller {
				src, dst, sp, dp = dst, src, dp, sp
			}
			raw := make([]byte, 12+len(r.Payload))
			raw[0] = 0x80
			raw[1] = r.PT
			binary.BigEndian.PutUint16(raw[2:4], r.Seq)
			binary.BigEndian.PutUint32(raw[4:8], r.Timestamp)
			binary.BigEndian.PutUint32(raw[8:12], s.SSRC)
			copy(raw[12:], r.Payload)
			write(src, dst, sp, dp, raw, s.Start.Add(r.Offset))
		}
	}
	return p
}

func TestConfigurableCallPCAPOverridesAndMultiCall(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	specs := []callPCAPSpec{{CallID: "a@test", CallerIP: "10.0.0.10", CalleeIP: "10.0.0.20", CallerMediaPort: 4000, CalleeMediaPort: 4002, Profile: "RTP/AVP", RTPMap: "PCMU", PT: 0, SSRC: 1111, Ptime: 20, Start: base, RTP: []rtpPacketSpec{{true, 7, 160, 0, []byte{0xff}, time.Millisecond}}}, {CallID: "b@test", CallerIP: "10.0.1.10", CalleeIP: "10.0.1.20", CallerMediaPort: 5000, CalleeMediaPort: 5002, Profile: "RTP/AVP", RTPMap: "PCMA", PT: 8, SSRC: 2222, Ptime: 10, Start: base.Add(time.Minute), RTP: []rtpPacketSpec{{true, 9, 80, 8, []byte{0xd5}, time.Millisecond}}}}
	r, e := Analyze(context.Background(), writeCallsPCAP(t, specs), nil)
	if e != nil {
		t.Fatal(e)
	}
	if r.TotalCalls != 2 {
		t.Fatalf("calls=%d", r.TotalCalls)
	}
	seen := map[string]bool{}
	for _, c := range r.Calls {
		seen[c.CallID] = true
	}
	if !seen["a@test"] || !seen["b@test"] {
		t.Fatal(seen)
	}
}
