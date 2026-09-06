package lab

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"trazip/internal/detection/scandetect"
	"trazip/internal/flow"
	"trazip/internal/packet"
	"trazip/internal/pcap"
	"trazip/internal/voip"
)

// pcapBuilder is a small helper shared by every scenario generator below —
// each scenario writes to an in-memory buffer (no temp file needed until
// WritePCAP saves the final bytes), with fixed addresses/timestamps so the
// output is byte-identical on every run (módulo 27 "escenarios
// reproducibles").
type pcapBuilder struct {
	buf  bytes.Buffer
	w    *pcapgo.Writer
	base time.Time
	err  error
}

func newPCAPBuilder() *pcapBuilder {
	b := &pcapBuilder{base: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	b.w = pcapgo.NewWriter(&b.buf)
	b.err = b.w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	return b
}

func (b *pcapBuilder) udp(src, dst net.IP, srcMAC, dstMAC net.HardwareAddr, srcPort, dstPort uint16, payload []byte, at time.Duration) {
	if b.err != nil {
		return
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	b.write(eth, ip, udp, payload, at)
}

func (b *pcapBuilder) tcp(src, dst net.IP, srcMAC, dstMAC net.HardwareAddr, srcPort, dstPort uint16, seq, ack uint32, flags tcpFlags, payload []byte, at time.Duration) {
	if b.err != nil {
		return
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
		Seq: seq, Ack: ack, Window: 64240,
		SYN: flags.syn, ACK: flags.ack, PSH: flags.psh, FIN: flags.fin, RST: flags.rst,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	b.write(eth, ip, tcp, payload, at)
}

type tcpFlags struct{ syn, ack, psh, fin, rst bool }

func (b *pcapBuilder) write(eth *layers.Ethernet, ip *layers.IPv4, transport gopacket.SerializableLayer, payload []byte, at time.Duration) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if len(payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, transport, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, transport)
	}
	if err != nil {
		b.err = err
		return
	}
	data := buf.Bytes()
	ci := gopacket.CaptureInfo{Timestamp: b.base.Add(at), CaptureLength: len(data), Length: len(data)}
	if err := b.w.WritePacket(ci, data); err != nil {
		b.err = err
	}
}

func (b *pcapBuilder) bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.buf.Bytes(), nil
}

// --- Scenario 1: VoIP call with partial packet loss -----------------------

func voipLossScenario() Scenario {
	return Scenario{
		ID:        "voip-rtp-loss",
		Title:     "Llamada VoIP con pérdida de paquetes RTP",
		Technique: "Calidad y exposición VoIP",
		Signal:    "Pérdida RTP observable y degradación del MOS estimado",
		Description: "Una llamada SIP/RTP completa entre dos extremos sintéticos (Alice/Bob) en la que el " +
			"tramo Alice→Bob pierde 2 de 40 paquetes RTP. Objetivo: usar el correlador VoIP de TRAZIP para " +
			"encontrar la llamada, identificar qué stream tiene pérdida y estimar su impacto en el MOS.",
		Objectives: []Objective{
			{Question: "¿Cuántas llamadas SIP se detectan en la captura?", Hint: "Pestaña VoIP Calls → contador de llamadas."},
			{Question: "¿La llamada se estableció correctamente (200 OK + RTP)?", Hint: "Estado de la llamada en la tabla."},
			{Question: "¿Cuántos streams RTP tienen paquetes perdidos?", Hint: "Columna de pérdida en la tabla de streams."},
			{Question: "¿Qué stream tiene el MOS más bajo, y por qué?", Hint: "La pérdida de paquetes reduce el MOS estimado."},
		},
		Expected: []Fact{
			fact("total_calls", "Llamadas totales", "1"),
			fact("established_calls", "Llamadas establecidas", "1"),
			fact("failed_calls", "Llamadas fallidas", "0"),
			fact("call_established", "Primera llamada establecida", "true"),
			fact("streams_with_loss", "Streams RTP con pérdida", "1"),
		},
		generate: generateVoIPLossPCAP,
		analyze:  analyzeVoIPScenario,
	}
}

func generateVoIPLossPCAP() ([]byte, error) {
	b := newPCAPBuilder()

	aliceIP, bobIP := net.IP{192, 168, 50, 10}, net.IP{192, 168, 50, 20}
	aliceMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	bobMAC := net.HardwareAddr{0, 6, 7, 8, 9, 10}

	sipMsg := func(lines ...string) []byte {
		s := ""
		for _, l := range lines {
			s += l + "\r\n"
		}
		return []byte(s)
	}

	offerSDP := "v=0\r\no=alice 1 1 IN IP4 192.168.50.10\r\ns=-\r\nc=IN IP4 192.168.50.10\r\nt=0 0\r\n" +
		"m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
	answerSDP := "v=0\r\no=bob 1 1 IN IP4 192.168.50.20\r\ns=-\r\nc=IN IP4 192.168.50.20\r\nt=0 0\r\n" +
		"m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

	invite := sipMsg(
		"INVITE sip:bob@192.168.50.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.50.20>",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 1 INVITE",
		"Contact: <sip:alice@192.168.50.10:5060>",
		"Content-Type: application/sdp",
		fmt.Sprintf("Content-Length: %d", len(offerSDP)), "", offerSDP,
	)
	trying := sipMsg(
		"SIP/2.0 100 Trying",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.50.20>",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 1 INVITE", "Content-Length: 0", "",
	)
	ringing := sipMsg(
		"SIP/2.0 180 Ringing",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.50.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 1 INVITE", "Content-Length: 0", "",
	)
	ok200 := sipMsg(
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.50.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 1 INVITE",
		"Contact: <sip:bob@192.168.50.20:5060>",
		"Content-Type: application/sdp",
		fmt.Sprintf("Content-Length: %d", len(answerSDP)), "", answerSDP,
	)
	ack := sipMsg(
		"ACK sip:bob@192.168.50.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK2",
		"To: Bob <sip:bob@192.168.50.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 1 ACK", "Content-Length: 0", "",
	)
	bye := sipMsg(
		"BYE sip:bob@192.168.50.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK3",
		"To: Bob <sip:bob@192.168.50.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 2 BYE", "Content-Length: 0", "",
	)
	byeOK := sipMsg(
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.168.50.10;branch=z9hG4bK3",
		"To: Bob <sip:bob@192.168.50.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.50.10>;tag=aaa111",
		"Call-ID: lab-voip-loss@192.168.50.10",
		"CSeq: 2 BYE", "Content-Length: 0", "",
	)

	b.udp(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, invite, 0)
	b.udp(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, trying, 10*time.Millisecond)
	b.udp(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, ringing, 200*time.Millisecond)
	b.udp(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, ok200, time.Second)
	b.udp(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, ack, 1010*time.Millisecond)

	rtpPayload := func(seq uint16, ts, ssrc uint32) []byte {
		p := make([]byte, 12+160)
		p[0] = 0x80
		p[1] = 0 // PCMU
		p[2], p[3] = byte(seq>>8), byte(seq)
		p[4], p[5], p[6], p[7] = byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts)
		p[8], p[9], p[10], p[11] = byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc)
		for i := 12; i < len(p); i++ {
			p[i] = 0xFF // near-silence in μ-law
		}
		return p
	}

	rtpStart := 1100 * time.Millisecond
	for i := 0; i < 40; i++ {
		at := rtpStart + time.Duration(i)*20*time.Millisecond
		// Drop 2 of 40 packets on the Alice→Bob leg only, per the scenario's premise.
		if i != 15 && i != 27 {
			b.udp(aliceIP, bobIP, aliceMAC, bobMAC, 40000, 40002, rtpPayload(uint16(i), uint32(i)*160, 0xA11CE001), at)
		}
		b.udp(bobIP, aliceIP, bobMAC, aliceMAC, 40002, 40000, rtpPayload(uint16(i), uint32(i)*160, 0xB0B00002), at+time.Millisecond)
	}

	end := rtpStart + 40*20*time.Millisecond
	b.udp(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, bye, end)
	b.udp(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, byeOK, end+10*time.Millisecond)

	return b.bytes()
}

func analyzeVoIPScenario(ctx context.Context, pcapPath string) ([]Fact, error) {
	// Lab scenarios use synthetic addresses for teaching (§27); there is
	// nothing for an offline GeoIP dataset to meaningfully resolve here.
	res, err := voip.Analyze(ctx, pcapPath, nil)
	if err != nil {
		return nil, err
	}
	return factsFromVoIP(res), nil
}

// --- Scenario 2: basic traffic flow / protocol mix -------------------------

func flowBasicsScenario() Scenario {
	return Scenario{
		ID:        "flow-basics",
		Title:     "Fundamentos de flujos: DNS + HTTP",
		Technique: "Análisis de tráfico",
		Signal:    "Flujos DNS/HTTP reconstruidos desde evidencia PCAP",
		Description: "Una captura sintética con una consulta DNS y una conversación HTTP completa (handshake, " +
			"GET, respuesta, cierre) entre dos hosts. Objetivo: usar PCAP Analyzer para identificar cuántos " +
			"flujos hay, cuál protocolo domina en paquetes, y reconstruir el orden de los eventos.",
		Objectives: []Objective{
			{Question: "¿Cuántos paquetes tiene la captura en total?", Hint: "Encabezado del PCAP Analyzer."},
			{Question: "¿Cuántos flujos (conversaciones) distintos hay?", Hint: "Pestaña Flujos."},
			{Question: "¿Qué protocolo de transporte predomina en cantidad de paquetes?", Hint: "Compará TCP vs UDP en la tabla de paquetes."},
		},
		Expected: []Fact{
			fact("total_packets", "Paquetes totales", "11"),
			fact("total_flows", "Flujos totales", "2"),
			fact("dominant_transport", "Transporte dominante", "tcp"),
		},
		generate: generateFlowBasicsPCAP,
		analyze:  analyzeFlowBasicsScenario,
	}
}

func generateFlowBasicsPCAP() ([]byte, error) {
	b := newPCAPBuilder()

	clientIP, serverIP := net.IP{10, 10, 0, 5}, net.IP{10, 10, 0, 1}
	clientMAC := net.HardwareAddr{0xAA, 0, 0, 0, 0, 1}
	serverMAC := net.HardwareAddr{0xAA, 0, 0, 0, 0, 2}

	// DNS query + response (UDP/53) — 2 packets.
	dnsQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	dnsResp := append(append([]byte{}, dnsQuery...), 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 10, 0, 1)
	dnsResp[2] = 0x81
	dnsResp[3] = 0x80
	dnsResp[7] = 0x01 // ANCOUNT=1
	b.udp(clientIP, serverIP, clientMAC, serverMAC, 51000, 53, dnsQuery, 0)
	b.udp(serverIP, clientIP, serverMAC, clientMAC, 53, 51000, dnsResp, 15*time.Millisecond)

	// TCP handshake + HTTP GET/response + close — 9 packets.
	var seqC, seqS uint32 = 1000, 5000
	b.tcp(clientIP, serverIP, clientMAC, serverMAC, 51001, 80, seqC, 0, tcpFlags{syn: true}, nil, 20*time.Millisecond)
	b.tcp(serverIP, clientIP, serverMAC, clientMAC, 80, 51001, seqS, seqC+1, tcpFlags{syn: true, ack: true}, nil, 22*time.Millisecond)
	seqC++
	b.tcp(clientIP, serverIP, clientMAC, serverMAC, 51001, 80, seqC, seqS+1, tcpFlags{ack: true}, nil, 24*time.Millisecond)

	get := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.tcp(clientIP, serverIP, clientMAC, serverMAC, 51001, 80, seqC, seqS+1, tcpFlags{ack: true, psh: true}, get, 26*time.Millisecond)
	seqS++
	b.tcp(serverIP, clientIP, serverMAC, clientMAC, 80, 51001, seqS, seqC+uint32(len(get)), tcpFlags{ack: true}, nil, 28*time.Millisecond)

	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	b.tcp(serverIP, clientIP, serverMAC, clientMAC, 80, 51001, seqS, seqC+uint32(len(get)), tcpFlags{ack: true, psh: true}, resp, 30*time.Millisecond)
	seqC += uint32(len(get))
	b.tcp(clientIP, serverIP, clientMAC, serverMAC, 51001, 80, seqC, seqS+uint32(len(resp)), tcpFlags{ack: true}, nil, 32*time.Millisecond)

	b.tcp(clientIP, serverIP, clientMAC, serverMAC, 51001, 80, seqC, seqS+uint32(len(resp)), tcpFlags{ack: true, fin: true}, nil, 34*time.Millisecond)
	seqS += uint32(len(resp))
	b.tcp(serverIP, clientIP, serverMAC, clientMAC, 80, 51001, seqS, seqC+1, tcpFlags{ack: true, fin: true}, nil, 36*time.Millisecond)

	return b.bytes()
}

func analyzeFlowBasicsScenario(ctx context.Context, pcapPath string) ([]Fact, error) {
	ft := flow.New()
	protoPkts := map[string]int{}
	var total int
	_, err := pcap.Read(ctx, pcapPath, func(s packet.Summary) {
		total++
		ft.Add(s)
		protoPkts[s.Transport]++
	}, pcap.Options{})
	if err != nil {
		return nil, err
	}

	dominant := ""
	best := -1
	for proto, n := range protoPkts {
		if n > best {
			best, dominant = n, proto
		}
	}

	return []Fact{
		fact("total_packets", "Paquetes totales", itoa(total)),
		fact("total_flows", "Flujos totales", itoa(len(ft.Flows()))),
		fact("dominant_transport", "Transporte dominante", dominant),
	}, nil
}

// --- Scenario 3: passive detection of vertical and horizontal scans -------

func scanDetectionScenario() Scenario {
	return Scenario{
		ID:        "purple-scan-detection",
		Title:     "Purple Team: detección pasiva de reconocimiento",
		Technique: "MITRE ATT&CK T1046 Network Service Discovery",
		Signal:    "SYN iniciales con fan-out vertical y horizontal",
		Description: "Una captura sintética contiene un barrido vertical contra un servidor y un barrido " +
			"horizontal del puerto SMB. TRAZIP no transmite esos paquetes: genera el PCAP localmente y valida " +
			"su motor defensivo con evidencia conocida.",
		Objectives: []Objective{
			{Question: "¿Qué origen realizó el barrido vertical?", Hint: "PCAP Analyzer → Detecciones."},
			{Question: "¿Cuántos puertos distintos intentó contra el servidor?", Hint: "Revise la evidencia del hallazgo vertical."},
			{Question: "¿Qué puerto fue probado en varios equipos?", Hint: "Revise el hallazgo horizontal."},
		},
		Expected: []Fact{
			fact("scan_findings", "Hallazgos de reconocimiento", "2"),
			fact("vertical_findings", "Barridos verticales", "1"),
			fact("horizontal_findings", "Barridos horizontales", "1"),
		},
		generate: generateScanDetectionPCAP,
		analyze:  analyzeScanDetectionScenario,
	}
}

func generateScanDetectionPCAP() ([]byte, error) {
	b := newPCAPBuilder()
	scannerIP, serverIP := net.IP{10, 20, 0, 10}, net.IP{10, 20, 0, 20}
	scannerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x10}
	targetMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20}

	// Vertical: 16 distinct destination ports on one server.
	for i, port := range []uint16{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 5060, 5432, 8080} {
		b.tcp(scannerIP, serverIP, scannerMAC, targetMAC, uint16(50000+i), port,
			uint32(1000+i), 0, tcpFlags{syn: true}, nil, time.Duration(i)*25*time.Millisecond)
	}

	// Horizontal: the same source checks SMB on 12 distinct hosts.
	for i := 1; i <= 12; i++ {
		dst := net.IP{10, 20, 1, byte(i)}
		b.tcp(scannerIP, dst, scannerMAC, targetMAC, uint16(51000+i), 445,
			uint32(2000+i), 0, tcpFlags{syn: true}, nil, time.Second+time.Duration(i)*30*time.Millisecond)
	}
	return b.bytes()
}

func analyzeScanDetectionScenario(ctx context.Context, pcapPath string) ([]Fact, error) {
	detector := scandetect.New()
	_, err := pcap.Read(ctx, pcapPath, detector.Add, pcap.Options{})
	if err != nil {
		return nil, err
	}
	res := detector.Result()
	return []Fact{
		fact("scan_findings", "Hallazgos de reconocimiento", itoa(len(res.Findings))),
		fact("vertical_findings", "Barridos verticales", itoa(res.Vertical)),
		fact("horizontal_findings", "Barridos horizontales", itoa(res.Horizontal)),
	}, nil
}
