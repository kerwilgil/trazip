package pcap

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"trazip/internal/packet"
	"trazip/internal/tzsp"
)

// Una captura tomada en la máquina que RECIBE un stream TZSP guarda cada trama
// envuelta en una sola conversación UDP. Leída al pie de la letra son dos
// endpoints y un flujo — cierto e inútil: el tráfico que se quiere diagnosticar
// va dentro. Estas pruebas fijan que se abra el sobre.
//
// El caso real que lo motivó: la misma captura de 86.362 paquetes daba 866
// flujos leída directa y 1 leída desde el colector TZSP.

// innerFrame construye una trama Ethernet+IPv4+TCP entre dos hosts dados.
func innerFrame(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x74, 0x4d, 0x28, 0x88, 0xd9, 0xa4},
		DstMAC:       net.HardwareAddr{0x14, 0x85, 0x7f, 0x34, 0x94, 0x73},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, SYN: true, Window: 64240}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return serialize(t, eth, ip, tcp)
}

// wrapTZSP mete una trama en un datagrama TZSP dentro de UDP/IPv4/Ethernet,
// que es exactamente lo que graba un sniffer apuntado al colector.
func wrapTZSP(t *testing.T, frame []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x74, 0x4d, 0x28, 0x88, 0xd9, 0xa4},
		DstMAC:       net.HardwareAddr{0xc0, 0x18, 0x50, 0x96, 0x4e, 0x4a},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 168, 1, 1}, DstIP: net.IP{192, 168, 1, 108}}
	udp := &layers.UDP{SrcPort: 40996, DstPort: tzsp.DefaultPort}
	_ = udp.SetNetworkLayerForChecksum(ip)
	return serialize(t, eth, ip, udp, gopacket.Payload(tzsp.Encode(frame)))
}

func writePcapOf(t *testing.T, name string, lt layers.LinkType, packets [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, lt); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, data := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     now.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(data), Length: len(data),
		}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestReadUnwrapsTZSPEnvelopes(t *testing.T) {
	inner := innerFrame(t, net.IP{192, 168, 1, 45}, net.IP{192, 168, 1, 100}, 51604, 7680)
	path := writePcapOf(t, "tzsp.pcap", layers.LinkTypeEthernet, [][]byte{
		wrapTZSP(t, inner), wrapTZSP(t, inner), wrapTZSP(t, inner),
	})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.TZSPDecapsulated != 3 {
		t.Errorf("TZSPDecapsulated = %d, se esperaban 3", info.TZSPDecapsulated)
	}
	if len(got) != 3 {
		t.Fatalf("se entregaron %d paquetes, se esperaban 3", len(got))
	}
	// Sin desencapsular esto sería 192.168.1.1 → 192.168.1.108 en UDP.
	s := got[0]
	if s.Src != "192.168.1.45" || s.Dst != "192.168.1.100" {
		t.Errorf("se reporta %s → %s; se esperaba el tráfico transportado 192.168.1.45 → 192.168.1.100", s.Src, s.Dst)
	}
	if s.Transport != "tcp" {
		t.Errorf("transporte %q, se esperaba tcp (el del interior, no el UDP del sobre)", s.Transport)
	}
	if s.DstPort != 7680 {
		t.Errorf("puerto destino %d, se esperaba 7680", s.DstPort)
	}
}

// El tráfico que no es TZSP tiene que quedarse tal cual: la detección se aplica
// sobre payloads UDP arbitrarios de un archivo, así que un falso positivo
// reescribiría tráfico legítimo.
func TestReadLeavesNonTZSPTrafficAlone(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 5000, DstPort: tzsp.DefaultPort}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Mismo puerto que TZSP y hasta la cabecera correcta, pero lo de dentro no
	// es una trama Ethernet: no debe tocarse.
	fake := append([]byte{1, 0, 0, 1, 1}, []byte("esto no es una trama ethernet")...)
	pkt := serialize(t, eth, ip, udp, gopacket.Payload(fake))

	path := writePcapOf(t, "falso.pcap", layers.LinkTypeEthernet, [][]byte{pkt})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.TZSPDecapsulated != 0 {
		t.Errorf("TZSPDecapsulated = %d: se desenvolvió algo que no era TZSP", info.TZSPDecapsulated)
	}
	if len(got) != 1 || got[0].Src != "10.0.0.1" || got[0].Dst != "10.0.0.2" {
		t.Errorf("el paquete original se alteró: %+v", got)
	}
}

// Una captura de un medio sin decodificador tiene que poder distinguirse de una
// que simplemente no tiene tráfico interesante. Es el caso de las capturas con
// link type 139, que se mostraban como una lista de fallos sin explicación.
func TestReadReportsUndecodableLinkType(t *testing.T) {
	// LinkType 139 no lo implementa gopacket; el contenido da igual.
	path := writePcapOf(t, "raro.pcap", layers.LinkType(139), [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
		{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12},
	})

	info, err := Read(context.Background(), path, nil, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.LinkTypeNum != 139 {
		t.Errorf("LinkTypeNum = %d, se esperaba 139 — el nombre es \"UnknownLinkType\" y no orienta a nadie", info.LinkTypeNum)
	}
	if info.Undecodable != info.Packets || info.Packets != 2 {
		t.Errorf("Undecodable = %d de %d paquetes; se esperaba que todos fallaran", info.Undecodable, info.Packets)
	}
}

// Una captura normal no debe reportar nada de esto.
func TestReadReportsNothingOddForPlainCapture(t *testing.T) {
	info, err := Read(context.Background(), writeTestPcap(t), nil, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 || info.TZSPDecapsulated != 0 {
		t.Errorf("captura normal marcada como rara: undecodable=%d tzsp=%d", info.Undecodable, info.TZSPDecapsulated)
	}
	if info.LinkTypeNum != int(layers.LinkTypeEthernet) {
		t.Errorf("LinkTypeNum = %d, se esperaba %d", info.LinkTypeNum, layers.LinkTypeEthernet)
	}
}

// ReadPackets alimenta al correlador VoIP, que lee SIP/RTP de los payloads
// crudos: necesita el mismo desenvuelto o una llamada capturada desde un
// colector TZSP no se ve.
func TestReadPacketsUnwrapsTZSPToo(t *testing.T) {
	inner := innerFrame(t, net.IP{192, 168, 1, 45}, net.IP{192, 168, 1, 100}, 51604, 5060)
	path := writePcapOf(t, "voip.pcap", layers.LinkTypeEthernet, [][]byte{wrapTZSP(t, inner)})

	var seen []gopacket.Packet
	info, err := ReadPackets(context.Background(), path, func(_ int, p gopacket.Packet) {
		seen = append(seen, p)
	})
	if err != nil {
		t.Fatalf("ReadPackets: %v", err)
	}
	if info.TZSPDecapsulated != 1 {
		t.Errorf("TZSPDecapsulated = %d, se esperaba 1", info.TZSPDecapsulated)
	}
	if len(seen) != 1 {
		t.Fatalf("se entregaron %d paquetes", len(seen))
	}
	if seen[0].Layer(layers.LayerTypeTCP) == nil {
		t.Error("no llegó la capa TCP del interior: se entregó el sobre, no la trama")
	}
}
