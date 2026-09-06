package pcap

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"trazip/internal/packet"
	"trazip/internal/ppi"
)

// beacon arma una trama 802.11 de baliza anunciando ssid en el canal dado.
// Se construye a mano porque gopacket no serializa balizas con sus elementos
// de información, y el punto de la prueba es leer lo que graba una herramienta
// de campo, no lo que produce la propia librería.
func beacon(ssid string, channel byte, bssid net.HardwareAddr) []byte {
	f := []byte{
		0x80, 0x00, // control de trama: gestión / baliza
		0x00, 0x00, // duración
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destino: difusión
	}
	f = append(f, bssid...) // transmisor
	f = append(f, bssid...) // BSSID
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0) // marca de tiempo
	f = append(f, 0x64, 0x00)             // intervalo de baliza
	f = append(f, 0x11, 0x04)             // capacidades
	f = append(f, 0x00, byte(len(ssid)))  // IE SSID
	f = append(f, []byte(ssid)...)
	f = append(f, 0x01, 0x01, 0x82)    // IE de tasas
	f = append(f, 0x03, 0x01, channel) // IE de parámetros DS: canal
	// Sin FCS al final, que es como se guardan muchas capturas reales: el
	// driver ya la verificó y la descartó. Verificado contra
	// Network_Join_Nokia_Mobile.pcap del corpus de Wireshark, donde ninguna de
	// las 1.180 tramas lo lleva.
	return f
}

// withFCS devuelve la trama con su secuencia de verificación real al final,
// como la guardan las capturas que sí la conservan.
func withFCS(frame []byte) []byte {
	out := make([]byte, len(frame)+4)
	copy(out, frame)
	binary.LittleEndian.PutUint32(out[len(frame):], crc32.ChecksumIEEE(frame))
	return out
}

func prism(frame []byte) []byte {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0x44)
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(header)))
	copy(header[8:24], []byte("trazip-test"))
	return append(header, frame...)
}

// ack es una trama de control de 10 bytes sin FCS: el caso que gopacket
// rechazaba de plano por exigir sitio para una FCS que no está.
func ack(ra net.HardwareAddr) []byte {
	f := []byte{0xd4, 0x00, 0x00, 0x00} // control / ACK + duración
	return append(f, ra...)
}

// Una captura de reconocimiento WiFi se guarda como link type 105. gopacket
// sabe decodificar 802.11 pero no asocia ese link type a su decodificador, así
// que sin el mapeo propio el archivo entero se leía como tramas ilegibles.
func TestReadDecodes80211Captures(t *testing.T) {
	bssid := net.HardwareAddr{0x74, 0x4d, 0x28, 0x88, 0xd9, 0xa4}
	path := writePcapOf(t, "wifi.pcap", layers.LinkTypeIEEE802_11, [][]byte{
		beacon("RedDeCasa", 6, bssid),
	})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 {
		t.Errorf("%d tramas ilegibles: el decodificador de 802.11 no se está aplicando", info.Undecodable)
	}
	if len(got) != 1 {
		t.Fatalf("se entregaron %d tramas", len(got))
	}
	s := got[0]
	if s.SSID != "RedDeCasa" {
		t.Errorf("SSID = %q", s.SSID)
	}
	if s.Channel != 6 {
		t.Errorf("canal = %d, se esperaba 6", s.Channel)
	}
	if s.BSSID != bssid.String() {
		t.Errorf("BSSID = %q, se esperaba %q", s.BSSID, bssid)
	}
	if s.WiFiType != "beacon" {
		t.Errorf("tipo de trama = %q", s.WiFiType)
	}
	// Sin esto la fila diría solo "Dot11", que no distingue una baliza de otra
	// en una lista de miles: la red anunciada es el contenido de la trama.
	if s.Info != "beacon · SSID RedDeCasa · channel 6" {
		t.Errorf("Info = %q", s.Info)
	}
	if s.Proto != "802.11" {
		t.Errorf("Proto = %q", s.Proto)
	}
}

// PPI es lo que anteponen las herramientas de reconocimiento para llevar lo que
// sabía la radio, sobre todo la posición GPS.
func TestReadUnwrapsPPIAndKeepsPosition(t *testing.T) {
	bssid := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	const lat, lon = 8.9824, -79.5199

	frames := [][]byte{
		ppi.EncodeGPS(uint32(layers.LinkTypeIEEE802_11), beacon("Oficina", 11, bssid), lat, lon, 20),
		ppi.EncodeGPS(uint32(layers.LinkTypeIEEE802_11), beacon("Oficina", 11, bssid), lat+0.001, lon, 21),
	}
	path := writePcapOf(t, "ppi.pcap", layers.LinkType(ppi.LinkType), frames)

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 {
		t.Errorf("%d tramas ilegibles tras desenvolver PPI", info.Undecodable)
	}
	if info.GPSFixes != 2 {
		t.Errorf("GPSFixes = %d, se esperaban 2", info.GPSFixes)
	}
	if !info.FirstFix.HasPosition() || !info.LastFix.HasPosition() {
		t.Fatalf("no se conservó la posición: primera=%+v última=%+v", info.FirstFix, info.LastFix)
	}
	if *info.FirstFix.Latitude == *info.LastFix.Latitude {
		t.Error("primera y última posición son la misma: el recorrido no se está siguiendo")
	}
	// Lo de dentro tiene que haberse decodificado como 802.11, no quedarse en
	// el envoltorio.
	if len(got) != 2 || got[0].SSID != "Oficina" || got[0].Channel != 11 {
		t.Errorf("la trama interior no se decodificó: %+v", got)
	}
}

// Una captura PPI sin GPS es normal (radio sin receptor conectado): se leen las
// tramas y no se inventa una posición.
func TestReadPPIWithoutGPS(t *testing.T) {
	frame := beacon("SinGPS", 1, net.HardwareAddr{1, 2, 3, 4, 5, 6})
	rec := make([]byte, 0, 8+len(frame))
	rec = append(rec, 0, 0)
	rec = binary.LittleEndian.AppendUint16(rec, 8)
	rec = binary.LittleEndian.AppendUint32(rec, uint32(layers.LinkTypeIEEE802_11))
	rec = append(rec, frame...)

	path := writePcapOf(t, "ppi-sin-gps.pcap", layers.LinkType(ppi.LinkType), [][]byte{rec})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.GPSFixes != 0 || info.FirstFix != nil {
		t.Errorf("se inventó una posición: fixes=%d primera=%+v", info.GPSFixes, info.FirstFix)
	}
	if len(got) != 1 || got[0].SSID != "SinGPS" {
		t.Errorf("no se leyó la trama: %+v", got)
	}
}

// Una red oculta anuncia un SSID vacío. Dejarlo en blanco parecería un fallo de
// lectura; decir que está oculta es el dato.
func TestHiddenSSIDIsNamed(t *testing.T) {
	path := writePcapOf(t, "oculta.pcap", layers.LinkTypeIEEE802_11, [][]byte{
		beacon("", 3, net.HardwareAddr{1, 2, 3, 4, 5, 6}),
	})
	var got []packet.Summary
	if _, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got[0].SSID != "(hidden)" {
		t.Errorf("SSID de una red oculta = %q", got[0].SSID)
	}
}

// Una captura Ethernet normal no debe adquirir campos WiFi ni posiciones.
func TestEthernetCaptureHasNoWiFiFields(t *testing.T) {
	var got []packet.Summary
	info, err := Read(context.Background(), writeTestPcap(t), func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.GPSFixes != 0 {
		t.Errorf("una captura Ethernet reportó %d posiciones", info.GPSFixes)
	}
	for _, s := range got {
		if s.SSID != "" || s.BSSID != "" || s.Channel != 0 || s.WiFiType != "" {
			t.Errorf("un paquete Ethernet trae campos WiFi: %+v", s)
		}
	}
}

// gopacket descuenta 4 bytes del final de toda trama 802.11 dando por hecho que
// hay una FCS. Muchas capturas se guardan sin ella, y entonces esos 4 bytes
// salen del cuerpo real: el último elemento de información de una baliza queda
// corto y la trama se marca ilegible. Comprobado con
// Network_Join_Nokia_Mobile.pcap (Wireshark SampleCaptures, link type 105):
// 96 tramas ilegibles y 647 balizas con error, todas recuperadas al detectar
// la ausencia de FCS.
func TestFramesWithoutFCSAreNotTruncated(t *testing.T) {
	bssid := net.HardwareAddr{0x74, 0x4d, 0x28, 0x88, 0xd9, 0xa4}
	path := writePcapOf(t, "sin-fcs.pcap", layers.LinkTypeIEEE802_11, [][]byte{
		beacon("SinFCS", 6, bssid),
		ack(bssid),
	})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 {
		t.Errorf("%d tramas ilegibles sin FCS", info.Undecodable)
	}
	if len(got) != 2 {
		t.Fatalf("se entregaron %d tramas", len(got))
	}
	if got[0].SSID != "SinFCS" || got[0].Channel != 6 {
		t.Errorf("la baliza perdió datos: ssid=%q canal=%d", got[0].SSID, got[0].Channel)
	}
	if got[0].Err != "" {
		t.Errorf("la baliza llegó con error: %q", got[0].Err)
	}
	// Un ACK son 10 bytes justos; sin el arreglo gopacket lo rechaza entero.
	if got[1].WiFiType != "control" {
		t.Errorf("el ACK no se decodificó: tipo=%q err=%q", got[1].WiFiType, got[1].Err)
	}
}

// La otra mitad del trato: una trama que sí trae su FCS no debe recibir relleno,
// o se le añadirían 4 bytes de más y el cuerpo volvería a descuadrar.
func TestFramesWithRealFCSAreLeftAlone(t *testing.T) {
	bssid := net.HardwareAddr{0x00, 0x0c, 0x41, 0x82, 0xb2, 0x55}
	path := writePcapOf(t, "con-fcs.pcap", layers.LinkTypeIEEE802_11, [][]byte{
		withFCS(beacon("ConFCS", 11, bssid)),
	})

	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 {
		t.Errorf("%d tramas ilegibles con FCS válida", info.Undecodable)
	}
	if len(got) != 1 || got[0].SSID != "ConFCS" || got[0].Channel != 11 {
		t.Fatalf("la baliza con FCS se leyó mal: %+v", got)
	}
	if got[0].Err != "" {
		t.Errorf("la baliza con FCS llegó con error: %q", got[0].Err)
	}
}

func TestPrismFrameWithRealFCSIsLeftAlone(t *testing.T) {
	bssid := net.HardwareAddr{0x00, 0x0c, 0x41, 0x82, 0xb2, 0x55}
	path := writePcapOf(t, "prism-con-fcs.pcap", layers.LinkTypePrismHeader, [][]byte{
		prism(withFCS(beacon("PrismFCS", 36, bssid))),
	})
	var got []packet.Summary
	info, err := Read(context.Background(), path, func(s packet.Summary) { got = append(got, s) }, Options{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.Undecodable != 0 || len(got) != 1 || got[0].SSID != "PrismFCS" || got[0].Channel != 36 || got[0].Err != "" {
		t.Fatalf("la trama Prism con FCS se leyó mal: info=%+v paquetes=%+v", info, got)
	}
}
