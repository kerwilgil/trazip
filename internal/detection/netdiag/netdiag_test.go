package netdiag

import (
	"encoding/json"
	"strings"
	"testing"

	"trazip/internal/packet"
)

// frame builds a summary with the link-layer fields the detector needs.
func frame(t float64, srcMAC, dstMAC, src, dst string, ipID uint16, length int) packet.Summary {
	return packet.Summary{
		TimeUnix: t, SrcMAC: srcMAC, DstMAC: dstMAC, Src: src, Dst: dst,
		IPID: ipID, Length: length, EtherType: "IPv4", Proto: "UDP", Transport: "udp",
	}
}

func TestLoopDetectedOnRepeatedIdenticalFrame(t *testing.T) {
	d := New()
	// La misma trama exacta volviendo cuatro veces en 40 ms.
	for i := 0; i < 4; i++ {
		d.Add(frame(1000.0+float64(i)*0.01, "74:4d:28:88:d9:a3", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", 4242, 120))
	}
	r := d.Result()
	if r.LoopedFrames != 4 {
		t.Errorf("LoopedFrames = %d, want 4", r.LoopedFrames)
	}
	var loop *Finding
	for i := range r.Findings {
		if r.Findings[i].Kind == "loop" {
			loop = &r.Findings[i]
		}
	}
	if loop == nil {
		t.Fatal("no se detectó el bucle")
	}
	if loop.Subject != "74:4d:28:88:d9:a3" || loop.Severity != "high" {
		t.Errorf("hallazgo = %+v", loop)
	}
	if loop.Caveat == "" {
		t.Error("un hallazgo de bucle debe declarar que no identifica el puerto físico")
	}
}

// Este es el falso positivo que importa: MNDP, mDNS y NetBIOS se emiten de
// forma periódica con contenido casi idéntico. No son un bucle, y el campo de
// identificación IPv4 es justamente lo que los distingue.
func TestPeriodicAnnouncementsAreNotALoop(t *testing.T) {
	d := New()
	for i := 0; i < 10; i++ {
		// Mismo emisor, mismo tamaño, distinto IP ID: emisiones nuevas.
		d.Add(frame(1000.0+float64(i)*60, "74:4d:28:88:d9:a3", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", uint16(100+i), 120))
	}
	r := d.Result()
	if r.LoopedFrames != 0 {
		t.Errorf("LoopedFrames = %d: anuncios periódicos no son un bucle", r.LoopedFrames)
	}
	for _, f := range r.Findings {
		if f.Kind == "loop" {
			t.Errorf("falso positivo de bucle: %+v", f)
		}
	}
}

func TestLoopSpreadOverTimeIsWeakerEvidence(t *testing.T) {
	d := New()
	// Mismo IP ID reapareciendo, pero repartido en 30 s: más probable que sea
	// un emisor que reutiliza identificadores que un bucle real.
	for i := 0; i < 4; i++ {
		d.Add(frame(1000.0+float64(i)*10, "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", "10.0.0.5", "255.255.255.255", 7, 64))
	}
	r := d.Result()
	for _, f := range r.Findings {
		if f.Kind == "loop" {
			if f.Severity != "medium" || f.Confidence >= 70 {
				t.Errorf("repeticiones espaciadas deberían bajar severidad/confianza: %+v", f)
			}
			return
		}
	}
	t.Fatal("se esperaba un hallazgo de bucle degradado, no ninguno")
}

func TestBroadcastStormRate(t *testing.T) {
	d := New()
	// 200 broadcasts en 2 s = 100/s, muy por encima del umbral.
	for i := 0; i < 200; i++ {
		d.Add(frame(500.0+float64(i)*0.01, "de:ad:be:ef:00:01", "ff:ff:ff:ff:ff:ff", "10.0.0.9", "255.255.255.255", uint16(i+1), 90))
	}
	r := d.Result()
	var storm *Finding
	for i := range r.Findings {
		if r.Findings[i].Kind == "broadcast_storm" {
			storm = &r.Findings[i]
		}
	}
	if storm == nil {
		t.Fatal("no se detectó la tormenta")
	}
	if storm.RatePerSec < 90 || storm.RatePerSec > 110 {
		t.Errorf("RatePerSec = %.1f, se esperaba ~100", storm.RatePerSec)
	}
	if storm.Severity != "high" {
		t.Errorf("severidad = %q, want high", storm.Severity)
	}
}

func TestQuietBroadcastIsNotAStorm(t *testing.T) {
	d := New()
	// Un ARP cada 5 s durante 5 minutos: chatter normal.
	for i := 0; i < 60; i++ {
		d.Add(frame(float64(i)*5, "de:ad:be:ef:00:02", "ff:ff:ff:ff:ff:ff", "10.0.0.10", "255.255.255.255", uint16(i+1), 60))
	}
	for _, f := range d.Result().Findings {
		if f.Kind == "broadcast_storm" {
			t.Errorf("falso positivo de tormenta: %+v", f)
		}
	}
}

func TestDuplicateIP(t *testing.T) {
	d := New()
	arp := func(mac, ip string) packet.Summary {
		return packet.Summary{TimeUnix: 1, SrcMAC: mac, DstMAC: "ff:ff:ff:ff:ff:ff", Src: ip, Proto: "ARP", EtherType: "ARP"}
	}
	d.Add(arp("aa:aa:aa:aa:aa:aa", "192.168.1.50"))
	d.Add(arp("bb:bb:bb:bb:bb:bb", "192.168.1.50"))
	d.Add(arp("cc:cc:cc:cc:cc:cc", "192.168.1.99")) // una sola MAC: normal

	var dup *Finding
	for i, f := range d.Result().Findings {
		if f.Kind == "duplicate_ip" {
			dup = &d.Result().Findings[i]
		}
	}
	if dup == nil {
		t.Fatal("no se detectó la IP duplicada")
	}
	if dup.Subject != "192.168.1.50" || dup.Count != 2 {
		t.Errorf("hallazgo = %+v", dup)
	}
	if !strings.Contains(dup.Caveat, "envenenamiento") {
		t.Error("debe advertir que no distingue conflicto de ARP spoofing")
	}
}

func TestRogueDHCPNeedsTwoServers(t *testing.T) {
	srv := func(mac string) packet.Summary {
		return packet.Summary{TimeUnix: 1, SrcMAC: mac, DstMAC: "ff:ff:ff:ff:ff:ff", Transport: "udp", SrcPort: 67, DstPort: 68, Proto: "DHCP"}
	}
	// Un solo servidor: normal, sin hallazgo.
	d := New()
	d.Add(srv("74:4d:28:00:00:01"))
	for _, f := range d.Result().Findings {
		if f.Kind == "rogue_dhcp" {
			t.Fatalf("un solo servidor DHCP no debería reportarse: %+v", f)
		}
	}
	// Dos servidores distintos: hallazgo.
	d.Add(srv("00:11:22:33:44:55"))
	found := false
	for _, f := range d.Result().Findings {
		if f.Kind == "rogue_dhcp" {
			found = true
		}
	}
	if !found {
		t.Error("dos servidores DHCP deberían dispararlo")
	}
}

func TestNeighborDiscovery(t *testing.T) {
	d := New()
	d.Add(packet.Summary{
		TimeUnix: 1, SrcMAC: "74:4d:28:88:d9:a3", DstMAC: "ff:ff:ff:ff:ff:ff",
		Src: "192.168.1.1", Transport: "udp", SrcPort: 5678, DstPort: 5678, Proto: "UDP", EtherType: "IPv4",
	})
	d.Add(packet.Summary{TimeUnix: 2, SrcMAC: "00:aa:bb:cc:dd:ee", DstMAC: "01:80:c2:00:00:0e", EtherType: "LinkLayerDiscovery", Proto: "LLDP"})

	r := d.Result()
	if len(r.Neighbors) != 2 {
		t.Fatalf("vecinos = %d (%+v), want 2", len(r.Neighbors), r.Neighbors)
	}
	byProto := map[string]Neighbor{}
	for _, n := range r.Neighbors {
		byProto[n.Protocol] = n
	}
	if byProto["MNDP"].MAC != "74:4d:28:88:d9:a3" || byProto["MNDP"].IP != "192.168.1.1" {
		t.Errorf("MNDP = %+v", byProto["MNDP"])
	}
	if byProto["LLDP"].MAC != "00:aa:bb:cc:dd:ee" {
		t.Errorf("LLDP = %+v", byProto["LLDP"])
	}
}

// El contrato con el frontend: los arreglos vacíos deben serializar como []
// y nunca como null. Un slice nil de Go marshalea a null, y un .map() sobre
// null tumba la vista — exactamente el fallo que ya se corrigió en Scanner.
func TestEmptyResultMarshalsArraysNotNull(t *testing.T) {
	raw, err := json.Marshal(New().Result())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	if strings.Contains(s, `"findings":null`) || strings.Contains(s, `"neighbors":null`) {
		t.Errorf("los arreglos vacíos deben ser [] y no null: %s", s)
	}
	if !strings.Contains(s, `"findings":[]`) || !strings.Contains(s, `"neighbors":[]`) {
		t.Errorf("faltan los arreglos vacíos: %s", s)
	}
}

func TestIgnoresPacketsWithoutLinkLayer(t *testing.T) {
	d := New()
	d.Add(packet.Summary{TimeUnix: 1, Src: "10.0.0.1", Dst: "10.0.0.2", IPID: 5, Length: 60})
	if r := d.Result(); r.Frames != 0 {
		t.Errorf("un paquete sin capa 2 no debería contarse, Frames = %d", r.Frames)
	}
}
