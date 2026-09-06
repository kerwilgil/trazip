package ipcalc

import (
	"strings"
	"testing"
)

func TestAnalyzeIPv4Typical(t *testing.T) {
	got, err := Analyze("192.168.10.77/26")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	checks := map[string]string{
		"Family":      got.Family,
		"Network":     got.Network,
		"Broadcast":   got.Broadcast,
		"FirstHost":   got.FirstHost,
		"LastHost":    got.LastHost,
		"Netmask":     got.Netmask,
		"Wildcard":    got.Wildcard,
		"TotalCount":  got.TotalCount,
		"UsableCount": got.UsableCount,
		"Class":       got.Class,
		"ReverseZone": got.ReverseZone,
		"PTR":         got.PTR,
		"Decimal":     got.Decimal,
	}
	want := map[string]string{
		"Family":      "IPv4",
		"Network":     "192.168.10.64",
		"Broadcast":   "192.168.10.127",
		"FirstHost":   "192.168.10.65",
		"LastHost":    "192.168.10.126",
		"Netmask":     "255.255.255.192",
		"Wildcard":    "0.0.0.63",
		"TotalCount":  "64",
		"UsableCount": "62",
		"Class":       "C",
		"ReverseZone": "64/26.10.168.192.in-addr.arpa",
		"PTR":         "77.10.168.192.in-addr.arpa",
		"Decimal":     "3232238157",
	}
	for k, w := range want {
		if checks[k] != w {
			t.Errorf("%s = %q, want %q", k, checks[k], w)
		}
	}
	if !strings.HasPrefix(got.AddrBinary, "11000000.10101000.") {
		t.Errorf("AddrBinary = %q", got.AddrBinary)
	}
	if got.IsPublic {
		t.Error("192.168.x.x no debería ser pública")
	}
}

func TestAnalyzeSlash31And32(t *testing.T) {
	p2p, err := Analyze("10.0.0.4/31")
	if err != nil {
		t.Fatalf("/31: %v", err)
	}
	if p2p.UsableCount != "2" || p2p.Broadcast != "" {
		t.Errorf("/31 usable=%q broadcast=%q, want 2 y sin broadcast", p2p.UsableCount, p2p.Broadcast)
	}
	if p2p.FirstHost != "10.0.0.4" || p2p.LastHost != "10.0.0.5" {
		t.Errorf("/31 rango = %s..%s, want 10.0.0.4..10.0.0.5", p2p.FirstHost, p2p.LastHost)
	}

	host, err := Analyze("10.0.0.7/32")
	if err != nil {
		t.Fatalf("/32: %v", err)
	}
	if host.UsableCount != "1" || host.Broadcast != "" {
		t.Errorf("/32 usable=%q broadcast=%q, want 1 y sin broadcast", host.UsableCount, host.Broadcast)
	}
	if host.FirstHost != "10.0.0.7" || host.LastHost != "10.0.0.7" {
		t.Errorf("/32 rango = %s..%s", host.FirstHost, host.LastHost)
	}
}

func TestAnalyzeSlashZeroAndEightBit(t *testing.T) {
	all, err := Analyze("0.0.0.0/0")
	if err != nil {
		t.Fatalf("/0: %v", err)
	}
	if all.TotalCount != "4294967296" {
		t.Errorf("/0 total = %q, want 4294967296", all.TotalCount)
	}
	if all.Broadcast != "255.255.255.255" {
		t.Errorf("/0 broadcast = %q", all.Broadcast)
	}

	eight, err := Analyze("10.1.2.3/8")
	if err != nil {
		t.Fatalf("/8: %v", err)
	}
	if eight.Network != "10.0.0.0" || eight.Broadcast != "10.255.255.255" {
		t.Errorf("/8 = %s..%s", eight.Network, eight.Broadcast)
	}
	if eight.ReverseZone != "10.in-addr.arpa" {
		t.Errorf("/8 zona = %q", eight.ReverseZone)
	}
	if eight.UsableCount != "16777214" {
		t.Errorf("/8 usable = %q, want 16777214", eight.UsableCount)
	}
}

func TestAnalyzeMaskForms(t *testing.T) {
	// Prefix length, dotted netmask and wildcard must all reach the same answer.
	for _, in := range []string{
		"192.168.1.10/24",
		"192.168.1.10 255.255.255.0",
		"192.168.1.10/255.255.255.0",
		"192.168.1.10 0.0.0.255",
	} {
		got, err := Analyze(in)
		if err != nil {
			t.Fatalf("Analyze(%q): %v", in, err)
		}
		if got.PrefixLen != 24 || got.Network != "192.168.1.0" || got.Broadcast != "192.168.1.255" {
			t.Errorf("Analyze(%q) = /%d %s..%s", in, got.PrefixLen, got.Network, got.Broadcast)
		}
	}
}

func TestAnalyzeRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "no-es-una-ip", "192.168.1.1/33", "10.0.0.1 255.0.255.0", "999.1.1.1"} {
		if _, err := Analyze(in); err == nil {
			t.Errorf("Analyze(%q) debería fallar", in)
		}
	}
}

func TestAnalyzeIPv6(t *testing.T) {
	got, err := Analyze("2001:db8::1/64")
	if err != nil {
		t.Fatalf("Analyze v6: %v", err)
	}
	if got.Family != "IPv6" {
		t.Errorf("Family = %q", got.Family)
	}
	if got.Network != "2001:db8::" {
		t.Errorf("Network = %q", got.Network)
	}
	if got.LastHost != "2001:db8::ffff:ffff:ffff:ffff" {
		t.Errorf("LastHost = %q", got.LastHost)
	}
	if got.TotalCount != "18446744073709551616" { // 2^64, mas alla de int64
		t.Errorf("TotalCount = %q, want 2^64", got.TotalCount)
	}
	if got.Expanded != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Errorf("Expanded = %q", got.Expanded)
	}
	if got.Broadcast != "" {
		t.Errorf("IPv6 no tiene broadcast, got %q", got.Broadcast)
	}
	if !strings.HasSuffix(got.PTR, ".ip6.arpa") {
		t.Errorf("PTR = %q", got.PTR)
	}
	// Un /64 delega 16 nibbles, no 8: 2001:0db8:0000:0000 invertido nibble a nibble.
	if got.ReverseZone != "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Errorf("ReverseZone = %q", got.ReverseZone)
	}
}

func TestSplit(t *testing.T) {
	res, err := Split("192.168.1.0/24", 26)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if res.Total != "4" || len(res.Rows) != 4 || res.Truncated {
		t.Fatalf("Split total=%q rows=%d truncated=%v", res.Total, len(res.Rows), res.Truncated)
	}
	wantNets := []string{"192.168.1.0", "192.168.1.64", "192.168.1.128", "192.168.1.192"}
	for i, w := range wantNets {
		if res.Rows[i].Network != w {
			t.Errorf("row %d network = %s, want %s", i, res.Rows[i].Network, w)
		}
		if res.Rows[i].UsableCount != "62" {
			t.Errorf("row %d usable = %s, want 62", i, res.Rows[i].UsableCount)
		}
	}
	if res.Rows[3].Broadcast != "192.168.1.255" {
		t.Errorf("ultimo broadcast = %s", res.Rows[3].Broadcast)
	}

	if _, err := Split("192.168.1.0/24", 20); err == nil {
		t.Error("dividir /24 en /20 debería fallar")
	}
}

func TestSplitTruncates(t *testing.T) {
	// A /8 split into /30s is ~4.2M subnets: the result must report the true
	// total while only materializing maxRows.
	res, err := Split("10.0.0.0/8", 30)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if res.Total != "4194304" {
		t.Errorf("Total = %q, want 4194304", res.Total)
	}
	if len(res.Rows) != maxRows || !res.Truncated {
		t.Errorf("rows = %d truncated = %v, want %d y true", len(res.Rows), res.Truncated, maxRows)
	}
}

func TestVLSM(t *testing.T) {
	res, err := VLSM("192.168.1.0/24", []VLSMRequest{
		{Label: "ventas", Hosts: 50},
		{Label: "wifi", Hosts: 100},
		{Label: "enlace", Hosts: 2},
	})
	if err != nil {
		t.Fatalf("VLSM: %v", err)
	}
	if len(res.Allocations) != 3 {
		t.Fatalf("allocations = %d, want 3", len(res.Allocations))
	}
	// Ordena de mayor a menor: wifi (/25) -> ventas (/26) -> enlace (/30).
	want := []struct {
		label  string
		prefix string
		usable int
	}{
		{"wifi", "192.168.1.0/25", 126},
		{"ventas", "192.168.1.128/26", 62},
		{"enlace", "192.168.1.192/30", 2},
	}
	for i, w := range want {
		a := res.Allocations[i]
		if a.Label != w.label || a.Prefix != w.prefix || a.UsableCount != w.usable {
			t.Errorf("alloc %d = %s %s (%d usables), want %s %s (%d)", i, a.Label, a.Prefix, a.UsableCount, w.label, w.prefix, w.usable)
		}
	}
	if res.Allocations[0].Waste != 26 { // 126 utiles - 100 pedidos
		t.Errorf("waste wifi = %d, want 26", res.Allocations[0].Waste)
	}
	if len(res.Remaining) == 0 {
		t.Error("deberia quedar espacio libre en el /24")
	}
}

func TestVLSMNoRoom(t *testing.T) {
	_, err := VLSM("192.168.1.0/28", []VLSMRequest{{Label: "grande", Hosts: 500}})
	if err == nil {
		t.Error("pedir 500 hosts en un /28 debería fallar")
	}
	if _, err := VLSM("2001:db8::/32", []VLSMRequest{{Label: "x", Hosts: 10}}); err == nil {
		t.Error("VLSM sobre IPv6 debería rechazarse explícitamente")
	}
}

func TestVLSMSlashZeroDoesNotPanicCalculatingRemainder(t *testing.T) {
	res, err := VLSM("0.0.0.0/0", []VLSMRequest{{Label: "segmento", Hosts: 2}})
	if err != nil {
		t.Fatalf("VLSM /0: %v", err)
	}
	if len(res.Allocations) != 1 || len(res.Remaining) == 0 {
		t.Fatalf("resultado incompleto: %+v", res)
	}
}

func TestPlanCustomerIPs(t *testing.T) {
	tests := []struct {
		name       string
		requested  uint64
		gateway    bool
		block      string
		total      uint64
		spare      uint64
		unassigned uint64
	}{
		{"una IP con gateway", 1, true, "/30", 4, 0, 3},
		{"dos IP con gateway", 2, true, "/29", 8, 3, 6},
		{"tres IP con gateway", 3, true, "/29", 8, 2, 5},
		{"cuatro IP con gateway", 4, true, "/29", 8, 1, 4},
		{"veinte IP con gateway", 20, true, "/27", 32, 9, 12},
		{"cuatro IP sin gateway", 4, false, "/29", 8, 2, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PlanCustomerIPs(tt.requested, tt.gateway)
			if err != nil {
				t.Fatalf("PlanCustomerIPs: %v", err)
			}
			if got.Block != tt.block || got.Total != tt.total || got.Spare != tt.spare ||
				got.NotAssignedToCustomer != tt.unassigned {
				t.Errorf("resultado = %+v; quiero bloque=%s total=%d libres=%d no-asignadas=%d",
					got, tt.block, tt.total, tt.spare, tt.unassigned)
			}
		})
	}
}

func TestPlanCustomerIPsRejectsInvalidAmounts(t *testing.T) {
	if _, err := PlanCustomerIPs(0, true); err == nil {
		t.Error("cero IP debería rechazarse")
	}
	if _, err := PlanCustomerIPs(uint64(1)<<32-2, true); err == nil {
		t.Error("un pedido que no deja espacio para gateway debería rechazarse")
	}
	if _, err := PlanCustomerIPs(^uint64(0), true); err == nil {
		t.Error("una cantidad que desborda IPv4 debería rechazarse sin overflow")
	}
}

func TestNeededBitsAndUsable(t *testing.T) {
	// neededBits nunca pasa de /30 a propósito (ver su doc): un plan con /31
	// no es desplegable en equipo que no soporte RFC 3021.
	cases := []struct{ hosts, bits int }{
		{1, 30}, {2, 30}, {3, 29}, {6, 29}, {50, 26}, {100, 25}, {254, 24}, {255, 23},
	}
	for _, c := range cases {
		if got := neededBits(c.hosts); got != c.bits {
			t.Errorf("neededBits(%d) = %d, want %d", c.hosts, got, c.bits)
		}
	}
	if usableV4(24) != 254 || usableV4(30) != 2 || usableV4(31) != 2 || usableV4(32) != 1 {
		t.Error("usableV4 con valores incorrectos")
	}
}

func TestAggregate(t *testing.T) {
	// Dos /25 hermanos colapsan al /24 padre.
	got, err := Aggregate([]string{"192.168.1.0/25", "192.168.1.128/25"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Errorf("hermanos = %v, want [192.168.1.0/24]", got)
	}

	// Contenido dentro de otro: se descarta el mas especifico.
	got, err = Aggregate([]string{"10.0.0.0/8", "10.1.2.0/24"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Errorf("contenido = %v, want [10.0.0.0/8]", got)
	}

	// No adyacentes: se conservan ambos.
	got, err = Aggregate([]string{"192.168.1.0/24", "192.168.3.0/24"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("no adyacentes = %v, want 2 prefijos", got)
	}

	// Familias mezcladas no se fusionan entre si.
	got, err = Aggregate([]string{"192.168.1.0/25", "192.168.1.128/25", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("Aggregate mixto: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("mixto = %v, want 2", got)
	}
}

func TestContains(t *testing.T) {
	in, err := Contains("192.168.1.0/24", "192.168.1.55")
	if err != nil || !in {
		t.Errorf("192.168.1.55 en /24: %v %v", in, err)
	}
	in, err = Contains("192.168.1.0/24", "192.168.2.1")
	if err != nil || in {
		t.Errorf("192.168.2.1 no está en /24: %v %v", in, err)
	}
	if _, err := Contains("192.168.1.0/24", "2001:db8::1"); err == nil {
		t.Error("comparar familias distintas debería fallar")
	}
}

func TestReverseZoneOctetBoundaries(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3/24": "2.1.10.in-addr.arpa",
		"10.1.2.3/16": "1.10.in-addr.arpa",
		"10.1.2.3/8":  "10.in-addr.arpa",
		"10.1.2.3/28": "0/28.2.1.10.in-addr.arpa",
	}
	for in, want := range cases {
		got, err := Analyze(in)
		if err != nil {
			t.Fatalf("Analyze(%q): %v", in, err)
		}
		if got.ReverseZone != want {
			t.Errorf("Analyze(%q).ReverseZone = %q, want %q", in, got.ReverseZone, want)
		}
	}
	// Un prefijo que no cae en limite de octeto no tiene zona propia.
	got, _ := Analyze("10.1.2.3/12")
	if !strings.Contains(got.ReverseZone, "varias zonas") {
		t.Errorf("/12 zona = %q, se esperaba la nota de multiples zonas", got.ReverseZone)
	}
}

func TestBareAddressDefaultsToHostPrefix(t *testing.T) {
	v4, err := Analyze("8.8.8.8")
	if err != nil {
		t.Fatalf("bare v4: %v", err)
	}
	if v4.PrefixLen != 32 || !v4.IsPublic {
		t.Errorf("8.8.8.8 = /%d public=%v", v4.PrefixLen, v4.IsPublic)
	}
	v6, err := Analyze("2001:db8::1")
	if err != nil {
		t.Fatalf("bare v6: %v", err)
	}
	if v6.PrefixLen != 128 {
		t.Errorf("v6 bare = /%d, want /128", v6.PrefixLen)
	}
}
