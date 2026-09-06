// Package netdiag is TRAZIP's passive layer-2 health detector: it looks at
// traffic already captured (local NIC, TZSP stream from a router, or a PCAP
// file) and reports segment-wide faults — switching loops, broadcast storms,
// duplicate IPs and unauthorized DHCP servers — plus a passive inventory of
// managed devices that announce themselves.
//
// It is a sibling of internal/detection/scandetect and deliberately mirrors
// its shape (Detector.Add per packet, bounded state, Result with
// evidence-backed findings), so it plugs into the same three places that
// already render scan detections: PCAP Analyzer, Live Capture and the session
// report.
//
// Everything here is passive. Nothing is sent, and a finding never claims a
// physical switch port: from a capture you can prove a loop exists and which
// MAC feeds it, but the port needs SNMP or the switch's own tooling.
package netdiag

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"trazip/internal/packet"
)

const (
	// broadcastMAC is the L2 broadcast destination.
	broadcastMAC = "ff:ff:ff:ff:ff:ff"

	// loopRepeatThreshold is how many times an identical frame must reappear
	// before it is called a loop. Legitimate retransmissions repeat a few
	// times; a loop repeats the *same IPv4 identification field*, which a
	// healthy sender does not reuse inside a short window.
	loopRepeatThreshold = 3

	// broadcastRateThreshold is broadcasts per second from a single MAC above
	// which the traffic stops looking like normal discovery chatter. Normal
	// hosts sit far below this: ARP, mDNS, NetBIOS and MNDP are periodic.
	broadcastRateThreshold = 20.0

	// minBroadcastForRate avoids calling a storm from a 3-packet capture,
	// where dividing by a tiny duration produces a meaningless rate.
	minBroadcastForRate = 50

	maxTrackedFrames  = 200000
	maxTrackedSources = 8192
	maxFindings       = 200
	maxEvidence       = 8
)

// Finding is one evidence-backed layer-2 fault.
type Finding struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"` // loop | broadcast_storm | duplicate_ip | rogue_dhcp
	Severity   string   `json:"severity"`
	Confidence uint8    `json:"confidence"`
	Subject    string   `json:"subject"` // the MAC or IP the finding is about
	Count      int      `json:"count"`   // how many observations back it
	RatePerSec float64  `json:"ratePerSec,omitempty"`
	Evidence   []string `json:"evidence"`
	Summary    string   `json:"summary"`
	Explain    string   `json:"explain"`
	Caveat     string   `json:"caveat,omitempty"`
}

// Neighbor is a managed device that announced itself on the segment.
type Neighbor struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip,omitempty"`
	Protocol string `json:"protocol"` // MNDP | LLDP | CDP
	Vendor   string `json:"vendor,omitempty"`
	Count    int    `json:"count"`
}

// Result is everything one capture revealed about the segment's health.
type Result struct {
	Frames       int        `json:"frames"`
	Broadcasts   int        `json:"broadcasts"`
	LoopedFrames int        `json:"loopedFrames"`
	Findings     []Finding  `json:"findings"`
	Neighbors    []Neighbor `json:"neighbors"`
	Truncated    bool       `json:"truncated"`
}

type frameSeen struct {
	count    int
	firstSec float64
	lastSec  float64
	sample   string
}

type sourceStat struct {
	broadcasts int
	firstSec   float64
	lastSec    float64
	sampleDst  string
	sampleInfo string
}

type ipClaim struct {
	macs  map[string]int
	order []string
}

// Detector accumulates bounded state across a capture.
type Detector struct {
	frames    map[string]*frameSeen
	sources   map[string]*sourceStat
	ipClaims  map[string]*ipClaim
	dhcpSrv   map[string]int
	neighbors map[string]*Neighbor

	total      int
	broadcasts int
	truncated  bool
}

// New returns an empty detector.
func New() *Detector {
	return &Detector{
		frames:    make(map[string]*frameSeen),
		sources:   make(map[string]*sourceStat),
		ipClaims:  make(map[string]*ipClaim),
		dhcpSrv:   make(map[string]int),
		neighbors: make(map[string]*Neighbor),
	}
}

// Add observes one packet summary.
func (d *Detector) Add(s packet.Summary) {
	if s.SrcMAC == "" {
		return // no link layer: nothing here applies
	}
	d.total++

	d.observeLoop(s)
	d.observeBroadcast(s)
	d.observeARP(s)
	d.observeDHCP(s)
	d.observeNeighbor(s)
}

// observeLoop counts identical flooded frames.
//
// Only broadcast and multicast destinations are considered, and that
// restriction is the whole reason this detector is usable. An earlier version
// looked at every frame and drowned in false positives on a real capture:
// unicast traffic forwarded by a router repeats the same source MAC,
// destination MAC and length constantly, and RFC 6864 explicitly allows a
// sender to put anything in the IPv4 identification field once DF is set — so
// CDN downloads (QUIC on UDP/443, 1460-byte payloads) looked exactly like a
// frame coming back around a loop.
//
// Restricting to flooded traffic matches where a layer-2 loop actually does
// damage, and there a repeated identical frame is unambiguous: a switch loop
// re-floods the same broadcast, while a host sending a new announcement
// produces a new IPv4 identification value.
func (d *Detector) observeLoop(s packet.Summary) {
	if s.IPID == 0 {
		return // non-IPv4 or no ID: this heuristic does not apply
	}
	if !isFlooded(s.DstMAC) {
		return
	}
	key := fmt.Sprintf("%s|%s|%d|%d|%s", s.SrcMAC, s.DstMAC, s.IPID, s.Length, s.EtherType)
	f := d.frames[key]
	if f == nil {
		if len(d.frames) >= maxTrackedFrames {
			d.truncated = true
			return
		}
		f = &frameSeen{firstSec: s.TimeUnix, sample: describe(s)}
		d.frames[key] = f
	}
	f.count++
	f.lastSec = s.TimeUnix
}

func (d *Detector) observeBroadcast(s packet.Summary) {
	if !strings.EqualFold(s.DstMAC, broadcastMAC) {
		return
	}
	d.broadcasts++
	st := d.sources[s.SrcMAC]
	if st == nil {
		if len(d.sources) >= maxTrackedSources {
			d.truncated = true
			return
		}
		st = &sourceStat{firstSec: s.TimeUnix, sampleDst: s.Dst, sampleInfo: describe(s)}
		d.sources[s.SrcMAC] = st
	}
	st.broadcasts++
	st.lastSec = s.TimeUnix
}

// observeARP records which MACs claim which IP. Two MACs claiming one IP is
// either a duplicate-address misconfiguration or ARP spoofing — the capture
// alone cannot tell which, which the finding says explicitly.
func (d *Detector) observeARP(s packet.Summary) {
	if s.Proto != "ARP" || s.Src == "" || s.Src == "0.0.0.0" {
		return
	}
	c := d.ipClaims[s.Src]
	if c == nil {
		if len(d.ipClaims) >= maxTrackedSources {
			d.truncated = true
			return
		}
		c = &ipClaim{macs: make(map[string]int)}
		d.ipClaims[s.Src] = c
	}
	if _, seen := c.macs[s.SrcMAC]; !seen {
		c.order = append(c.order, s.SrcMAC)
	}
	c.macs[s.SrcMAC]++
}

// observeDHCP tracks which MACs act as a DHCP server (traffic sourced from
// UDP/67). More than one on a segment is the classic cause of intermittent
// "the internet drops" with no obvious culprit.
func (d *Detector) observeDHCP(s packet.Summary) {
	if s.Transport != "udp" || s.SrcPort != 67 {
		return
	}
	if len(d.dhcpSrv) >= maxTrackedSources {
		d.truncated = true
		return
	}
	d.dhcpSrv[s.SrcMAC]++
}

// observeNeighbor collects managed devices that announce themselves. MNDP is
// identified by its UDP port; LLDP and CDP by their link-layer type. Only the
// presence, MAC and IP are recorded — the device name and port live deeper in
// the payload than the summary carries, so they are not claimed here.
func (d *Detector) observeNeighbor(s packet.Summary) {
	proto := ""
	switch {
	case s.Transport == "udp" && (s.DstPort == 5678 || s.SrcPort == 5678):
		proto = "MNDP"
	case strings.Contains(strings.ToLower(s.EtherType), "linklayerdiscovery"):
		proto = "LLDP"
	case strings.Contains(strings.ToLower(s.Proto), "ciscodiscovery"):
		proto = "CDP"
	}
	if proto == "" {
		return
	}
	key := s.SrcMAC + "|" + proto
	n := d.neighbors[key]
	if n == nil {
		if len(d.neighbors) >= maxTrackedSources {
			d.truncated = true
			return
		}
		n = &Neighbor{MAC: s.SrcMAC, Protocol: proto}
		d.neighbors[key] = n
	}
	n.Count++
	if n.IP == "" && s.Src != "" && s.Src != s.SrcMAC {
		n.IP = s.Src
	}
}

// Result builds the findings from everything observed so far.
func (d *Detector) Result() Result {
	r := Result{Frames: d.total, Broadcasts: d.broadcasts, Truncated: d.truncated}

	r.Findings = append(r.Findings, d.loopFindings(&r)...)
	r.Findings = append(r.Findings, d.stormFindings()...)
	r.Findings = append(r.Findings, d.duplicateIPFindings()...)
	r.Findings = append(r.Findings, d.rogueDHCPFindings()...)

	// Most severe first, then by weight of evidence.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		si, sj := severityRank(r.Findings[i].Severity), severityRank(r.Findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return r.Findings[i].Count > r.Findings[j].Count
	})
	if len(r.Findings) > maxFindings {
		r.Findings = r.Findings[:maxFindings]
		r.Truncated = true
	}

	for _, n := range d.neighbors {
		r.Neighbors = append(r.Neighbors, *n)
	}
	sort.SliceStable(r.Neighbors, func(i, j int) bool {
		if r.Neighbors[i].Protocol != r.Neighbors[j].Protocol {
			return r.Neighbors[i].Protocol < r.Neighbors[j].Protocol
		}
		return r.Neighbors[i].MAC < r.Neighbors[j].MAC
	})
	// A nil slice marshals to JSON null, which the views would have to guard
	// on every render; empty slices keep the contract "always an array".
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	if r.Neighbors == nil {
		r.Neighbors = []Neighbor{}
	}
	return r
}

func (d *Detector) loopFindings(r *Result) []Finding {
	var out []Finding
	for key, f := range d.frames {
		if f.count < loopRepeatThreshold {
			continue
		}
		r.LoopedFrames += f.count
		src := strings.SplitN(key, "|", 2)[0]
		span := f.lastSec - f.firstSec
		conf := uint8(70)
		sev := "high"
		if f.count >= loopRepeatThreshold*3 {
			conf = 90
		}
		// Repeats spread over a long capture are far weaker evidence than the
		// same frame coming back within a second.
		if span > 5 {
			conf = 55
			sev = "medium"
		}
		out = append(out, Finding{
			ID:         "loop:" + key,
			Kind:       "loop",
			Severity:   sev,
			Confidence: conf,
			Subject:    src,
			Count:      f.count,
			Evidence:   []string{f.sample, fmt.Sprintf("la misma trama reapareció %d veces en %.2f s", f.count, span)},
			Summary:    fmt.Sprintf("Trama idéntica repetida %d veces desde %s", f.count, src),
			Explain: "Una trama con la misma MAC origen, MAC destino, identificación IPv4 y longitud reapareció varias veces. " +
				"Un emisor sano no reutiliza el campo de identificación IPv4 en una ventana corta, así que lo esperable es que " +
				"la trama esté dando vueltas por un bucle de capa 2.",
			Caveat: "La captura demuestra que el bucle existe y qué MAC lo alimenta, no en qué puerto ni en qué switch se cierra.",
		})
	}
	return out
}

func (d *Detector) stormFindings() []Finding {
	var out []Finding
	for mac, st := range d.sources {
		if st.broadcasts < minBroadcastForRate {
			continue
		}
		span := st.lastSec - st.firstSec
		if span <= 0 {
			continue
		}
		rate := float64(st.broadcasts) / span
		if rate < broadcastRateThreshold {
			continue
		}
		sev := "medium"
		conf := uint8(70)
		if rate >= broadcastRateThreshold*5 {
			sev = "high"
			conf = 85
		}
		out = append(out, Finding{
			ID:         "storm:" + mac,
			Kind:       "broadcast_storm",
			Severity:   sev,
			Confidence: conf,
			Subject:    mac,
			Count:      st.broadcasts,
			RatePerSec: rate,
			Evidence:   []string{st.sampleInfo, fmt.Sprintf("%d broadcasts en %.1f s = %.1f/s", st.broadcasts, span, rate)},
			Summary:    fmt.Sprintf("%s emite %.0f broadcasts por segundo", mac, rate),
			Explain: "El tráfico de descubrimiento normal (ARP, mDNS, NetBIOS, MNDP) es periódico y de baja tasa. " +
				"Un ritmo sostenido muy por encima de eso satura el dominio de difusión: todos los equipos del segmento " +
				"procesan cada trama, lo que degrada la red aunque el enlace WAN esté libre.",
			Caveat: "Un equipo puede emitir mucho broadcast legítimamente (por ejemplo un servidor de descubrimiento); confirmá qué es antes de desconectarlo.",
		})
	}
	return out
}

func (d *Detector) duplicateIPFindings() []Finding {
	var out []Finding
	for ip, c := range d.ipClaims {
		if len(c.macs) < 2 {
			continue
		}
		ev := make([]string, 0, maxEvidence)
		total := 0
		for _, mac := range c.order {
			if len(ev) < maxEvidence {
				ev = append(ev, fmt.Sprintf("%s anunció %s en %d ARP", mac, ip, c.macs[mac]))
			}
			total += c.macs[mac]
		}
		out = append(out, Finding{
			ID:         "dupip:" + ip,
			Kind:       "duplicate_ip",
			Severity:   "high",
			Confidence: 85,
			Subject:    ip,
			Count:      total,
			Evidence:   ev,
			Summary:    fmt.Sprintf("%d MAC distintas reclaman la IP %s", len(c.macs), ip),
			Explain: "Dos equipos respondiendo por la misma dirección hacen que el tráfico se reparta entre ambos de forma " +
				"impredecible, según qué respuesta ARP llegó última a cada vecino. Es una causa habitual de cortes " +
				"intermitentes que aparecen y desaparecen sin patrón claro.",
			Caveat: "Una captura no distingue un conflicto de direcciones por configuración de un envenenamiento ARP deliberado. " +
				"Verificá primero la configuración de ambos equipos.",
		})
	}
	return out
}

func (d *Detector) rogueDHCPFindings() []Finding {
	if len(d.dhcpSrv) < 2 {
		return nil
	}
	ev := make([]string, 0, maxEvidence)
	total := 0
	macs := make([]string, 0, len(d.dhcpSrv))
	for mac := range d.dhcpSrv {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		if len(ev) < maxEvidence {
			ev = append(ev, fmt.Sprintf("%s respondió como servidor DHCP %d veces", mac, d.dhcpSrv[mac]))
		}
		total += d.dhcpSrv[mac]
	}
	return []Finding{{
		ID:         "dhcp:multiple",
		Kind:       "rogue_dhcp",
		Severity:   "high",
		Confidence: 80,
		Subject:    strings.Join(macs, ", "),
		Count:      total,
		Evidence:   ev,
		Summary:    fmt.Sprintf("%d equipos distintos actúan como servidor DHCP", len(macs)),
		Explain: "En un segmento debería responder un solo servidor DHCP. Si hay varios, los clientes toman la " +
			"configuración del que conteste primero, que puede traer gateway o DNS equivocados. El síntoma típico es " +
			"que unos equipos navegan y otros no, sin relación aparente.",
		Caveat: "Una red con servidores DHCP redundantes por diseño también dispara este hallazgo; comparalo con la configuración esperada.",
	}}
}

func describe(s packet.Summary) string {
	dst := s.Dst
	if dst == "" {
		dst = s.DstMAC
	}
	if s.Info != "" {
		return fmt.Sprintf("%s → %s · %s · %s", s.Src, dst, s.Proto, s.Info)
	}
	return fmt.Sprintf("%s → %s · %s", s.Src, dst, s.Proto)
}

// isFlooded reports whether a destination MAC is one a switch floods to every
// port: the broadcast address, or any multicast address (least significant bit
// of the first octet set).
func isFlooded(mac string) bool {
	if strings.EqualFold(mac, broadcastMAC) {
		return true
	}
	if len(mac) < 2 {
		return false
	}
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil {
		return false
	}
	return first&0x01 == 1
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
