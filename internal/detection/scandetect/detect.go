// Package scandetect detects scan-shaped TCP activity in packet summaries.
// It is passive: it never opens sockets or sends packets. The same streaming
// detector is used for files, local live capture and TZSP traffic.
package scandetect

import (
	"fmt"
	"sort"
	"strings"

	"trazip/internal/packet"
)

const (
	verticalThreshold   = 10
	horizontalThreshold = 10
	maxGroups           = 10000
	maxFindings         = 200
	maxEvidenceValues   = 32
	maxDistinctPerGroup = 4096
	maxObservations     = 250000
)

// Finding is one evidence-backed scan pattern observed in traffic.
type Finding struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // vertical | horizontal
	Severity    string   `json:"severity"`
	Confidence  uint8    `json:"confidence"`
	Source      string   `json:"source"`
	Target      string   `json:"target,omitempty"`
	Port        uint16   `json:"port,omitempty"`
	Distinct    int      `json:"distinct"`
	Attempts    int      `json:"attempts"`
	FirstSeen   string   `json:"firstSeen,omitempty"`
	LastSeen    string   `json:"lastSeen,omitempty"`
	DurationSec float64  `json:"durationSec"`
	Ports       []uint16 `json:"ports,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	Summary     string   `json:"summary"`
	Explain     string   `json:"explain"`
	MITRE       string   `json:"mitre"`
}

// Result summarizes all scan-shaped activity observed by a Detector.
type Result struct {
	InitialSYN int       `json:"initialSyn"`
	Vertical   int       `json:"vertical"`
	Horizontal int       `json:"horizontal"`
	Findings   []Finding `json:"findings"`
	Truncated  bool      `json:"truncated"`
}

type group struct {
	source   string
	target   string
	port     uint16
	attempts int
	first    string
	last     string
	firstSec float64
	lastSec  float64
	ports    map[uint16]struct{}
	targets  map[string]struct{}
}

// Detector accepts packet summaries incrementally and keeps bounded state.
type Detector struct {
	vertical   map[string]*group
	horizontal map[string]*group
	initialSYN int
	truncated  bool
}

// New returns an empty passive detector.
func New() *Detector {
	return &Detector{
		vertical:   make(map[string]*group),
		horizontal: make(map[string]*group),
	}
}

// Add observes one packet. Only initial TCP SYN packets (SYN without ACK)
// contribute to scan detection, avoiding established connections and replies.
func (d *Detector) Add(s packet.Summary) {
	if !isInitialSYN(s) || s.Src == "" || s.Dst == "" || s.DstPort == 0 {
		return
	}
	if d.initialSYN >= maxObservations {
		d.truncated = true
		return
	}
	d.initialSYN++

	vk := s.Src + "\x00" + s.Dst
	vg := d.vertical[vk]
	if vg == nil {
		if len(d.vertical) >= maxGroups {
			d.truncated = true
		} else {
			vg = &group{source: s.Src, target: s.Dst, ports: make(map[uint16]struct{})}
			d.vertical[vk] = vg
		}
	}
	if vg != nil {
		if len(vg.ports) < maxDistinctPerGroup {
			vg.ports[s.DstPort] = struct{}{}
		} else {
			d.truncated = true
		}
		observeTime(vg, s)
	}

	hk := s.Src + "\x00" + fmt.Sprint(s.DstPort)
	hg := d.horizontal[hk]
	if hg == nil {
		if len(d.horizontal) >= maxGroups {
			d.truncated = true
		} else {
			hg = &group{source: s.Src, port: s.DstPort, targets: make(map[string]struct{})}
			d.horizontal[hk] = hg
		}
	}
	if hg != nil {
		if len(hg.targets) < maxDistinctPerGroup {
			hg.targets[s.Dst] = struct{}{}
		} else {
			d.truncated = true
		}
		observeTime(hg, s)
	}
}

func observeTime(g *group, s packet.Summary) {
	g.attempts++
	if g.first == "" || (s.TimeUnix > 0 && s.TimeUnix < g.firstSec) {
		g.first, g.firstSec = s.Time, s.TimeUnix
	}
	if g.last == "" || s.TimeUnix > g.lastSec {
		g.last, g.lastSec = s.Time, s.TimeUnix
	}
}

// Result builds a stable, severity-sorted snapshot of current detections.
func (d *Detector) Result() Result {
	findings := make([]Finding, 0)
	for _, g := range d.vertical {
		if len(g.ports) < verticalThreshold {
			continue
		}
		ports := sortedPorts(g.ports)
		distinct := len(ports)
		f := baseFinding("vertical", g, distinct)
		f.ID = "vertical:" + g.source + ":" + g.target
		f.Target = g.target
		f.Ports = samplePorts(ports)
		f.Summary = fmt.Sprintf("%s probó %d puertos TCP en %s", g.source, distinct, g.target)
		f.Explain = "Múltiples SYN iniciales desde un origen hacia puertos distintos del mismo objetivo. Puede ser inventario autorizado o reconocimiento; valide el alcance y el proceso que lo originó."
		findings = append(findings, f)
	}
	for _, g := range d.horizontal {
		if len(g.targets) < horizontalThresholdForPort(g.port) {
			continue
		}
		targets := sortedTargets(g.targets)
		distinct := len(targets)
		f := baseFinding("horizontal", g, distinct)
		f.ID = fmt.Sprintf("horizontal:%s:%d", g.source, g.port)
		f.Port = g.port
		f.Targets = sampleTargets(targets)
		f.Summary = fmt.Sprintf("%s probó el puerto TCP %d en %d objetivos", g.source, g.port, distinct)
		f.Explain = "Múltiples SYN iniciales desde un origen hacia el mismo puerto en destinos distintos. Puede ser descubrimiento autorizado o un barrido lateral; valide el alcance y el proceso que lo originó."
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		if findings[i].Attempts != findings[j].Attempts {
			return findings[i].Attempts > findings[j].Attempts
		}
		return findings[i].ID < findings[j].ID
	})
	if len(findings) > maxFindings {
		findings = findings[:maxFindings]
		d.truncated = true
	}
	res := Result{InitialSYN: d.initialSYN, Findings: findings, Truncated: d.truncated}
	for _, f := range findings {
		if f.Kind == "vertical" {
			res.Vertical++
		} else {
			res.Horizontal++
		}
	}
	return res
}

func baseFinding(kind string, g *group, distinct int) Finding {
	duration := g.lastSec - g.firstSec
	if duration < 0 {
		duration = 0
	}
	confidence := uint8(70)
	switch {
	case distinct >= 100:
		confidence = 95
	case distinct >= 50:
		confidence = 90
	case distinct >= 20:
		confidence = 82
	}
	severity := "medium"
	if duration > 300 || ((g.port == 80 || g.port == 443) && kind == "horizontal") {
		severity = "low"
		if confidence > 55 {
			confidence = 55
		}
	} else if distinct >= 100 || (duration > 0 && float64(g.attempts)/duration >= 100) {
		severity = "high"
	}
	return Finding{
		Kind: kind, Severity: severity, Confidence: confidence, Source: g.source,
		Distinct: distinct, Attempts: g.attempts, FirstSeen: g.first, LastSeen: g.last,
		DurationSec: duration, MITRE: "T1046 Network Service Discovery",
	}
}

func horizontalThresholdForPort(port uint16) int {
	// Browsers and update agents legitimately fan out to many web frontends.
	// Keep those patterns visible only at substantially higher cardinality.
	if port == 80 || port == 443 {
		return 50
	}
	return horizontalThreshold
}

func isInitialSYN(s packet.Summary) bool {
	if !strings.EqualFold(s.Transport, "tcp") {
		return false
	}
	hasSYN, hasACK := false, false
	for _, f := range s.TCPFlags {
		switch strings.ToUpper(f) {
		case "SYN":
			hasSYN = true
		case "ACK":
			hasACK = true
		}
	}
	return hasSYN && !hasACK
}

func sortedPorts(set map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedTargets(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for target := range set {
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func samplePorts(in []uint16) []uint16 {
	if len(in) > maxEvidenceValues {
		in = in[:maxEvidenceValues]
	}
	return append([]uint16(nil), in...)
}

func sampleTargets(in []string) []string {
	if len(in) > maxEvidenceValues {
		in = in[:maxEvidenceValues]
	}
	return append([]string(nil), in...)
}
