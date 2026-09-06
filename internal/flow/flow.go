// Package flow aggregates packet summaries into bidirectional flows keyed by the
// canonical 5-tuple (prompt maestro §8 Flow, §9 Fase 1 #7). A→B and B→A packets
// collapse into a single flow with per-direction counters.
package flow

import (
	"sort"
	"strconv"
	"strings"

	"trazip/internal/packet"
)

// Flow is a bidirectional conversation. Direction A→B is the side that sent the
// first observed packet.
type Flow struct {
	Proto       string   `json:"proto"` // tcp | udp | icmp | icmp6
	AAddr       string   `json:"aAddr"`
	APort       uint16   `json:"aPort,omitempty"`
	BAddr       string   `json:"bAddr"`
	BPort       uint16   `json:"bPort,omitempty"`
	PktsAB      int      `json:"pktsAB"`
	PktsBA      int      `json:"pktsBA"`
	BytesAB     int64    `json:"bytesAB"`
	BytesBA     int64    `json:"bytesBA"`
	Packets     int      `json:"packets"`
	Bytes       int64    `json:"bytes"`
	Start       string   `json:"start,omitempty"`
	End         string   `json:"end,omitempty"`
	DurationSec float64  `json:"durationSec"`
	Apps        []string `json:"apps,omitempty"`
	Resets      int      `json:"resets,omitempty"`

	startUnix float64
	endUnix   float64
	appSet    map[string]struct{}
}

// Table accumulates flows.
type Table struct {
	flows map[string]*Flow
	order []string
}

// New returns an empty flow table.
func New() *Table {
	return &Table{flows: make(map[string]*Flow)}
}

func endpoint(addr string, port uint16) string {
	return addr + ":" + strconv.FormatUint(uint64(port), 10)
}

// Add folds one packet summary into the table.
func (t *Table) Add(s packet.Summary) {
	if s.Transport == "" || s.Src == "" || s.Dst == "" {
		return
	}
	e1 := endpoint(s.Src, s.SrcPort)
	e2 := endpoint(s.Dst, s.DstPort)
	key := s.Transport + "|" + minStr(e1, e2) + "|" + maxStr(e1, e2)

	f := t.flows[key]
	if f == nil {
		f = &Flow{
			Proto:     s.Transport,
			AAddr:     s.Src,
			APort:     s.SrcPort,
			BAddr:     s.Dst,
			BPort:     s.DstPort,
			startUnix: s.TimeUnix,
			endUnix:   s.TimeUnix,
			Start:     s.Time,
			appSet:    make(map[string]struct{}),
		}
		t.flows[key] = f
		t.order = append(t.order, key)
	}

	aToB := s.Src == f.AAddr && s.SrcPort == f.APort
	if aToB {
		f.PktsAB++
		f.BytesAB += int64(s.Length)
	} else {
		f.PktsBA++
		f.BytesBA += int64(s.Length)
	}
	f.Packets++
	f.Bytes += int64(s.Length)

	if s.TimeUnix < f.startUnix {
		f.startUnix = s.TimeUnix
		f.Start = s.Time
	}
	if s.TimeUnix > f.endUnix {
		f.endUnix = s.TimeUnix
		f.End = s.Time
	}

	if isApp(s.Proto) {
		f.appSet[s.Proto] = struct{}{}
	}
	if strings.Contains(s.Info, "RST") {
		f.Resets++
	}
}

// Flows returns the aggregated flows sorted by total bytes (descending).
func (t *Table) Flows() []Flow {
	out := make([]Flow, 0, len(t.order))
	for _, k := range t.order {
		f := t.flows[k]
		f.DurationSec = f.endUnix - f.startUnix
		f.Apps = f.Apps[:0]
		for a := range f.appSet {
			f.Apps = append(f.Apps, a)
		}
		sort.Strings(f.Apps)
		out = append(out, *f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// Len is the number of distinct flows.
func (t *Table) Len() int { return len(t.order) }

func isApp(proto string) bool {
	switch proto {
	case "TCP", "UDP", "ICMP", "ICMPv6", "?", "":
		return false
	default:
		return true // DNS, TLS, HTTP, etc.
	}
}

func minStr(a, b string) string {
	if a <= b {
		return a
	}
	return b
}

func maxStr(a, b string) string {
	if a <= b {
		return b
	}
	return a
}
