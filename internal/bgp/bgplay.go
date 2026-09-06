// BGPlay — v1.2 Gate 4 (BGP_INTELLIGENCE_ROADMAP.md §23.1 C, §23.6). A
// single point-in-time query over RIPEstat's bgplay endpoint for a closed
// [StartTime, EndTime) window — topological visualization data (paths at
// StartTime + every update event + AS/collector metadata), never realtime,
// never a subscription, never used to build History (bgp-updates,
// history.go, is the correct lighter datasource for that — §23.1 C "nunca
// para History simple").
package bgp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Limits for BGPlay (§23.6) — stricter than History given the real
// probed volume (see bgplayMaxNodes' own doc comment for the Gate 4
// evidence behind its value).
const (
	bgplayMaxInitialState = 500
	bgplayMaxEvents       = historyMaxUpdates // same limit, same underlying data shape (BGPHistoryUpdate) — §23.6 "mismo límite y mismo tipo de dato que History"

	// bgplayMaxNodes resolves the roadmap's §23.6 "300, cifra a confirmar
	// en Gate 4" candidate. Gate 4 preflight ran two live, read-only 24h
	// bgplay probes against the two most-queried anycast DNS prefixes on
	// the internet (the same class of "popular prefix" the roadmap's own
	// §23.1 C probe used): 1.1.1.0/24 → 313 nodes (matching the roadmap's
	// own documented probe exactly), 8.8.8.0/24 → 311 nodes. Both already
	// exceed 300 — freezing the candidate as-is would truncate on the most
	// common realistic "interesting" case tested, not just an adversarial
	// edge case. 350 keeps ~12% headroom over both observed maxima while
	// staying the same order of magnitude (never "an enormous number to
	// avoid truncation" — still an explicit, deterministic, small bound).
	bgplayMaxNodes = 350
)

// BGPlayRequest is one closed-window bgplay query.
type BGPlayRequest struct {
	Resource  string
	StartTime string
	EndTime   string
}

// BGPlayResult is the bounded, honest result of one BGPlayRequest.
//
// Sources is deliberately UNBOUNDED by this gate (§23.6 leaves it
// unlimited; the task's own Gate 4 instructions forbid inventing a bound
// silently — "STOP y reportar el gap contractual con evidencia antes de
// inventarlo"). Gate 4 evidence: the same two live probes that resolved
// bgplayMaxNodes observed 373/374 Sources — MORE than Nodes, and larger
// than bgplayMaxNodes itself. Sources is naturally bounded by the real
// population of RIS route collectors/peers (a fixed, non-adversarial,
// real-world set — not a value an attacker or a busy resource can grow
// without bound the way Events could), which is why leaving it uncapped
// for THIS gate is defensible rather than an oversight; a future gate
// should revisit with its own evidence if that assumption ever breaks,
// rather than this gate inventing an arbitrary cap now.
type BGPlayResult struct {
	Resource             string
	StartTime            string
	EndTime              string
	InitialState         []BGPlayPath        `json:"initialState"`
	Events               []BGPHistoryUpdate  `json:"events"` // same type as History (bgp-updates) — one update event is one update event regardless of endpoint
	Nodes                []BGPlayNode        `json:"nodes"`
	Sources              []BGPlaySource      `json:"sources"`
	Truncated            bool                `json:"truncated"`
	ObservedInitialState int                 `json:"observedInitialState"`
	ObservedEvents       int                 `json:"observedEvents"`
	ObservedNodes        int                 `json:"observedNodes"`
	Evidence             []ComponentEvidence `json:"evidence"`
	Err                  string              `json:"err,omitempty"`
}

// BGPlayPath is one initial_state entry — a path active exactly at
// StartTime, one per (source_id, path).
type BGPlayPath struct {
	SourceID     string
	TargetPrefix string
	Path         []int
	Community    []string // "ASN:value" strings, same shape as History — RIPEstat REST
}

// BGPlayNode is one ASN's render metadata. Owner is literal RIPEstat
// metadata — NEVER a source for inferring provider/customer/transit/
// Tier-1 commercial relationships (§23.1 C, same principle as v1.1 §13).
type BGPlayNode struct {
	ASN   int
	Owner string
}

// BGPlaySource is one RIS route collector (RRC) that contributed data.
// ID correlates with Events[].SourceID / InitialState[].SourceID.
type BGPlaySource struct {
	ASN int
	ID  string
	IP  string
	RRC string
}

// bgplayData mirrors RIPEstat's real bgplay response shape (§23.1 C,
// verified live). events uses the same wire shape as bgp-updates.updates
// (bgpUpdateWire, history.go) — one datasource, two endpoints, same event
// model.
type bgplayData struct {
	Resource       string             `json:"resource"`
	QueryStartTime string             `json:"query_starttime"`
	QueryEndTime   string             `json:"query_endtime"`
	InitialState   []bgplayPathWire   `json:"initial_state"`
	Events         []bgpUpdateWire    `json:"events"`
	Nodes          []bgplayNodeWire   `json:"nodes"`
	Sources        []bgplaySourceWire `json:"sources"`
	// targets intentionally not decoded — §23.6 exposes no functionality
	// over it; decoding it now would be inventing scope the contract
	// doesn't ask for.
}

type bgplayPathWire struct {
	SourceID     string   `json:"source_id"`
	TargetPrefix string   `json:"target_prefix"`
	Path         []int    `json:"path,omitempty"`
	Community    []string `json:"community,omitempty"`
}

type bgplayNodeWire struct {
	ASN   int    `json:"as_number"`
	Owner string `json:"owner"`
}

type bgplaySourceWire struct {
	ASN int    `json:"as_number"`
	ID  string `json:"id"`
	IP  string `json:"ip"`
	RRC string `json:"rrc"`
}

func decodeBGPlayPath(w bgplayPathWire) BGPlayPath {
	return BGPlayPath{
		SourceID:     w.SourceID,
		TargetPrefix: w.TargetPrefix,
		Path:         w.Path,
		Community:    w.Community,
	}
}

func decodeBGPlayNode(w bgplayNodeWire) BGPlayNode {
	return BGPlayNode{ASN: w.ASN, Owner: w.Owner}
}

func decodeBGPlaySource(w bgplaySourceWire) BGPlaySource {
	return BGPlaySource{ASN: w.ASN, ID: w.ID, IP: w.IP, RRC: w.RRC}
}

// BGPlay queries the bgplay endpoint for req.Resource over [req.StartTime,
// req.EndTime) — one HTTP call, user-initiated, never polling, never
// treated as realtime even when the requested range ends "now" (§23.6).
// Any local validation failure short-circuits before any network access,
// mirroring BGPHistory exactly (both share validateTimeRange).
func (c *Client) BGPlay(ctx context.Context, req BGPlayRequest) BGPlayResult {
	res := BGPlayResult{
		Resource:     strings.TrimSpace(req.Resource),
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
		InitialState: []BGPlayPath{},
		Events:       []BGPHistoryUpdate{},
		Nodes:        []BGPlayNode{},
		Sources:      []BGPlaySource{},
	}

	kind, normalized := ClassifyResource(req.Resource)
	if kind == KindInvalid {
		res.Err = fmt.Sprintf("recurso inválido: %q", req.Resource)
		res.Evidence = []ComponentEvidence{{Component: "bgplay", Status: ComponentNotApplicable}}
		return res
	}
	res.Resource = normalized

	if err := validateTimeRange(req.StartTime, req.EndTime); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{Component: "bgplay", Status: ComponentNotApplicable}}
		return res
	}

	dataSent := fmt.Sprintf("recurso %s, rango [%s, %s]", normalized, req.StartTime, req.EndTime)
	params := url.Values{"resource": {normalized}, "starttime": {req.StartTime}, "endtime": {req.EndTime}}
	var data bgplayData
	if err := c.get(ctx, "bgplay", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{
			Component:  "bgplay",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	res.ObservedInitialState = len(data.InitialState)
	nInit := min(res.ObservedInitialState, bgplayMaxInitialState)
	initialState := make([]BGPlayPath, nInit)
	for i := 0; i < nInit; i++ {
		initialState[i] = decodeBGPlayPath(data.InitialState[i])
	}
	res.InitialState = initialState

	res.ObservedEvents = len(data.Events)
	nEvents := min(res.ObservedEvents, bgplayMaxEvents)
	events := make([]BGPHistoryUpdate, nEvents)
	for i := 0; i < nEvents; i++ {
		events[i] = decodeBGPHistoryUpdate(data.Events[i])
	}
	res.Events = events

	res.ObservedNodes = len(data.Nodes)
	nNodes := min(res.ObservedNodes, bgplayMaxNodes)
	nodes := make([]BGPlayNode, nNodes)
	for i := 0; i < nNodes; i++ {
		nodes[i] = decodeBGPlayNode(data.Nodes[i])
	}
	res.Nodes = nodes

	// Sources: never truncated by this gate — see BGPlayResult.Sources'
	// own doc comment for why.
	sources := make([]BGPlaySource, len(data.Sources))
	for i, s := range data.Sources {
		sources[i] = decodeBGPlaySource(s)
	}
	res.Sources = sources

	res.Truncated = res.ObservedInitialState > bgplayMaxInitialState ||
		res.ObservedEvents > bgplayMaxEvents ||
		res.ObservedNodes > bgplayMaxNodes
	res.Evidence = []ComponentEvidence{{
		Component:  "bgplay",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}}
	return res
}
