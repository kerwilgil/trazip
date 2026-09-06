// BGP History — v1.2 Gate 4 (BGP_INTELLIGENCE_ROADMAP.md §23.1 B.1, §23.6).
// A single point-in-time query over RIPEstat's bgp-updates endpoint for a
// closed [StartTime, EndTime) window — never a subscription, never
// polling, never realtime. History and BGPlay (bgplay.go) share the same
// temporal contract (validateTimeRange below) but never the same
// datasource: bgp-updates is deliberately lighter than bgplay (raw update
// events only, no initial_state/nodes/sources enrichment) — §23.1 B.1's
// own wording: "nunca bgplay para esto".
package bgp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// bgpTimeRangeMax bounds every History/BGPlay request window — shared
	// by both endpoints (§23.6). Justified by the real probe in §23.1 B.1:
	// a 1-year bgp-updates query never returned within 30s (no explicit
	// server-side rejection), while a 7-day query for one popular prefix
	// returned 4204 events/783KB in ~3.3s — RIPEstat itself imposes no
	// range cap, so TRAZIP must. 24h is the roadmap's own chosen bound.
	bgpTimeRangeMax = 24 * time.Hour

	// historyMaxUpdates bounds BGPHistoryResult.Updates (§23.6 "Límites
	// para History") — RIPEstat's own bgp-updates response is NOT
	// server-side paginated (confirmed live, Gate 4 preflight probe:
	// data.nr_updates always equals len(data.updates) for the requests
	// tested, including the empty case — data.nr_updates:0 with
	// data.updates:[] — so RIPEstat always sends both, never omits
	// nr_updates), so TRAZIP receives the full result and truncates
	// itself.
	historyMaxUpdates = 2000
)

// BGPHistoryRequest is one closed-window bgp-updates query — never open
// ended ("desde siempre" is explicitly rejected, see validateTimeRange).
type BGPHistoryRequest struct {
	Resource  string
	StartTime string // RFC3339, obligatorio
	EndTime   string // RFC3339, obligatorio
}

// BGPHistoryResult is the bounded, honest result of one BGPHistoryRequest.
type BGPHistoryResult struct {
	Resource        string
	StartTime       string
	EndTime         string
	Updates         []BGPHistoryUpdate  `json:"updates"`
	Truncated       bool                `json:"truncated"`
	ObservedUpdates int                 `json:"observedUpdates"`
	Evidence        []ComponentEvidence `json:"evidence"`
	Err             string              `json:"err,omitempty"`
}

// BGPHistoryUpdate is one raw bgp-updates event, decoded losslessly —
// never reinterpreted into hijack/attack/provider/customer vocabulary
// (§23.6 "History representa updates observados. Nada más."). Reused
// verbatim by BGPlay's Events (bgplay.go) — one update event is one update
// event regardless of which endpoint returned it.
type BGPHistoryUpdate struct {
	Seq       int64
	Timestamp string
	// Type is "A" | "W" exactly as the wire sends it — never rewritten to
	// "announcement"/"withdrawal" at this level (§23.6).
	Type     string
	SourceID string
	// TargetPrefix is attrs.target_prefix, literal — never derived from
	// the request's Resource. Gate 4 erratum: a Resource=ASN query can
	// legitimately span multiple prefixes in one bgp-updates/bgplay
	// response (RIPEstat correlates by (source_id, target_prefix), not by
	// the queried resource alone), so without this field two updates for
	// different prefixes under the same ASN would be indistinguishable.
	TargetPrefix string   `json:"targetPrefix"`
	Path         []int    `json:"path,omitempty"`
	Community    []string `json:"community,omitempty"` // "ASN:value" strings — RIPEstat REST shape, distinct from RIS Live's [ASN,value] pairs (§23.1 discrepancy note)
}

// bgpUpdatesData mirrors RIPEstat's real bgp-updates response shape
// (§23.1 B.1, verified live). NrUpdates is the source's own declared
// total (data.nr_updates) — confirmed live to always be present,
// including the empty-result case (nr_updates:0, updates:[]) — see
// historyMaxUpdates' doc comment. ObservedUpdates is derived from this,
// never silently from len(Updates) alone (Gate 4 P1-1 closure).
type bgpUpdatesData struct {
	Resource       string          `json:"resource"`
	QueryStartTime string          `json:"query_starttime"`
	QueryEndTime   string          `json:"query_endtime"`
	NrUpdates      int             `json:"nr_updates"`
	Updates        []bgpUpdateWire `json:"updates"`
}

// bgpUpdateWire is one raw update as RIPEstat sends it. Path/Community
// live under attrs and are present ONLY on "A" (announcement) events —
// absent on "W" (withdrawal), confirmed live — so they decode to a nil
// slice for withdrawals, never a fabricated empty-but-present array.
type bgpUpdateWire struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Attrs     struct {
		SourceID     string   `json:"source_id"`
		TargetPrefix string   `json:"target_prefix"`
		Path         []int    `json:"path,omitempty"`
		Community    []string `json:"community,omitempty"`
	} `json:"attrs"`
}

func decodeBGPHistoryUpdate(w bgpUpdateWire) BGPHistoryUpdate {
	return BGPHistoryUpdate{
		Seq:          w.Seq,
		Timestamp:    w.Timestamp,
		Type:         w.Type,
		SourceID:     w.Attrs.SourceID,
		TargetPrefix: w.Attrs.TargetPrefix,
		Path:         w.Attrs.Path,
		Community:    w.Attrs.Community,
	}
}

// validateTimeRange enforces the shared History/BGPlay temporal contract
// (§23.6) entirely before any network access: both timestamps mandatory
// RFC3339, Start strictly before End, and the window no wider than
// bgpTimeRangeMax. A request that fails here costs zero HTTP calls — never
// silently clamped to 24h, always rejected outright (§23.6 "nunca
// silenciosamente recortado").
func validateTimeRange(start, end string) error {
	if strings.TrimSpace(start) == "" {
		return fmt.Errorf("StartTime vacío — obligatorio y explícito, nunca \"desde siempre\"")
	}
	if strings.TrimSpace(end) == "" {
		return fmt.Errorf("EndTime vacío — obligatorio")
	}
	st, err := time.Parse(time.RFC3339, start)
	if err != nil {
		return fmt.Errorf("StartTime inválido (se espera RFC3339): %w", err)
	}
	et, err := time.Parse(time.RFC3339, end)
	if err != nil {
		return fmt.Errorf("EndTime inválido (se espera RFC3339): %w", err)
	}
	if !st.Before(et) {
		return fmt.Errorf("StartTime (%s) debe ser anterior a EndTime (%s)", start, end)
	}
	if d := et.Sub(st); d > bgpTimeRangeMax {
		return fmt.Errorf("rango temporal %s excede el máximo permitido de %s — nunca recortado silenciosamente, la petición se rechaza completa", d, bgpTimeRangeMax)
	}
	return nil
}

// BGPHistory queries bgp-updates for req.Resource over [req.StartTime,
// req.EndTime) — one HTTP call, user-initiated, never polling. Any local
// validation failure (invalid resource, invalid/missing timestamps,
// inverted or oversized range) short-circuits before any network access,
// Evidence.Status = ComponentNotApplicable, Err honest and specific.
func (c *Client) BGPHistory(ctx context.Context, req BGPHistoryRequest) BGPHistoryResult {
	res := BGPHistoryResult{
		Resource:  strings.TrimSpace(req.Resource),
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		Updates:   []BGPHistoryUpdate{},
	}

	kind, normalized := ClassifyResource(req.Resource)
	if kind == KindInvalid {
		res.Err = fmt.Sprintf("recurso inválido: %q", req.Resource)
		res.Evidence = []ComponentEvidence{{Component: "bgp-updates", Status: ComponentNotApplicable}}
		return res
	}
	res.Resource = normalized

	if err := validateTimeRange(req.StartTime, req.EndTime); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{Component: "bgp-updates", Status: ComponentNotApplicable}}
		return res
	}

	dataSent := fmt.Sprintf("recurso %s, rango [%s, %s]", normalized, req.StartTime, req.EndTime)
	params := url.Values{"resource": {normalized}, "starttime": {req.StartTime}, "endtime": {req.EndTime}}
	var data bgpUpdatesData
	if err := c.get(ctx, "bgp-updates", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{
			Component:  "bgp-updates",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	// ObservedUpdates comes from the source's own declared total
	// (data.nr_updates), never silently substituted with len(data.Updates)
	// — Gate 4 P1-1 closure. nr_updates < len(updates) is not a shape
	// RIPEstat has ever been observed to send (live probes: always equal,
	// or nr_updates strictly larger when the array itself got capped
	// upstream) — it would mean the source declared a total than it
	// itself, so it is treated as a decode/datasource inconsistency,
	// never presented as a real (and definitely fabricated) count.
	if data.NrUpdates < len(data.Updates) {
		res.Err = fmt.Sprintf("bgp-updates respuesta inconsistente: nr_updates=%d < len(updates)=%d", data.NrUpdates, len(data.Updates))
		res.Evidence = []ComponentEvidence{{
			Component:  "bgp-updates",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	res.ObservedUpdates = data.NrUpdates
	n := min(len(data.Updates), historyMaxUpdates)
	updates := make([]BGPHistoryUpdate, n)
	for i := 0; i < n; i++ {
		updates[i] = decodeBGPHistoryUpdate(data.Updates[i])
	}
	res.Updates = updates
	// Truncated whenever the returned view is smaller than what the
	// source declared existed — either because TRAZIP itself capped it at
	// historyMaxUpdates, or because nr_updates > len(updates) (the source
	// already reported more than it actually returned, independent of
	// TRAZIP's own cap).
	res.Truncated = res.ObservedUpdates > n
	res.Evidence = []ComponentEvidence{{
		Component:  "bgp-updates",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}}
	return res
}
