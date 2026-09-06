// Global RIS Observatory — v1.3 Gate 2 Part A. A one-shot snapshot of two
// globally-scoped RIPEstat datasources — ris-asns (RIS-observed ASN count)
// and ris-peer-count (RIS collector peer counts) — never a subscription,
// never polling, never a background timer.
//
// Gate 2's original spec also named prefix-count as a global IPv4/IPv6
// route-count source. Verified live and against RIPEstat's own docs
// (stat.ripe.net/docs/data-api/api-endpoints/prefix-count/): "resource"
// is a required AS-number parameter — a bare GET with no resource returns
// HTTP 400. Every other candidate in RIPEstat's full endpoint index
// (visibility, ris-prefixes, related-prefixes, ...) is likewise
// per-resource, never global. No RIPEstat data call reports a global
// IPv4/IPv6 route count without per-resource scoping, so
// VisibleIPv4Routes/VisibleIPv6Routes are deliberately absent from this
// file's DTO — approved by the user rather than fabricate a source or
// aggregate thousands of per-ASN calls (which would also violate "one
// HTTP call per required datasource, no polling").
package bgp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// GlobalRISObservatoryResult is a one-shot snapshot of ris-asns and
// ris-peer-count. RIS visibility is not global routing truth, a prefix
// count is not ownership, and this type carries no health/risk/security
// score and no provider/customer/upstream/downstream/Tier-1 inference —
// it is two counts, nothing more.
type GlobalRISObservatoryResult struct {
	// VisibleASNs is ris-asns' own data.counts.total (queried with
	// list_asns=false — a count, never the full ASN list). nil means the
	// call failed or didn't return a usable value; it is never set to 0
	// as an implicit "absent" sentinel, since a genuine 0 is a real,
	// distinct observation this type must be able to represent too.
	VisibleASNs *int `json:"visibleAsns,omitempty"`
	// ASNsQueryTime is ris-asns' own query_time, preserved verbatim —
	// never fabricated. Empty when VisibleASNs is nil.
	ASNsQueryTime string `json:"asnsQueryTime,omitempty"`

	// RISPeersIPv4Total/RISPeersIPv4FullFeed/RISPeersIPv6Total/
	// RISPeersIPv6FullFeed are ris-peer-count's own four counts (its most
	// recent timestamped point when no time range is requested),
	// preserved as four separate fields rather than fabricated into one
	// combined "RISPeers" number — the wire itself reports four distinct
	// counts (v4/v6 × total/full-feed peers), and summing or picking one
	// arbitrarily would misrepresent the source (the Gate 2 spec's own
	// principle: "preferir campos explícitos antes que fabricar uno
	// agregado"). Each is nil, never 0, if its own timestamped series was
	// empty.
	RISPeersIPv4Total    *int `json:"risPeersIPv4Total,omitempty"`
	RISPeersIPv4FullFeed *int `json:"risPeersIPv4FullFeed,omitempty"`
	RISPeersIPv6Total    *int `json:"risPeersIPv6Total,omitempty"`
	RISPeersIPv6FullFeed *int `json:"risPeersIPv6FullFeed,omitempty"`
	// PeersStartTime/PeersEndTime are ris-peer-count's own
	// starttime/endtime, preserved verbatim. Empty when the call failed.
	PeersStartTime string `json:"peersStartTime,omitempty"`
	PeersEndTime   string `json:"peersEndTime,omitempty"`

	// DataSufficient is true only when BOTH datasources succeeded AND
	// returned every value this result's minimum contract needs
	// (Gate 2 P1 fix): ris-asns' counts.total present, and all four
	// ris-peer-count series (v4/v6 × total/full-feed) present — HTTP 200
	// with a decodable-but-incomplete body is never enough on its own. A
	// single missing value makes the whole snapshot insufficient,
	// conservatively, even though the other component's (or the same
	// component's other) real values are still visible in the struct and
	// in Evidence.
	DataSufficient bool `json:"dataSufficient"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// risAsnsData mirrors RIPEstat's real ris-asns response (verified live
// with list_asns=false): a single global count under counts.total, plus
// the source's own query_time. With list_asns=false there is no "asns"
// list in the response at all (confirmed live) — this package never
// requests list_asns=true, since a global ASN list (tens of thousands of
// entries) is not what this observatory needs or exposes. Total is *int,
// not int (Gate 2 P1 fix): counts.total missing/absent from the response
// must be distinguishable from a genuine total:0 — a plain int would
// silently collapse both into the same zero value.
type risAsnsData struct {
	Counts struct {
		Total *int `json:"total"`
	} `json:"counts"`
	QueryTime string `json:"query_time"`
}

// risPeerCountData mirrors RIPEstat's real ris-peer-count response
// (verified live): peer counts are timestamped arrays per protocol per
// feed-type, not flat scalars — with no starttime/endtime requested, RIS
// returns exactly one current point per array (confirmed live), so this
// package takes each array's last (most recent) point rather than
// assuming a fixed length of one.
type risPeerCountData struct {
	StartTime string `json:"starttime"`
	EndTime   string `json:"endtime"`
	PeerCount struct {
		V4 risPeerCountProtocol `json:"v4"`
		V6 risPeerCountProtocol `json:"v6"`
	} `json:"peer_count"`
}

type risPeerCountProtocol struct {
	Total    []risPeerCountPoint `json:"total"`
	FullFeed []risPeerCountPoint `json:"full_feed"`
}

type risPeerCountPoint struct {
	Timestamp string `json:"timestamp"`
	Count     int    `json:"count"`
}

// lastPeerCount returns a pointer to the last (most recent) point's
// count, or nil if points is empty — never a fabricated 0 for an empty
// series.
func lastPeerCount(points []risPeerCountPoint) *int {
	if len(points) == 0 {
		return nil
	}
	n := points[len(points)-1].Count
	return &n
}

// GlobalRISObservatory queries ris-asns and ris-peer-count — two HTTP
// calls total, one per datasource, user-initiated, never polling, never a
// background timer or goroutine. Each datasource gets its own
// ComponentEvidence entry regardless of the other's outcome, so a partial
// failure is always visible rather than silently downgrading the whole
// result.
func (c *Client) GlobalRISObservatory(ctx context.Context) GlobalRISObservatoryResult {
	var res GlobalRISObservatoryResult

	asnsOK := c.fetchRISAsns(ctx, &res)
	peersOK := c.fetchRISPeerCount(ctx, &res)

	res.DataSufficient = asnsOK && peersOK
	if !res.DataSufficient {
		var failed []string
		if !asnsOK {
			failed = append(failed, "ris-asns")
		}
		if !peersOK {
			failed = append(failed, "ris-peer-count")
		}
		res.Err = fmt.Sprintf("datasource(s) fallidos: %s", strings.Join(failed, ", "))
	}
	return res
}

func (c *Client) fetchRISAsns(ctx context.Context, res *GlobalRISObservatoryResult) bool {
	dataSent := "conteo global de ASNs visibles en RIS (list_asns=false)"
	var data risAsnsData
	params := url.Values{"list_asns": {"false"}}
	if err := c.get(ctx, "ris-asns", params, &data); err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component:  "ris-asns",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        err.Error(),
		})
		return false
	}
	// A response that decoded but never carried counts.total is a
	// datasource inconsistency, not a real result — never presented as
	// ComponentOK, and query_time is never kept on its own since it
	// describes a total that isn't actually here (Gate 2 P1 fix).
	if data.Counts.Total == nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component:  "ris-asns",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        "ris-asns respondió sin counts.total",
		})
		return false
	}
	total := *data.Counts.Total
	res.VisibleASNs = &total
	res.ASNsQueryTime = data.QueryTime
	res.Evidence = append(res.Evidence, ComponentEvidence{
		Component:  "ris-asns",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	})
	return true
}

func (c *Client) fetchRISPeerCount(ctx context.Context, res *GlobalRISObservatoryResult) bool {
	dataSent := "conteo global de peers RIS (v4/v6, total y full-feed)"
	var data risPeerCountData
	if err := c.get(ctx, "ris-peer-count", url.Values{}, &data); err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component:  "ris-peer-count",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        err.Error(),
		})
		return false
	}
	res.PeersStartTime = data.StartTime
	res.PeersEndTime = data.EndTime
	res.RISPeersIPv4Total = lastPeerCount(data.PeerCount.V4.Total)
	res.RISPeersIPv4FullFeed = lastPeerCount(data.PeerCount.V4.FullFeed)
	res.RISPeersIPv6Total = lastPeerCount(data.PeerCount.V6.Total)
	res.RISPeersIPv6FullFeed = lastPeerCount(data.PeerCount.V6.FullFeed)

	// The minimum contract needs all four series present (Gate 2 P1
	// fix) — a response missing even one (e.g. v6.full_feed's array is
	// empty) is a partial result, never ComponentOK. Whatever series DID
	// decode stay in the struct exactly as set above — a failing
	// component here never discards another component's real values,
	// and never discards its own partially-present series either.
	var missing []string
	if res.RISPeersIPv4Total == nil {
		missing = append(missing, "v4.total")
	}
	if res.RISPeersIPv4FullFeed == nil {
		missing = append(missing, "v4.full_feed")
	}
	if res.RISPeersIPv6Total == nil {
		missing = append(missing, "v6.total")
	}
	if res.RISPeersIPv6FullFeed == nil {
		missing = append(missing, "v6.full_feed")
	}
	if len(missing) > 0 {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component:  "ris-peer-count",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        fmt.Sprintf("ris-peer-count respondió sin series peer_count requeridas: %s", strings.Join(missing, ", ")),
		})
		return false
	}

	res.Evidence = append(res.Evidence, ComponentEvidence{
		Component:  "ris-peer-count",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	})
	return true
}
