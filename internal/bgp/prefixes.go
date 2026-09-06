package bgp

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// prefixPageSize is the fixed v1.1 page size — never configurable per
// request, so the request budget (prefixPageSize*2 external calls) stays
// a hard, testable constant.
const prefixPageSize = 25

// maxPrefixEnrichmentConcurrency bounds how many rows of one page are
// enriched in parallel — a small, fixed worker pool, never one goroutine
// per row left unbounded.
const maxPrefixEnrichmentConcurrency = 4

// PrefixEnrichmentState is a row's per-call lifecycle state. It is
// entirely distinct from RPKIState: a row can be PrefixLoaded with
// RPKI.State == RPKIUnknown (RIPEstat successfully reported "no ROA
// covers this"), which is a completely different fact from
// PrefixUnavailable/PrefixDegraded (the query itself did not produce a
// usable/successful result). Never conflate the two.
type PrefixEnrichmentState string

const (
	// PrefixNotLoaded: enrichment has not been attempted for this row.
	// Reserved for a future asynchronous/streaming consumer — this
	// package's PrefixList is synchronous and never returns a row in
	// this state.
	PrefixNotLoaded PrefixEnrichmentState = "not_loaded"
	// PrefixLoading: enrichment is in flight. Same reservation as
	// PrefixNotLoaded — never observed in a PrefixList result.
	PrefixLoading PrefixEnrichmentState = "loading"
	// PrefixLoaded: both routing-status and rpki-validation completed
	// with ComponentOK for this row.
	PrefixLoaded PrefixEnrichmentState = "loaded"
	// PrefixUnavailable: both calls completed (or were not applicable)
	// but at least one produced no usable data — never a network/query
	// failure.
	PrefixUnavailable PrefixEnrichmentState = "unavailable"
	// PrefixDegraded: at least one of the two calls failed at the
	// network/query layer.
	PrefixDegraded PrefixEnrichmentState = "degraded"
)

// PrefixRow is one announced-prefixes entry enriched with exactly one
// routing-status call and exactly one rpki-validation call — the latter
// always for the ASN this PrefixList was queried for, never for every
// origin in a MOAS (see RPKIValidateDetailed field doc below).
type PrefixRow struct {
	Prefix string `json:"prefix"`
	Family string `json:"family"` // "ipv4" | "ipv6"

	// Timelines is exactly what AnnouncedPrefixesRaw reported — windows
	// within the query period, never "currently announced" semantics.
	Timelines []PrefixTimeline `json:"timelines,omitempty"`

	// Visibility is the row's own family's visibility (VisibilityV4 for
	// an ipv4 row, VisibilityV6 for ipv6) from this row's routing-status
	// call — never the other family's, never fabricated.
	Visibility *Visibility `json:"visibility,omitempty"`

	// Origins/MOAS come from this row's own routing-status call — the
	// origins currently observed announcing this prefix, not derived
	// from announced-prefixes (which never reports origins).
	Origins []int `json:"origins,omitempty"`
	MOAS    bool  `json:"moas"`

	// RPKI is the validation of (queried ASN, this prefix) ONLY — never
	// every origin in a MOAS (that fan-out belongs to Security, see
	// security.go). A row with MOAS=true still carries exactly one RPKI
	// result, for the queried ASN's own claim, so this must never be
	// presented as "the RPKI state of every origin".
	RPKI *RPKIValidationDetailed `json:"rpki,omitempty"`

	State PrefixEnrichmentState `json:"state"`

	// Evidence has exactly two entries once enriched: routing-status,
	// then rpki-validation — never collapsed, never omitted even on
	// failure.
	Evidence []ComponentEvidence `json:"evidence,omitempty"`
}

// PrefixPageRequest is one page request. Page is 1-based.
type PrefixPageRequest struct {
	ASN  int
	Page int // 1-based; <1 or beyond the last page returns a valid empty page, never an error or panic.

	// Family filters locally on the already-fetched listing: "all"
	// (default), "ipv4", "ipv6". No additional network request.
	Family string
	// Search filters locally, case-insensitive substring match on the
	// prefix string. No additional network request.
	Search string
	// Sort supports "prefix_asc" (default), "prefix_desc", "family" —
	// all computable from the already-fetched listing alone. Any other
	// value (in particular anything RPKI/visibility-based, which would
	// require enriching the entire collection first) is documented as
	// unsupported for v1.1 and silently falls back to "prefix_asc".
	Sort string
}

// PrefixPage is one filtered/sorted/paginated, page-enriched result.
type PrefixPage struct {
	ASN        int
	Page       int // echoes PrefixPageRequest.Page verbatim, even when out of range
	PageSize   int
	TotalItems int
	TotalPages int // 0 when TotalItems == 0
	Items      []PrefixRow

	// Evidence always has the announced-prefixes call's evidence first;
	// per-row routing-status/rpki-validation evidence lives on each
	// PrefixRow, not duplicated here.
	Evidence []ComponentEvidence

	// Err is set only when no useful page could be produced at all
	// (announced-prefixes itself failed/was rejected) — a single failed
	// row's enrichment never sets this; see PrefixRow.State/Evidence.
	Err string
}

// PrefixList fetches AnnouncedPrefixesRaw for one ASN (reusing its
// existing cache — this function adds no cache of its own), applies
// Family/Search/Sort entirely in memory, paginates at a fixed page size
// of 25, and enriches ONLY the resulting page's rows — never the full
// collection, never adjacent pages, never a prefetch. Each row costs at
// most 2 external datasource calls (routing-status + rpki-validation),
// so one page never exceeds prefixPageSize*2 == 50 calls, regardless of
// MOAS rows (which still cost exactly 2, never one per origin).
func (c *Client) PrefixList(ctx context.Context, req PrefixPageRequest) PrefixPage {
	page := PrefixPage{ASN: req.ASN, Page: req.Page, PageSize: prefixPageSize}

	prefixesRaw := c.AnnouncedPrefixesRaw(ctx, req.ASN)
	page.Evidence = append(page.Evidence, prefixesRaw.Evidence)
	if prefixesRaw.Evidence.Status != ComponentOK {
		page.Err = prefixesRaw.Err
		if page.Err == "" {
			page.Err = "no fue posible obtener la lista de prefijos para este ASN"
		}
		return page
	}

	rows := make([]PrefixRow, 0, len(prefixesRaw.Prefixes))
	for _, p := range prefixesRaw.Prefixes {
		rows = append(rows, PrefixRow{
			Prefix:    p.Prefix,
			Family:    prefixFamily(p.Prefix),
			Timelines: p.Timelines,
			State:     PrefixNotLoaded,
		})
	}

	rows = filterPrefixRows(rows, req.Family, req.Search)
	rows = sortPrefixRows(rows, req.Sort)

	page.TotalItems = len(rows)
	page.TotalPages = totalPages(page.TotalItems, prefixPageSize)

	if req.Page < 1 || (page.TotalPages > 0 && req.Page > page.TotalPages) {
		page.Items = []PrefixRow{}
		return page
	}

	start := (req.Page - 1) * prefixPageSize
	if start >= len(rows) {
		page.Items = []PrefixRow{}
		return page
	}
	end := start + prefixPageSize
	if end > len(rows) {
		end = len(rows)
	}

	page.Items = c.enrichPrefixRows(ctx, req.ASN, rows[start:end])
	return page
}

func prefixFamily(prefix string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
	if err != nil {
		return ""
	}
	if p.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func filterPrefixRows(rows []PrefixRow, family, search string) []PrefixRow {
	family = strings.ToLower(strings.TrimSpace(family))
	search = strings.ToLower(strings.TrimSpace(search))
	if family == "" {
		family = "all"
	}
	if family == "all" && search == "" {
		return rows
	}
	out := make([]PrefixRow, 0, len(rows))
	for _, r := range rows {
		if family != "all" && r.Family != family {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(r.Prefix), search) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func sortPrefixRows(rows []PrefixRow, sortKey string) []PrefixRow {
	sorted := make([]PrefixRow, len(rows))
	copy(sorted, rows)
	switch sortKey {
	case "prefix_desc":
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Prefix > sorted[j].Prefix })
	case "family":
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].Family != sorted[j].Family {
				return sorted[i].Family < sorted[j].Family
			}
			return sorted[i].Prefix < sorted[j].Prefix
		})
	default:
		// "prefix_asc" and any unrecognized/unsupported value — see
		// PrefixPageRequest.Sort's doc comment.
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Prefix < sorted[j].Prefix })
	}
	return sorted
}

func totalPages(totalItems, pageSize int) int {
	if totalItems == 0 {
		return 0
	}
	return (totalItems + pageSize - 1) / pageSize
}

// enrichPrefixRows runs at most maxPrefixEnrichmentConcurrency row
// enrichments in parallel, writing each result directly to its own
// index — never through an append/channel-drain pattern — so the
// returned slice always matches the input's order regardless of which
// goroutine finishes first.
func (c *Client) enrichPrefixRows(ctx context.Context, asn int, rows []PrefixRow) []PrefixRow {
	result := make([]PrefixRow, len(rows))
	copy(result, rows)

	sem := make(chan struct{}, maxPrefixEnrichmentConcurrency)
	var wg sync.WaitGroup
	for i := range result {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result[i] = c.enrichPrefixRow(ctx, asn, result[i])
		}(i)
	}
	wg.Wait()
	return result
}

// enrichPrefixRow always attempts exactly one RoutingStatusDetailedQuery
// and exactly one RPKIValidateDetailed call — unconditionally, even if
// the other one fails — so a page's total call count is always
// deterministic (2 per row) regardless of individual row outcomes.
func (c *Client) enrichPrefixRow(ctx context.Context, asn int, row PrefixRow) PrefixRow {
	routing := c.RoutingStatusDetailedQuery(ctx, row.Prefix)
	row.Evidence = append(row.Evidence, routing.Evidence)
	if routing.Err == "" {
		for _, o := range routing.Origins {
			row.Origins = append(row.Origins, o.Origin)
		}
		row.MOAS = len(row.Origins) > 1
		switch row.Family {
		case "ipv6":
			row.Visibility = routing.VisibilityV6
		default:
			row.Visibility = routing.VisibilityV4
		}
	}

	rpki := c.RPKIValidateDetailed(ctx, asn, row.Prefix)
	row.Evidence = append(row.Evidence, rpki.Evidence)
	row.RPKI = &rpki

	row.State = derivePrefixRowState(routing.Evidence.Status, rpki.Evidence.Status)
	return row
}

func derivePrefixRowState(routingStatus, rpkiStatus ComponentStatus) PrefixEnrichmentState {
	if routingStatus == ComponentDegraded || rpkiStatus == ComponentDegraded {
		return PrefixDegraded
	}
	if routingStatus == ComponentUnavailable || rpkiStatus == ComponentUnavailable ||
		routingStatus == ComponentNotApplicable || rpkiStatus == ComponentNotApplicable {
		return PrefixUnavailable
	}
	return PrefixLoaded
}
