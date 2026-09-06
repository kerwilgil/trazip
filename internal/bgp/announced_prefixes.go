package bgp

import (
	"context"
	"fmt"
)

// PrefixTimeline is one window during which a prefix was observed
// announced, within the queried time range.
type PrefixTimeline struct {
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}

// AnnouncedPrefixEntry is one prefix plus every window in which
// announced-prefixes observed it announced during the query period —
// never a single "is it announced right now" boolean.
type AnnouncedPrefixEntry struct {
	Prefix    string           `json:"prefix"`
	Timelines []PrefixTimeline `json:"timelines"`
}

// AnnouncedPrefixesResult is a RAW decode of RIPEstat's
// announced-prefixes for one ASN. Despite the endpoint's name, this is
// NOT "the prefixes this ASN announces right now" — it is "the prefixes
// RIPEstat observed announced by this ASN, and during which windows,
// within [QueryStartTime, QueryEndTime]". A prefix appearing here may
// have stopped being announced before QueryEndTime, or may have multiple
// disjoint timelines. No UI-level "current prefix list" semantics are
// applied at this layer — that belongs to a future prefixes.go consumer,
// not to this raw mapper.
type AnnouncedPrefixesResult struct {
	Resource       string                 `json:"resource"`
	QueryStartTime string                 `json:"queryStartTime,omitempty"`
	QueryEndTime   string                 `json:"queryEndTime,omitempty"`
	EarliestTime   string                 `json:"earliestTime,omitempty"`
	LatestTime     string                 `json:"latestTime,omitempty"`
	Prefixes       []AnnouncedPrefixEntry `json:"prefixes"`

	Evidence ComponentEvidence `json:"evidence"`
	Err      string            `json:"err,omitempty"`
}

type announcedPrefixesData struct {
	Resource       string `json:"resource"`
	QueryStartTime string `json:"query_starttime"`
	QueryEndTime   string `json:"query_endtime"`
	EarliestTime   string `json:"earliest_time"`
	LatestTime     string `json:"latest_time"`
	Prefixes       []struct {
		Prefix    string `json:"prefix"`
		Timelines []struct {
			StartTime string `json:"starttime"`
			EndTime   string `json:"endtime"`
		} `json:"timelines"`
	} `json:"prefixes"`
}

// AnnouncedPrefixesRaw calls RIPEstat's announced-prefixes endpoint for
// one ASN and returns its response as-is — one call, no enrichment
// (no RPKI, no per-prefix routing-status), no pagination beyond whatever
// the endpoint itself returns, and no widening of the existing
// Client.get() body-size limit. A response that doesn't parse, or that
// get() rejects for exceeding that limit, is reported as
// ComponentDegraded with an empty Prefixes list — never as a partial
// list silently presented as complete.
func (c *Client) AnnouncedPrefixesRaw(ctx context.Context, asn int) AnnouncedPrefixesResult {
	res := AnnouncedPrefixesResult{Resource: fmt.Sprintf("AS%d", asn)}

	if asn <= 0 || asn > maxASN {
		res.Err = fmt.Sprintf("ASN inválido: %d (debe estar entre 1 y %d)", asn, maxASN)
		res.Evidence = ComponentEvidence{Component: "announced-prefixes", Status: ComponentNotApplicable}
		return res
	}

	cacheKey := fmt.Sprintf("announced-prefixes|%d", asn)
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(AnnouncedPrefixesResult)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchAnnouncedPrefixes(ctx, asn)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, announcedPrefixesTTL)
	}
	return result
}

func (c *Client) fetchAnnouncedPrefixes(ctx context.Context, asn int) AnnouncedPrefixesResult {
	res := AnnouncedPrefixesResult{Resource: fmt.Sprintf("AS%d", asn)}
	dataSent := fmt.Sprintf("ASN %d", asn)
	var data announcedPrefixesData
	if err := c.get(ctx, "announced-prefixes", urlValuesResource(fmt.Sprintf("AS%d", asn)), &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "announced-prefixes",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.Resource = data.Resource
	res.QueryStartTime = data.QueryStartTime
	res.QueryEndTime = data.QueryEndTime
	res.EarliestTime = data.EarliestTime
	res.LatestTime = data.LatestTime
	for _, p := range data.Prefixes {
		entry := AnnouncedPrefixEntry{Prefix: p.Prefix}
		for _, tl := range p.Timelines {
			entry.Timelines = append(entry.Timelines, PrefixTimeline{StartTime: tl.StartTime, EndTime: tl.EndTime})
		}
		res.Prefixes = append(res.Prefixes, entry)
	}
	res.Evidence = ComponentEvidence{
		Component:  "announced-prefixes",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}
