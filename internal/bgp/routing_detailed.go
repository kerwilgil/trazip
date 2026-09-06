package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Visibility is one address family's observed RIS peer coverage for a
// resource — per RIPEstat's routing-status "visibility.v4"/"visibility.v6".
// v4 and v6 are always kept separate; they are never combined into one
// ratio, since a resource can be well-observed in one family and poorly
// observed (or entirely absent) in the other.
type Visibility struct {
	Family         string  `json:"family"` // "v4" | "v6"
	RISPeersSeeing int     `json:"risPeersSeeing"`
	TotalRISPeers  int     `json:"totalRisPeers"`
	Ratio          float64 `json:"ratio"`          // RISPeersSeeing/TotalRISPeers, 0 if TotalRISPeers == 0
	Classification string  `json:"classification"` // TRAZIP-defined, NOT a RIPE NCC classification — see classifyVisibility
}

// classifyVisibility applies TRAZIP's own thresholds to a raw ratio. This
// is a TRAZIP interpretation, not something RIPEstat returns — never
// presented as an official RIPE NCC classification. Not yet consumed by
// any health/scoring logic in this gate.
func classifyVisibility(ratio float64) string {
	switch {
	case ratio >= 0.66:
		return "alta"
	case ratio >= 0.33:
		return "media"
	case ratio > 0:
		return "baja"
	default:
		return "no_observado"
	}
}

func newVisibility(family string, seeing, total int) Visibility {
	v := Visibility{Family: family, RISPeersSeeing: seeing, TotalRISPeers: total}
	if total > 0 {
		v.Ratio = float64(seeing) / float64(total)
	}
	v.Classification = classifyVisibility(v.Ratio)
	return v
}

// SeenEvent is a first-seen/last-seen observation: when a resource was
// first/last observed in BGP, under which origin ASN and covering prefix.
type SeenEvent struct {
	Time   string `json:"time"`
	Origin int    `json:"origin"`
	Prefix string `json:"prefix"`
}

// AnnouncedSpaceV4 is the IPv4 announced-space summary for an ASN.
type AnnouncedSpaceV4 struct {
	Prefixes int64 `json:"prefixes"`
	IPs      int64 `json:"ips"`
}

// AnnouncedSpaceV6 is the IPv6 announced-space summary for an ASN.
// RIPEstat reports IPv6 space in prefix count plus a /48-equivalent
// count (its own normalization), not an address count — preserved as
// its own field, never conflated with AnnouncedSpaceV4.IPs.
type AnnouncedSpaceV6 struct {
	Prefixes int64 `json:"prefixes"`
	Slash48s int64 `json:"slash48s"`
}

// RouteOrigin is one origin ASN announcing a resource, with whatever
// route-object evidence RIPEstat attaches to it. A resource with more
// than one entry here is a MOAS (multi-origin) — preserved as-is, no
// judgment attached at this layer.
type RouteOrigin struct {
	Origin       int      `json:"origin"`
	RouteObjects []string `json:"routeObjects,omitempty"`
}

// RoutingStatusDetailed is the fuller routing-status decode — additive to
// RouteStatus (bgp.go), which stays untouched for existing callers.
type RoutingStatusDetailed struct {
	Resource  string        `json:"resource"`
	Announced bool          `json:"announced"`
	Prefix    string        `json:"prefix,omitempty"` // RIPEstat's own resolved covering prefix, when present
	Origins   []RouteOrigin `json:"origins,omitempty"`

	VisibilityV4 *Visibility `json:"visibilityV4,omitempty"`
	VisibilityV6 *Visibility `json:"visibilityV6,omitempty"`

	FirstSeen *SeenEvent `json:"firstSeen,omitempty"`
	LastSeen  *SeenEvent `json:"lastSeen,omitempty"`

	AnnouncedSpaceV4 *AnnouncedSpaceV4 `json:"announcedSpaceV4,omitempty"`
	AnnouncedSpaceV6 *AnnouncedSpaceV6 `json:"announcedSpaceV6,omitempty"`

	ObservedNeighbours int `json:"observedNeighbours"`

	QueryTime string `json:"queryTime,omitempty"`

	Evidence ComponentEvidence `json:"evidence"`
	Err      string            `json:"err,omitempty"`
}

// routingStatusDetailedData mirrors RIPEstat's actual routing-status
// response in full — a superset of bgp.go's private routingStatusData,
// kept as its own type so this file has no compile dependency on that
// private shape and can evolve independently.
type routingStatusDetailedData struct {
	Resource string `json:"resource"`
	Origins  []struct {
		Origin       int      `json:"origin"`
		RouteObjects []string `json:"route_objects"`
	} `json:"origins"`
	Visibility struct {
		V4 *struct {
			RISPeersSeeing int `json:"ris_peers_seeing"`
			TotalRISPeers  int `json:"total_ris_peers"`
		} `json:"v4"`
		V6 *struct {
			RISPeersSeeing int `json:"ris_peers_seeing"`
			TotalRISPeers  int `json:"total_ris_peers"`
		} `json:"v6"`
	} `json:"visibility"`
	FirstSeen *struct {
		Time   string          `json:"time"`
		Origin json.RawMessage `json:"origin"` // ASN as either a bare number or an "ASxxxx" string, depending on RIPEstat version
		Prefix string          `json:"prefix"`
	} `json:"first_seen"`
	LastSeen *struct {
		Time   string          `json:"time"`
		Origin json.RawMessage `json:"origin"`
		Prefix string          `json:"prefix"`
	} `json:"last_seen"`
	AnnouncedSpace struct {
		V4 *struct {
			Prefixes int64 `json:"prefixes"`
			IPs      int64 `json:"ips"`
		} `json:"v4"`
		V6 *struct {
			Prefixes int64 `json:"prefixes"`
			Slash48s int64 `json:"48s"`
		} `json:"v6"`
	} `json:"announced_space"`
	ObservedNeighbours int    `json:"observed_neighbours"`
	QueryTime          string `json:"query_time"`
}

// RoutingStatusDetailedQuery calls the same routing-status endpoint as
// RoutingStatus but decodes the full response — visibility per family,
// first/last seen, announced space, observed neighbours — instead of just
// origins/announced/prefix. RoutingStatus/RouteStatus and their existing
// callers (stage_routing_security.go, BGPRoutingStatus) are untouched.
func (c *Client) RoutingStatusDetailedQuery(ctx context.Context, resource string) RoutingStatusDetailed {
	res := RoutingStatusDetailed{Resource: strings.TrimSpace(resource)}

	// Local validation before any network access — reuses ClassifyResource
	// (resource.go) rather than duplicating parsing logic, and queries
	// RIPEstat with the NORMALIZED form it returns (e.g. "as3333" ->
	// "AS3333", "192.0.2.7/24" -> "192.0.2.0/24"), never the raw input.
	kind, normalized := ClassifyResource(resource)
	if kind == KindInvalid {
		res.Err = fmt.Sprintf("recurso inválido: %q", resource)
		res.Evidence = ComponentEvidence{Component: "routing-status", Status: ComponentNotApplicable}
		return res
	}

	cacheKey := "routing-status|" + normalized
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(RoutingStatusDetailed)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchRoutingStatusDetailed(ctx, normalized)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, routingStatusTTL)
	}
	return result
}

func (c *Client) fetchRoutingStatusDetailed(ctx context.Context, normalized string) RoutingStatusDetailed {
	res := RoutingStatusDetailed{Resource: normalized}
	dataSent := fmt.Sprintf("recurso %s", normalized)
	var data routingStatusDetailedData
	if err := c.get(ctx, "routing-status", urlValuesResource(normalized), &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "routing-status",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.Prefix = data.Resource
	for _, o := range data.Origins {
		res.Origins = append(res.Origins, RouteOrigin{Origin: o.Origin, RouteObjects: o.RouteObjects})
	}
	res.Announced = len(res.Origins) > 0

	if data.Visibility.V4 != nil {
		v := newVisibility("v4", data.Visibility.V4.RISPeersSeeing, data.Visibility.V4.TotalRISPeers)
		res.VisibilityV4 = &v
	}
	if data.Visibility.V6 != nil {
		v := newVisibility("v6", data.Visibility.V6.RISPeersSeeing, data.Visibility.V6.TotalRISPeers)
		res.VisibilityV6 = &v
	}

	if data.FirstSeen != nil {
		res.FirstSeen = &SeenEvent{Time: data.FirstSeen.Time, Origin: parseOriginASN(data.FirstSeen.Origin), Prefix: data.FirstSeen.Prefix}
	}
	if data.LastSeen != nil {
		res.LastSeen = &SeenEvent{Time: data.LastSeen.Time, Origin: parseOriginASN(data.LastSeen.Origin), Prefix: data.LastSeen.Prefix}
	}

	if data.AnnouncedSpace.V4 != nil {
		res.AnnouncedSpaceV4 = &AnnouncedSpaceV4{Prefixes: data.AnnouncedSpace.V4.Prefixes, IPs: data.AnnouncedSpace.V4.IPs}
	}
	if data.AnnouncedSpace.V6 != nil {
		res.AnnouncedSpaceV6 = &AnnouncedSpaceV6{Prefixes: data.AnnouncedSpace.V6.Prefixes, Slash48s: data.AnnouncedSpace.V6.Slash48s}
	}

	res.ObservedNeighbours = data.ObservedNeighbours
	res.QueryTime = data.QueryTime
	res.Evidence = ComponentEvidence{
		Component:  "routing-status",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}

// urlValuesResource builds the standard single-"resource"-param query used
// by most RIPEstat endpoints.
func urlValuesResource(resource string) url.Values {
	return url.Values{"resource": {resource}}
}

// parseOriginASN decodes a RIPEstat "origin" field that may arrive as
// either a bare JSON number or a string (optionally "AS"-prefixed) — RIS
// data has varied on this across endpoint versions. Returns 0 (never a
// panic, never a fabricated ASN) if raw is empty or unparseable.
func parseOriginASN(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
			s = s[2:]
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return 0
}
