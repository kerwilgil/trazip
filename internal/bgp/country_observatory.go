// Country Observatory — v1.3 Gate 1 (BGP_INTELLIGENCE_ROADMAP v1.3 §Observatory
// "Country / ASN / Prefix / Global statistics"). A single point-in-time query
// over RIPEstat's country-resource-stats endpoint for a closed
// [StartTime, EndTime) window at one of four fixed resolutions — never a
// subscription, never polling, never realtime. Reports aggregate
// registration and routing-visibility counts for one ISO alpha-2 country,
// nothing more: this endpoint has no concept of health, risk, security,
// adoption, attack, hijack, or provider/customer relationships, and this
// file never invents one.
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// countryObservatoryMaxWindow bounds every CountryObservatory request window
// per resolution — RIPEstat itself imposes no such cap, so TRAZIP must
// (same rationale as bgpTimeRangeMax in history.go). Bounds are fixed
// durations (365-day years), never calendar arithmetic, so a boundary is
// exactly reproducible independent of which real dates a caller happens to
// pick.
var countryObservatoryMaxWindow = map[string]time.Duration{
	"5m": 72 * time.Hour,
	"1h": 31 * 24 * time.Hour,
	"1d": 2 * 365 * 24 * time.Hour,
	"1w": 10 * 365 * 24 * time.Hour,
}

// CountryObservatoryRequest is one closed-window country-resource-stats
// query — never open ended, resolution always one of the four fixed values
// countryObservatoryMaxWindow knows about.
type CountryObservatoryRequest struct {
	Country    string // ISO alpha-2, case-insensitive on input, normalized uppercase
	StartTime  string // RFC3339, obligatorio
	EndTime    string // RFC3339, obligatorio
	Resolution string // "5m" | "1h" | "1d" | "1w", obligatorio, exact match
}

// CountryObservatoryPoint is one stats[] entry, decoded losslessly.
// StatsData is the wire's own stats_data value preserved verbatim as a
// string — its real shape is not a boolean (Gate 1 P1-1 correction: an
// earlier revision of this file wrongly decoded it as bool and derived
// DataSufficient from it; both were wrong). This package never parses,
// interprets, or branches on StatsData's content — it is opaque,
// pass-through data. Whether a point is "empty" or a real observation is
// decided at the CountryObservatoryResult level by whether Points is
// non-empty (§21 "Empty stats != zero-valued data" — an empty Points
// slice vs. a point present with real, possibly zero-valued counts).
type CountryObservatoryPoint struct {
	StatsData string `json:"statsData"`

	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`

	// *RIS fields are RIPEstat/RIS-observed routing counts — what is
	// actually seen announced. *Registered fields are registry-derived
	// registration counts (decoded from the wire's own *_stats fields,
	// Gate 1 P1-3 rename — never conflated with the wire naming) — what
	// is delegated to the country. The two are never conflated: a
	// resource can be registered without being routed, and this package
	// never labels that state "inactive" or anything else beyond the two
	// counts themselves (§22-23).
	ASNsRIS                int `json:"asnsRis"`
	ASNsRegistered         int `json:"asnsRegistered"`
	IPv4PrefixesRIS        int `json:"ipv4PrefixesRis"`
	IPv4PrefixesRegistered int `json:"ipv4PrefixesRegistered"`
	IPv6PrefixesRIS        int `json:"ipv6PrefixesRis"`
	IPv6PrefixesRegistered int `json:"ipv6PrefixesRegistered"`
}

// CountryObservatoryResult is the bounded, honest result of one
// CountryObservatoryRequest.
type CountryObservatoryResult struct {
	Country    string `json:"country"`
	StartTime  string `json:"startTime"`
	EndTime    string `json:"endTime"`
	Resolution string `json:"resolution"`

	// QueryStartTime/QueryEndTime/EarliestTime/LatestTime/HDLatestTime are
	// RIPEstat's own declared values, preserved verbatim (§19-20) —
	// never derived from the request's StartTime/EndTime, which are what
	// TRAZIP asked for, not necessarily what RIPEstat says it actually
	// covers.
	QueryStartTime string `json:"queryStartTime"`
	QueryEndTime   string `json:"queryEndTime"`
	EarliestTime   string `json:"earliestTime"`
	LatestTime     string `json:"latestTime"`
	HDLatestTime   string `json:"hdLatestTime"`

	Points []CountryObservatoryPoint `json:"points"`

	// DataSufficient is true iff the HTTP call and decode both succeeded
	// AND len(Points) > 0 (Gate 1 P1-1 correction, §29 as re-scoped —
	// StatsData's real string shape carries no known true/false signal,
	// so sufficiency can no longer be derived from it). An empty stats[]
	// on an otherwise-successful call yields Points=[] and
	// DataSufficient=false; it is never fabricated into a zero-valued
	// point (§21 "Empty stats != zero-valued data").
	DataSufficient bool `json:"dataSufficient"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// countryResourceStatsData mirrors RIPEstat's real country-resource-stats
// response shape (stat.ripe.net/docs/02.data-api/country-resource-stats),
// per the Gate 1 wire contract.
type countryResourceStatsData struct {
	QueryStartTime string                          `json:"query_starttime"`
	QueryEndTime   string                          `json:"query_endtime"`
	EarliestTime   string                          `json:"earliest_time"`
	LatestTime     string                          `json:"latest_time"`
	HDLatestTime   string                          `json:"hd_latest_time"`
	Stats          []countryResourceStatsPointWire `json:"stats"`
}

type countryResourceStatsPointWire struct {
	StatsData string `json:"stats_data"`
	StatsDate string `json:"stats_date"`
	Timeline  struct {
		StartTime string `json:"starttime"`
		EndTime   string `json:"endtime"`
	} `json:"timeline"`
	ASNsRIS         int `json:"asns_ris"`
	ASNsStats       int `json:"asns_stats"`
	V4PrefixesRIS   int `json:"v4_prefixes_ris"`
	V4PrefixesStats int `json:"v4_prefixes_stats"`
	V6PrefixesRIS   int `json:"v6_prefixes_ris"`
	V6PrefixesStats int `json:"v6_prefixes_stats"`
}

// UnmarshalJSON accepts both country-resource-stats timeline shapes observed
// from RIPEstat: the historical object and the current one-element array.
func (p *countryResourceStatsPointWire) UnmarshalJSON(data []byte) error {
	var raw struct {
		StatsData       string          `json:"stats_data"`
		StatsDate       string          `json:"stats_date"`
		Timeline        json.RawMessage `json:"timeline"`
		ASNsRIS         int             `json:"asns_ris"`
		ASNsStats       int             `json:"asns_stats"`
		V4PrefixesRIS   int             `json:"v4_prefixes_ris"`
		V4PrefixesStats int             `json:"v4_prefixes_stats"`
		V6PrefixesRIS   int             `json:"v6_prefixes_ris"`
		V6PrefixesStats int             `json:"v6_prefixes_stats"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = countryResourceStatsPointWire{
		StatsData: raw.StatsData, StatsDate: raw.StatsDate,
		ASNsRIS: raw.ASNsRIS, ASNsStats: raw.ASNsStats,
		V4PrefixesRIS: raw.V4PrefixesRIS, V4PrefixesStats: raw.V4PrefixesStats,
		V6PrefixesRIS: raw.V6PrefixesRIS, V6PrefixesStats: raw.V6PrefixesStats,
	}
	if len(raw.Timeline) == 0 || string(raw.Timeline) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw.Timeline, &p.Timeline); err == nil {
		return nil
	}
	var timeline []struct {
		StartTime string `json:"starttime"`
		EndTime   string `json:"endtime"`
	}
	if err := json.Unmarshal(raw.Timeline, &timeline); err != nil {
		return err
	}
	if len(timeline) > 0 {
		p.Timeline.StartTime = timeline[0].StartTime
		p.Timeline.EndTime = timeline[0].EndTime
	}
	return nil
}

// isoAlpha2CountryCodesList enumerates every ISO 3166-1 alpha-2 code
// officially assigned to a country or territory (249 entries, current
// standard) — kept as one space-separated constant, not a struct literal,
// so the whole list stays reviewable as a single block. Deliberately
// excludes every user-assigned code element (AA, QM-QZ, XA-XZ, ZZ per the
// standard's own reserved ranges — Gate 1 P1-2 §14 "No aceptar
// user-assigned/reserved codes") and every exceptionally/transitionally
// reserved code that is not itself an officially assigned element (e.g.
// EU, UK are reserved by exception, not assigned). No external package —
// this is a fixed, small, rarely-changing list, so a hardcoded local
// constant is simpler and has zero supply-chain/network surface (§12-13).
const isoAlpha2CountryCodesList = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ " +
	"BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ " +
	"DE DJ DK DM DO DZ " +
	"EC EE EG EH ER ES ET " +
	"FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY " +
	"HK HM HN HR HT HU " +
	"ID IE IL IM IN IO IQ IR IS IT " +
	"JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ " +
	"LA LB LC LI LK LR LS LT LU LV LY " +
	"MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
	"NA NC NE NF NG NI NL NO NP NR NU NZ " +
	"OM " +
	"PA PE PF PG PH PK PL PM PN PR PS PT PW PY " +
	"QA " +
	"RE RO RS RU RW " +
	"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ " +
	"TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ " +
	"UA UG UM US UY UZ " +
	"VA VC VE VG VI VN VU " +
	"WF WS " +
	"YE YT " +
	"ZA ZM ZW"

// isoAlpha2Countries is the lookup form of isoAlpha2CountryCodesList,
// built once at package init. A country string is a real, accepted
// country iff it is an exact key in this map — no length/format
// pre-check is needed separately, since every non-conforming input
// (wrong length, lowercase, digits, punctuation) simply isn't a key.
var isoAlpha2Countries = func() map[string]bool {
	fields := strings.Fields(isoAlpha2CountryCodesList)
	m := make(map[string]bool, len(fields))
	for _, code := range fields {
		m[code] = true
	}
	return m
}()

// validateCountryObservatoryRequest enforces the full Gate 1 local contract
// entirely before any network access (§15 "Invalid local request => zero
// HTTP calls"): country normalizes to exactly two uppercase letters,
// resolution is exactly one of the four fixed values, both timestamps
// mandatory RFC3339, Start strictly before End, and the window no wider
// than countryObservatoryMaxWindow[resolution]. A request that fails here
// costs zero HTTP calls and is never silently clamped (§16).
func validateCountryObservatoryRequest(req CountryObservatoryRequest) (country, resolution string, err error) {
	country = strings.ToUpper(strings.TrimSpace(req.Country))
	if !isoAlpha2Countries[country] {
		return "", "", fmt.Errorf("country inválido (se espera código ISO 3166-1 alpha-2 oficialmente asignado): %q", req.Country)
	}

	resolution = strings.TrimSpace(req.Resolution)
	maxWindow, ok := countryObservatoryMaxWindow[resolution]
	if !ok {
		return "", "", fmt.Errorf("resolution inválida (se espera exactamente 5m|1h|1d|1w): %q", req.Resolution)
	}

	if strings.TrimSpace(req.StartTime) == "" {
		return "", "", fmt.Errorf("StartTime vacío — obligatorio y explícito")
	}
	if strings.TrimSpace(req.EndTime) == "" {
		return "", "", fmt.Errorf("EndTime vacío — obligatorio")
	}
	st, perr := time.Parse(time.RFC3339, req.StartTime)
	if perr != nil {
		return "", "", fmt.Errorf("StartTime inválido (se espera RFC3339): %w", perr)
	}
	et, perr := time.Parse(time.RFC3339, req.EndTime)
	if perr != nil {
		return "", "", fmt.Errorf("EndTime inválido (se espera RFC3339): %w", perr)
	}
	if !st.Before(et) {
		return "", "", fmt.Errorf("StartTime (%s) debe ser anterior a EndTime (%s)", req.StartTime, req.EndTime)
	}
	if d := et.Sub(st); d > maxWindow {
		return "", "", fmt.Errorf("rango temporal %s excede el máximo permitido de %s para resolution=%s — nunca recortado silenciosamente, la petición se rechaza completa", d, maxWindow, resolution)
	}
	return country, resolution, nil
}

// countryObservatoryWireTime serializes an already-validated RFC3339 input
// in the subset accepted by RIPEstat. JavaScript Date.toISOString() includes
// fractional seconds (for example .000Z), which country-resource-stats
// rejects with HTTP 400 even though it is valid RFC3339. The public request
// remains RFC3339; only the outbound wire representation is normalized.
func countryObservatoryWireTime(value string) (string, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(time.RFC3339), nil
}

// CountryObservatory queries country-resource-stats for req.Country over
// [req.StartTime, req.EndTime) at req.Resolution — one HTTP call,
// user-initiated, never polling, never a background timer or goroutine.
// Any local validation failure short-circuits before any network access,
// Evidence.Status = ComponentNotApplicable, Err honest and specific.
func (c *Client) CountryObservatory(ctx context.Context, req CountryObservatoryRequest) CountryObservatoryResult {
	res := CountryObservatoryResult{
		Country:    strings.ToUpper(strings.TrimSpace(req.Country)),
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		Resolution: req.Resolution,
		Points:     []CountryObservatoryPoint{},
	}

	country, resolution, err := validateCountryObservatoryRequest(req)
	if err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{Component: "country-resource-stats", Status: ComponentNotApplicable}}
		return res
	}
	res.Country = country
	res.Resolution = resolution
	wireStartTime, err := countryObservatoryWireTime(req.StartTime)
	if err != nil {
		res.Err = fmt.Sprintf("StartTime inválido para serialización wire: %v", err)
		res.Evidence = []ComponentEvidence{{Component: "country-resource-stats", Status: ComponentNotApplicable}}
		return res
	}
	wireEndTime, err := countryObservatoryWireTime(req.EndTime)
	if err != nil {
		res.Err = fmt.Sprintf("EndTime inválido para serialización wire: %v", err)
		res.Evidence = []ComponentEvidence{{Component: "country-resource-stats", Status: ComponentNotApplicable}}
		return res
	}

	dataSent := fmt.Sprintf("country %s, rango [%s, %s], resolution %s", country, req.StartTime, req.EndTime, resolution)
	params := url.Values{
		"resource":   {country},
		"starttime":  {wireStartTime},
		"endtime":    {wireEndTime},
		"resolution": {resolution},
	}

	var data countryResourceStatsData
	if err := c.get(ctx, "country-resource-stats", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{
			Component:  "country-resource-stats",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	res.QueryStartTime = data.QueryStartTime
	res.QueryEndTime = data.QueryEndTime
	res.EarliestTime = data.EarliestTime
	res.LatestTime = data.LatestTime
	res.HDLatestTime = data.HDLatestTime

	points := make([]CountryObservatoryPoint, len(data.Stats))
	for i, s := range data.Stats {
		statsData := s.StatsData
		if statsData == "" {
			statsData = s.StatsDate
		}
		points[i] = CountryObservatoryPoint{
			StatsData:              statsData,
			StartTime:              s.Timeline.StartTime,
			EndTime:                s.Timeline.EndTime,
			ASNsRIS:                s.ASNsRIS,
			ASNsRegistered:         s.ASNsStats,
			IPv4PrefixesRIS:        s.V4PrefixesRIS,
			IPv4PrefixesRegistered: s.V4PrefixesStats,
			IPv6PrefixesRIS:        s.V6PrefixesRIS,
			IPv6PrefixesRegistered: s.V6PrefixesStats,
		}
	}
	res.Points = points
	// DataSufficient = HTTP/decode succeeded (guaranteed at this point in
	// the function) AND len(data.Stats) > 0 — never derived from
	// StatsData's content (Gate 1 P1-1 correction).
	res.DataSufficient = len(data.Stats) > 0

	res.Evidence = []ComponentEvidence{{
		Component:  "country-resource-stats",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}}
	return res
}
