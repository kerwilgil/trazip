package bgp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// --- fixture helpers ---

func countryStatsEnvelope(t *testing.T, stats []map[string]any) string {
	t.Helper()
	data := map[string]any{
		"query_starttime": "2026-08-01T00:00:00",
		"query_endtime":   "2026-08-02T00:00:00",
		"earliest_time":   "2000-08-01T00:00:00",
		"latest_time":     "2026-08-16T00:00:00",
		"hd_latest_time":  "2026-08-16T08:00:00",
		"stats":           stats,
	}
	env := map[string]any{"status": "ok", "data": data}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

func countryStatsFixtureServer(t *testing.T, body string) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
}

func onePoint(statsData string, asnsRis, asnsStats, v4Ris, v4Stats, v6Ris, v6Stats int) map[string]any {
	return map[string]any{
		"stats_data":        statsData,
		"timeline":          map[string]any{"starttime": "2026-08-01T00:00:00", "endtime": "2026-08-01T01:00:00"},
		"asns_ris":          asnsRis,
		"asns_stats":        asnsStats,
		"v4_prefixes_ris":   v4Ris,
		"v4_prefixes_stats": v4Stats,
		"v6_prefixes_ris":   v6Ris,
		"v6_prefixes_stats": v6Stats,
	}
}

const (
	coStart = "2026-08-01T00:00:00Z"
	coEnd   = "2026-08-01T01:00:00Z" // 1h window, valid for every resolution
)

func validCountryReq() CountryObservatoryRequest {
	return CountryObservatoryRequest{Country: "PA", StartTime: coStart, EndTime: coEnd, Resolution: "1h"}
}

// --- 30-31: valid country normalization ---

func TestCountryObservatory_LowercasePA_NormalizedUppercase(t *testing.T) {
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)}))
	c := &Client{BaseURL: addr}
	req := validCountryReq()
	req.Country = "pa"
	res := c.CountryObservatory(context.Background(), req)
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Country != "PA" {
		t.Errorf("Country = %q, want %q", res.Country, "PA")
	}
}

func TestCountryObservatory_ValidUS(t *testing.T) {
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)}))
	c := &Client{BaseURL: addr}
	req := validCountryReq()
	req.Country = "US"
	res := c.CountryObservatory(context.Background(), req)
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Country != "US" {
		t.Errorf("Country = %q, want %q", res.Country, "US")
	}
}

func TestCountryObservatory_WireTimesDropRFC3339FractionalSeconds(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got, want := q.Get("resource"), "PA"; got != want {
			t.Errorf("resource = %q, want %q", got, want)
		}
		if got, want := q.Get("starttime"), "2026-08-01T05:00:00Z"; got != want {
			t.Errorf("starttime = %q, want %q", got, want)
		}
		if got, want := q.Get("endtime"), "2026-08-08T05:00:00Z"; got != want {
			t.Errorf("endtime = %q, want %q", got, want)
		}
		w.Write([]byte(countryStatsEnvelope(t, nil)))
	})
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), CountryObservatoryRequest{
		Country: "PA", StartTime: "2026-08-01T05:00:00.000Z", EndTime: "2026-08-08T05:00:00.000Z", Resolution: "1d",
	})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if got, want := res.StartTime, "2026-08-01T05:00:00.000Z"; got != want {
		t.Errorf("StartTime = %q, want public request preserved as %q", got, want)
	}
}

func TestCountryObservatory_CurrentLiveWireShape_Decodes(t *testing.T) {
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{{
		"stats_date": "2026-08-02T00:00:00",
		"timeline":   []map[string]any{{"starttime": "2026-08-02T00:00:00", "endtime": "2026-08-02T00:00:00"}},
		"asns_ris":   90, "asns_stats": 151,
		"v4_prefixes_ris": 3253, "v4_prefixes_stats": -1,
		"v6_prefixes_ris": 374, "v6_prefixes_stats": -1,
	}}))
	res := (&Client{BaseURL: addr}).CountryObservatory(context.Background(), validCountryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1", len(res.Points))
	}
	p := res.Points[0]
	if p.StatsData != "2026-08-02T00:00:00" || p.StartTime != "2026-08-02T00:00:00" {
		t.Errorf("point = %+v, want stats_date and array timeline preserved", p)
	}
	if p.ASNsRIS != 90 || p.ASNsRegistered != 151 || p.IPv4PrefixesRIS != 3253 || p.IPv6PrefixesRIS != 374 {
		t.Errorf("point counts = %+v, want live wire values", p)
	}
}

// Gate 1 P1-2 rule 10: additional officially-assigned codes beyond
// PA/US, proving the whitelist isn't a two-entry special case.
func TestCountryObservatory_ValidES_DE(t *testing.T) {
	for _, cc := range []string{"ES", "DE"} {
		t.Run(cc, func(t *testing.T) {
			addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)}))
			c := &Client{BaseURL: addr}
			req := validCountryReq()
			req.Country = cc
			res := c.CountryObservatory(context.Background(), req)
			if res.Err != "" {
				t.Fatalf("unexpected Err for %q: %s", cc, res.Err)
			}
			if res.Country != cc {
				t.Errorf("Country = %q, want %q", res.Country, cc)
			}
		})
	}
}

// Gate 1 P1-2: the whitelist must contain exactly the officially assigned
// ISO 3166-1 alpha-2 set (249 entries) — a regression guard against
// accidental additions/removals to isoAlpha2CountryCodesList.
func TestCountryObservatory_ISOAlpha2Whitelist_ExactCount(t *testing.T) {
	if got := len(isoAlpha2Countries); got != 249 {
		t.Errorf("len(isoAlpha2Countries) = %d, want 249", got)
	}
}

// Gate 1 P1-2 rule 11/14: reserved/unassigned code elements (user-assigned
// AA, QM-QZ range, XA-XZ range, ZZ) must be rejected LOCALLY — never
// treated as real countries just because they're two uppercase letters.
// This is the exact regression the pre-fix isISOAlpha2 (format-only) would
// have missed: every one of these passed the old check and would have
// gone to network.
func TestCountryObservatory_ReservedOrUnassignedCodes_Rejected_ZeroHTTP(t *testing.T) {
	cases := []string{"ZZ", "XX", "AA", "QM", "XA"}
	for _, cc := range cases {
		t.Run(cc, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			req := validCountryReq()
			req.Country = cc
			res := c.CountryObservatory(context.Background(), req)
			if res.Err == "" {
				t.Fatalf("Err empty for reserved/unassigned code %q, want a rejection", cc)
			}
			if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
			}
		})
	}
}

// --- 32: invalid country names, zero HTTP ---

func TestCountryObservatory_InvalidCountryNames_ZeroHTTP(t *testing.T) {
	cases := []string{"USA", "PANAMA", "P", "PAN", "1A", "P4", "P A", "--"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			req := validCountryReq()
			req.Country = name
			res := c.CountryObservatory(context.Background(), req)
			if res.Err == "" {
				t.Fatalf("Err empty for country %q, want a rejection", name)
			}
			if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
			}
		})
	}
}

// --- 33: invalid ASN/IP/prefix as Country, zero HTTP ---

func TestCountryObservatory_ResourceShapesAsCountry_Rejected_ZeroHTTP(t *testing.T) {
	cases := []string{"AS13335", "13335", "1.1.1.1", "1.1.1.0/24", "2001:db8::1"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			req := validCountryReq()
			req.Country = name
			res := c.CountryObservatory(context.Background(), req)
			if res.Err == "" {
				t.Fatalf("Err empty for %q, want a rejection", name)
			}
			if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
			}
		})
	}
}

// --- 34: empty Country, zero HTTP ---

func TestCountryObservatory_EmptyCountry_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.Country = ""
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
		t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
	}
}

// --- 35: malformed timestamps, zero HTTP ---

func TestCountryObservatory_MalformedStartTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.StartTime = "not-a-time"
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestCountryObservatory_MalformedEndTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.EndTime = "not-a-time"
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestCountryObservatory_EmptyStartTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.StartTime = ""
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestCountryObservatory_EmptyEndTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.EndTime = ""
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

// --- 36-37: Start == End, Start > End ---

func TestCountryObservatory_StartEqualsEnd_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.EndTime = req.StartTime
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestCountryObservatory_StartAfterEnd_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	req := validCountryReq()
	req.StartTime, req.EndTime = coEnd, coStart
	res := c.CountryObservatory(context.Background(), req)
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

// --- 38: every allowed resolution ---

func TestCountryObservatory_EveryAllowedResolution_Accepted(t *testing.T) {
	for _, res := range []string{"5m", "1h", "1d", "1w"} {
		t.Run(res, func(t *testing.T) {
			addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)}))
			c := &Client{BaseURL: addr}
			req := validCountryReq()
			req.Resolution = res
			result := c.CountryObservatory(context.Background(), req)
			if result.Err != "" {
				t.Fatalf("unexpected Err for resolution %q: %s", res, result.Err)
			}
			if result.Resolution != res {
				t.Errorf("Resolution = %q, want %q", result.Resolution, res)
			}
		})
	}
}

func TestCountryObservatory_InvalidResolution_ZeroHTTP(t *testing.T) {
	cases := []string{"5M", "1H", "1D", "1W", "10m", "2h", "hour", "", "1m", "1y"}
	for _, res := range cases {
		t.Run(res, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			req := validCountryReq()
			req.Resolution = res
			result := c.CountryObservatory(context.Background(), req)
			if result.Err == "" {
				t.Fatalf("Err empty for resolution %q, want a rejection", res)
			}
			if len(result.Evidence) != 1 || result.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", result.Evidence)
			}
		})
	}
}

// --- 39-40: resolution boundaries, exact max => PASS, max+1s => rejection ---

func TestCountryObservatory_ResolutionBoundaries_ExactMax_Accepted(t *testing.T) {
	base, err := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("parse base time: %v", err)
	}
	for res, maxWindow := range countryObservatoryMaxWindow {
		t.Run(res, func(t *testing.T) {
			start := base
			end := start.Add(maxWindow)
			addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)}))
			c := &Client{BaseURL: addr}
			result := c.CountryObservatory(context.Background(), CountryObservatoryRequest{
				Country:    "PA",
				StartTime:  start.Format(time.RFC3339),
				EndTime:    end.Format(time.RFC3339),
				Resolution: res,
			})
			if result.Err != "" {
				t.Fatalf("unexpected Err at exact max window for resolution %q: %s", res, result.Err)
			}
		})
	}
}

func TestCountryObservatory_ResolutionBoundaries_MaxPlusOneSecond_Rejected_ZeroHTTP(t *testing.T) {
	base, err := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("parse base time: %v", err)
	}
	for res, maxWindow := range countryObservatoryMaxWindow {
		t.Run(res, func(t *testing.T) {
			start := base
			end := start.Add(maxWindow + time.Second)
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			result := c.CountryObservatory(context.Background(), CountryObservatoryRequest{
				Country:    "PA",
				StartTime:  start.Format(time.RFC3339),
				EndTime:    end.Format(time.RFC3339),
				Resolution: res,
			})
			if result.Err == "" {
				t.Fatalf("Err empty for resolution %q at max+1s, want a rejection", res)
			}
			if len(result.Evidence) != 1 || result.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", result.Evidence)
			}
		})
	}
}

// --- 41: wire fixture full decode ---

func TestCountryObservatory_FullDecode(t *testing.T) {
	stats := []map[string]any{
		{
			"stats_data":        "true",
			"timeline":          map[string]any{"starttime": "2026-08-01T00:00:00", "endtime": "2026-08-01T01:00:00"},
			"asns_ris":          10,
			"asns_stats":        12,
			"v4_prefixes_ris":   100,
			"v4_prefixes_stats": 120,
			"v6_prefixes_ris":   5,
			"v6_prefixes_stats": 7,
		},
	}
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, stats))
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.QueryStartTime != "2026-08-01T00:00:00" || res.QueryEndTime != "2026-08-02T00:00:00" {
		t.Errorf("QueryStartTime/QueryEndTime not preserved: %q/%q", res.QueryStartTime, res.QueryEndTime)
	}
	if res.EarliestTime != "2000-08-01T00:00:00" || res.LatestTime != "2026-08-16T00:00:00" || res.HDLatestTime != "2026-08-16T08:00:00" {
		t.Errorf("earliest/latest/hd_latest not preserved: %q/%q/%q", res.EarliestTime, res.LatestTime, res.HDLatestTime)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1", len(res.Points))
	}
	p := res.Points[0]
	if p.StatsData != "true" {
		t.Errorf("StatsData = %q, want %q (preserved verbatim as string, never parsed as bool)", p.StatsData, "true")
	}
	if p.StartTime != "2026-08-01T00:00:00" || p.EndTime != "2026-08-01T01:00:00" {
		t.Errorf("StartTime/EndTime not preserved: %q/%q", p.StartTime, p.EndTime)
	}
	if p.ASNsRIS != 10 || p.ASNsRegistered != 12 {
		t.Errorf("ASNsRIS/ASNsRegistered = %d/%d, want 10/12", p.ASNsRIS, p.ASNsRegistered)
	}
	if p.IPv4PrefixesRIS != 100 || p.IPv4PrefixesRegistered != 120 {
		t.Errorf("IPv4PrefixesRIS/Registered = %d/%d, want 100/120", p.IPv4PrefixesRIS, p.IPv4PrefixesRegistered)
	}
	if p.IPv6PrefixesRIS != 5 || p.IPv6PrefixesRegistered != 7 {
		t.Errorf("IPv6PrefixesRIS/Registered = %d/%d, want 5/7", p.IPv6PrefixesRIS, p.IPv6PrefixesRegistered)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — one valid point present")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentOK {
		t.Errorf("Evidence = %+v, want single ComponentOK entry", res.Evidence)
	}
}

// --- 42: empty stats ---

func TestCountryObservatory_EmptyStats_DataInsufficient(t *testing.T) {
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{}))
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 0 {
		t.Errorf("Points = %v, want empty", res.Points)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false — empty stats[]")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentOK {
		t.Errorf("Evidence = %+v, want single ComponentOK entry — the query itself succeeded, it's the source that had nothing", res.Evidence)
	}
}

// Gate 1 P1-1 correction: StatsData is an opaque wire string, never a
// bool, and DataSufficient never derives from its content — only from
// len(Points) > 0 on an otherwise-successful call. A point whose
// stats_data literally spells "false" must be preserved verbatim AND
// still count toward DataSufficient — proving the old (wrong) bool
// interpretation is gone, not just renamed.
func TestCountryObservatory_StatsDataStringSayingFalse_StillSufficient_PreservedVerbatim(t *testing.T) {
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint("false", 0, 0, 0, 0, 0, 0)}))
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1 — the point exists on the wire and must be preserved", len(res.Points))
	}
	if res.Points[0].StatsData != "false" {
		t.Errorf("StatsData = %q, want %q — preserved verbatim from wire, never parsed", res.Points[0].StatsData, "false")
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — one point present, regardless of what StatsData says")
	}
	if res.Points[0].ASNsRIS != 0 {
		t.Errorf("ASNsRIS = %d, want 0 (real zero, not absent)", res.Points[0].ASNsRIS)
	}
}

// Gate 1 P1-1 rule 6-7: a real timestamp-shaped stats_data value must
// arrive at the result identical to what the wire sent — no reformatting,
// no reinterpretation, no truncation.
func TestCountryObservatory_StatsDataRealTimestampString_PreservedIdentical(t *testing.T) {
	const wireValue = "2026-08-20T00:00:00"
	addr := countryStatsFixtureServer(t, countryStatsEnvelope(t, []map[string]any{onePoint(wireValue, 1, 1, 1, 1, 1, 1)}))
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1", len(res.Points))
	}
	if res.Points[0].StatsData != wireValue {
		t.Errorf("StatsData = %q, want %q identical to wire", res.Points[0].StatsData, wireValue)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — one point present")
	}
}

// --- 43: malformed source response ---

func TestCountryObservatory_MalformedJSON_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if len(res.Points) != 0 {
		t.Errorf("Points = %v, want empty", res.Points)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- 44: HTTP error ---

func TestCountryObservatory_DatasourceHTTPError_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	res := c.CountryObservatory(context.Background(), validCountryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a datasource error")
	}
	if len(res.Points) != 0 {
		t.Errorf("Points = %v, want empty — never fabricated on failure", res.Points)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- 45: context cancellation/timeout ---

func TestCountryObservatory_ContextCanceled_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		// never actually reached — context is canceled before the call
		w.Write([]byte(countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)})))
	})
	c := &Client{BaseURL: addr}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.CountryObservatory(ctx, validCountryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a context-canceled error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestCountryObservatory_ContextTimeout_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(countryStatsEnvelope(t, []map[string]any{onePoint("true", 1, 1, 1, 1, 1, 1)})))
	})
	c := &Client{BaseURL: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	res := c.CountryObservatory(ctx, validCountryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a timeout error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- 46: prove zero network calls for every validation rejection path, combined ---

func TestCountryObservatory_EveryLocalRejection_ZeroNetworkCalls(t *testing.T) {
	base := validCountryReq()

	invalid := []CountryObservatoryRequest{
		withCountry(base, "USA"),
		withCountry(base, "1.1.1.1"),
		withCountry(base, ""),
		withResolution(base, "10m"),
		withResolution(base, ""),
		withTimes(base, "", coEnd),
		withTimes(base, coStart, ""),
		withTimes(base, "bad", coEnd),
		withTimes(base, coStart, "bad"),
		withTimes(base, coStart, coStart),
		withTimes(base, coEnd, coStart),
	}

	for i, req := range invalid {
		t.Run(req.Country+"_"+req.Resolution+"_"+string(rune('a'+i)), func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			res := c.CountryObservatory(context.Background(), req)
			if res.Err == "" {
				t.Fatalf("case %d: Err empty, want a rejection", i)
			}
		})
	}
}

func withCountry(req CountryObservatoryRequest, country string) CountryObservatoryRequest {
	req.Country = country
	return req
}

func withResolution(req CountryObservatoryRequest, resolution string) CountryObservatoryRequest {
	req.Resolution = resolution
	return req
}

func withTimes(req CountryObservatoryRequest, start, end string) CountryObservatoryRequest {
	req.StartTime = start
	req.EndTime = end
	return req
}

// --- scope: no new goroutines/timers — CountryObservatory is a single
// synchronous call, verified by the fact every test above runs to
// completion without any background state surviving the call.
