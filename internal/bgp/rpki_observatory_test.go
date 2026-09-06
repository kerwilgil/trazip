package bgp

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// --- fixture helpers ---

func rpkiDailyFixtureBody(points []map[string]any) string {
	data := map[string]any{"timeseries": points}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

func rpkiDailyPoint(t string, vrpCount any) map[string]any {
	p := map[string]any{"time": t, "rpki": map[string]any{"vrp_count": vrpCount}}
	return p
}

// rpkiDailyPointNoTime/rpkiDailyPointNoVRPCount build a point missing the
// named field entirely (not present-as-empty/zero) — used to test
// structural-incompleteness detection.
func rpkiDailyPointNoTime(vrpCount int) map[string]any {
	return map[string]any{"rpki": map[string]any{"vrp_count": vrpCount}}
}

func rpkiDailyPointNoVRPCount(t string) map[string]any {
	return map[string]any{"time": t, "rpki": map[string]any{}}
}

func rpkiAggFixtureBody(points []map[string]any) string {
	data := map[string]any{"timeseries": points}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

func rpkiAggPoint(t string, min, max, avg, first, last, samples any) map[string]any {
	return map[string]any{
		"time": t,
		"rpki": map[string]any{
			"vrp_count": map[string]any{
				"min": min, "max": max, "avg": avg,
				"first": first, "last": last, "samples": samples,
			},
		},
	}
}

func rpkiAggPointMissing(t string, missingField string) map[string]any {
	vrp := map[string]any{"min": 1.0, "max": 2.0, "avg": 1.5, "first": 1.0, "last": 2.0, "samples": 3}
	delete(vrp, missingField)
	return map[string]any{"time": t, "rpki": map[string]any{"vrp_count": vrp}}
}

func rpkiHistoryFixtureServer(t *testing.T, body string) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
}

func validRPKIReq() RPKIObservatoryRequest {
	return RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"}
}

// ================= VALIDATION (1-20) =================

func TestRPKIObservatory_ValidAS13335(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Resource != "AS13335" || res.ResourceKind != "asn" {
		t.Errorf("Resource/Kind = %q/%q, want AS13335/asn", res.Resource, res.ResourceKind)
	}
}

func TestRPKIObservatory_Valid13335_NormalizesSame(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)}))
	a := (&Client{BaseURL: addr}).RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	b := (&Client{BaseURL: addr}).RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "13335", Family: 4, Resolution: "m"})
	if a.Err != "" || b.Err != "" {
		t.Fatalf("unexpected Err: a=%q b=%q", a.Err, b.Err)
	}
	if a.Resource != b.Resource {
		t.Errorf("normalization mismatch: %q vs %q", a.Resource, b.Resource)
	}
}

// Gate 3 scope decision (verified live, approved by the user): prefix
// resources are rejected unconditionally, even when Family matches the
// prefix's own IP version — rpki-history's prefix wire shape is
// incompatible with this Gate's ASN/country contract (no "rpki" wrapper,
// flat scalar vrp_count regardless of resolution, extra count/max_length
// fields; "resolution" has no observable effect on a prefix query at
// all, confirmed live with two different resolutions returning identical
// datasets). This replaces what was originally planned as an acceptance
// test.
func TestRPKIObservatory_IPv4Prefix_RejectedOutOfScope_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "1.1.1.0/24", Family: 4, Resolution: "m"})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection — prefixes are out of Gate 3's scope even with matching Family")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
		t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
	}
}

func TestRPKIObservatory_IPv6Prefix_RejectedOutOfScope_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "2606:4700::/32", Family: 6, Resolution: "m"})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection — prefixes are out of Gate 3's scope even with matching Family")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
		t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
	}
}

func TestRPKIObservatory_ValidPA(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "PA", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Resource != "PA" || res.ResourceKind != "country" {
		t.Errorf("Resource/Kind = %q/%q, want PA/country", res.Resource, res.ResourceKind)
	}
}

func TestRPKIObservatory_LowercasePA_NormalizesToPA(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "pa", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Resource != "PA" {
		t.Errorf("Resource = %q, want PA", res.Resource)
	}
}

func TestRPKIObservatory_LocalRejections_ZeroHTTP(t *testing.T) {
	cases := map[string]RPKIObservatoryRequest{
		"empty resource":       {Resource: "", Family: 4, Resolution: "m"},
		"AS0":                  {Resource: "AS0", Family: 4, Resolution: "m"},
		"zero":                 {Resource: "0", Family: 4, Resolution: "m"},
		"ASN out of range":     {Resource: "4294967296", Family: 4, Resolution: "m"},
		"single IP":            {Resource: "1.1.1.1", Family: 4, Resolution: "m"},
		"hostname":             {Resource: "example.com", Family: 4, Resolution: "m"},
		"reserved country ZZ":  {Resource: "ZZ", Family: 4, Resolution: "m"},
		"reserved country XX":  {Resource: "XX", Family: 4, Resolution: "m"},
		"reserved country AA":  {Resource: "AA", Family: 4, Resolution: "m"},
		"invalid prefix":       {Resource: "1.1.1.0/99", Family: 4, Resolution: "m"},
		"family zero":          {Resource: "AS13335", Family: 0, Resolution: "m"},
		"family five":          {Resource: "AS13335", Family: 5, Resolution: "m"},
		"ipv4 prefix family 6": {Resource: "1.1.1.0/24", Family: 6, Resolution: "m"},
		"ipv6 prefix family 4": {Resource: "2606:4700::/32", Family: 4, Resolution: "m"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			res := c.RPKIObservatory(context.Background(), req)
			if res.Err == "" {
				t.Fatalf("Err empty for %+v, want a rejection", req)
			}
			if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
			}
			if res.DataSufficient {
				t.Error("DataSufficient = true, want false")
			}
		})
	}
}

func TestRPKIObservatory_EveryResolutionValid_Accepted(t *testing.T) {
	for _, res := range []string{"d", "w", "m", "y"} {
		t.Run(res, func(t *testing.T) {
			var addr string
			if res == "d" {
				addr = rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{rpkiDailyPoint("2026-08-01T00:00:00Z", 5)}))
			} else {
				addr = rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)}))
			}
			c := &Client{BaseURL: addr}
			result := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: res})
			if result.Err != "" {
				t.Fatalf("unexpected Err for resolution %q: %s", res, result.Err)
			}
		})
	}
}

func TestRPKIObservatory_InvalidResolution_ZeroHTTP(t *testing.T) {
	for _, res := range []string{"D", "W", "month", "1d", ""} {
		t.Run(res, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			result := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: res})
			if result.Err == "" {
				t.Fatalf("Err empty for resolution %q, want a rejection", res)
			}
			if len(result.Evidence) != 1 || result.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", result.Evidence)
			}
		})
	}
}

func TestRPKIObservatory_EveryLocalRejection_ZeroNetworkCalls(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	invalid := []RPKIObservatoryRequest{
		{Resource: "", Family: 4, Resolution: "m"},
		{Resource: "AS0", Family: 4, Resolution: "m"},
		{Resource: "1.1.1.1", Family: 4, Resolution: "m"},
		{Resource: "example.com", Family: 4, Resolution: "m"},
		{Resource: "ZZ", Family: 4, Resolution: "m"},
		{Resource: "AS13335", Family: 0, Resolution: "m"},
		{Resource: "AS13335", Family: 4, Resolution: "D"},
		{Resource: "1.1.1.0/24", Family: 6, Resolution: "m"},
		{Resource: "2606:4700::/32", Family: 4, Resolution: "m"},
		{Resource: "1.1.1.0/24", Family: 4, Resolution: "m"},     // matching family, still out of scope
		{Resource: "2606:4700::/32", Family: 6, Resolution: "m"}, // matching family, still out of scope
	}
	for _, req := range invalid {
		c.RPKIObservatory(context.Background(), req)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0 across every local rejection", requests)
	}
}

// ================= DAILY WIRE (21-27) =================

func TestRPKIObservatory_Daily_FullDecode(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{
		rpkiDailyPoint("2026-08-18T00:00:00Z", 100),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1", len(res.Points))
	}
	p := res.Points[0]
	if p.Time != "2026-08-18T00:00:00Z" {
		t.Errorf("Time = %q, want preserved verbatim", p.Time)
	}
	if p.VRPCount == nil || *p.VRPCount != 100 {
		t.Errorf("VRPCount = %v, want pointer to 100", p.VRPCount)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentOK || res.Evidence[0].Component != "rpki-history" {
		t.Errorf("Evidence = %+v, want single rpki-history ComponentOK entry", res.Evidence)
	}
}

func TestRPKIObservatory_Daily_VRPCountZero_RealValid(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{
		rpkiDailyPoint("2026-08-18T00:00:00Z", 0),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Points[0].VRPCount == nil {
		t.Fatal("VRPCount = nil, want a real zero pointer")
	}
	if *res.Points[0].VRPCount != 0 {
		t.Errorf("VRPCount = %d, want 0", *res.Points[0].VRPCount)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — a real zero VRP count is a valid, complete point")
	}
}

func TestRPKIObservatory_Daily_VRPCountAbsent_Degraded(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{
		rpkiDailyPointNoVRPCount("2026-08-18T00:00:00Z"),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})
	if res.Err == "" {
		t.Fatal("Err empty, want a structural-incompleteness error")
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_Daily_TimeAbsent_Degraded(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{
		rpkiDailyPointNoTime(5),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})
	if res.Err == "" {
		t.Fatal("Err empty, want a structural-incompleteness error")
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_Daily_EmptyTimeseries_DataInsufficient(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiDailyFixtureBody([]map[string]any{}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 0 {
		t.Errorf("Points = %v, want empty", res.Points)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false — empty timeseries")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentOK {
		t.Errorf("Evidence = %+v, want single ComponentOK entry — the query itself succeeded", res.Evidence)
	}
}

// ================= AGGREGATED WIRE (28-41) =================

func testAggFullDecode(t *testing.T, resolution string) {
	t.Helper()
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{
		rpkiAggPoint("2026-08-01T00:00:00Z", 2.0, 5.0, 3.5, 2.0, 5.0, 10),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: resolution})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("Points = %d, want 1", len(res.Points))
	}
	p := res.Points[0]
	if p.VRPCount != nil {
		t.Errorf("VRPCount = %v, want nil for aggregated resolution %q", p.VRPCount, resolution)
	}
	checks := []struct {
		name string
		got  *float64
		want float64
	}{
		{"Min", p.Min, 2.0}, {"Max", p.Max, 5.0}, {"Avg", p.Avg, 3.5},
		{"First", p.First, 2.0}, {"Last", p.Last, 5.0},
	}
	for _, c := range checks {
		if c.got == nil || *c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if p.Samples == nil || *p.Samples != 10 {
		t.Errorf("Samples = %v, want 10", p.Samples)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
}

func TestRPKIObservatory_Aggregated_FullDecode_Weekly(t *testing.T)  { testAggFullDecode(t, "w") }
func TestRPKIObservatory_Aggregated_FullDecode_Monthly(t *testing.T) { testAggFullDecode(t, "m") }
func TestRPKIObservatory_Aggregated_FullDecode_Yearly(t *testing.T)  { testAggFullDecode(t, "y") }

func TestRPKIObservatory_Aggregated_ZeroValuesPreserved(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{
		rpkiAggPoint("2026-08-01T00:00:00Z", 0.0, 0.0, 0.0, 0.0, 0.0, 0),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	p := res.Points[0]
	for name, got := range map[string]*float64{"Min": p.Min, "Max": p.Max, "Avg": p.Avg, "First": p.First, "Last": p.Last} {
		if got == nil {
			t.Errorf("%s = nil, want a real zero pointer", name)
			continue
		}
		if *got != 0 {
			t.Errorf("%s = %v, want 0", name, *got)
		}
	}
	if p.Samples == nil || *p.Samples != 0 {
		t.Errorf("Samples = %v, want pointer to 0", p.Samples)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — real zeros are complete, valid data")
	}
}

func testAggMissingField(t *testing.T, field string) {
	t.Helper()
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{
		rpkiAggPointMissing("2026-08-01T00:00:00Z", field),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	if res.Err == "" {
		t.Fatalf("Err empty for missing %q, want a structural-incompleteness error", field)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_Aggregated_MissingMin_Degraded(t *testing.T) { testAggMissingField(t, "min") }
func TestRPKIObservatory_Aggregated_MissingAvg_Degraded(t *testing.T) { testAggMissingField(t, "avg") }
func TestRPKIObservatory_Aggregated_MissingSamples_Degraded(t *testing.T) {
	testAggMissingField(t, "samples")
}

func TestRPKIObservatory_Aggregated_NeverFabricatesVRPCount(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{
		rpkiAggPoint("2026-08-01T00:00:00Z", 2.0, 5.0, 3.5, 2.0, 5.0, 10),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Points[0].VRPCount != nil {
		t.Errorf("VRPCount = %v, want nil — aggregated points never synthesize a daily-style count from min/max/avg", res.Points[0].VRPCount)
	}
}

// ================= DATASOURCE (42-46) =================

func TestRPKIObservatory_HTTPError_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), validRPKIReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a datasource error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_MalformedJSON_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), validRPKIReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_EnvelopeStatusNotOK_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","data":{"timeseries":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), validRPKIReq())
	if res.Err == "" {
		t.Fatal("Err empty, want an envelope-status error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestRPKIObservatory_ContextCanceled_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(rpkiAggFixtureBody([]map[string]any{rpkiAggPoint("2026-08-01T00:00:00Z", 1.0, 2.0, 1.5, 1.0, 2.0, 3)})))
	})
	c := &Client{BaseURL: addr}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.RPKIObservatory(ctx, validRPKIReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a context-canceled error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// ================= SEMANTICS (47-50) =================

// forbiddenSemanticSubstrings never appears in RPKIObservatoryPoint or
// RPKIObservatoryResult's field names or json tags — this Gate produces
// VRP counts, never rpki-validation states, never a derived score, never
// a hijack/attack inference (§ RPKI SEMANTICS).
func TestRPKIObservatory_NoForbiddenSemanticFields(t *testing.T) {
	forbidden := []string{
		"valid", "invalid", "unknown", "status",
		"health", "risk", "security",
		"attack", "hijack", "secuestro",
		"provider", "customer", "upstream", "downstream", "tier",
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(RPKIObservatoryPoint{}),
		reflect.TypeOf(RPKIObservatoryResult{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			tag := strings.ToLower(string(f.Tag))
			for _, bad := range forbidden {
				if strings.Contains(name, bad) || strings.Contains(tag, bad) {
					t.Errorf("%s.%s (tag %q) contains forbidden semantic substring %q", typ.Name(), f.Name, f.Tag, bad)
				}
			}
		}
	}
}

// TestRPKIObservatory_NoRouteValidityConversion documents (§49-50) that
// this Gate's public contract exposes only raw VRP counts (daily
// VRPCount, aggregated Min/Max/Avg/First/Last/Samples) — there is no
// field anywhere that could hold a computed validity percentage, adoption
// score, or route-validity classification; RPKIValidate (bgp.go, v1.1)
// remains the only source of VALID/INVALID_ASN/INVALID_LENGTH/UNKNOWN in
// this package, untouched by this file.
func TestRPKIObservatory_NoRouteValidityConversion(t *testing.T) {
	pointFields := map[string]bool{}
	typ := reflect.TypeOf(RPKIObservatoryPoint{})
	for i := 0; i < typ.NumField(); i++ {
		pointFields[typ.Field(i).Name] = true
	}
	want := []string{"Time", "VRPCount", "Min", "Max", "Avg", "First", "Last", "Samples"}
	if len(pointFields) != len(want) {
		t.Fatalf("RPKIObservatoryPoint has %d fields, want exactly %d: %v", len(pointFields), len(want), want)
	}
	for _, w := range want {
		if !pointFields[w] {
			t.Errorf("RPKIObservatoryPoint missing expected field %q", w)
		}
	}
}

// ================= ORDER (51) =================

func TestRPKIObservatory_OrderPreserved(t *testing.T) {
	addr := rpkiHistoryFixtureServer(t, rpkiAggFixtureBody([]map[string]any{
		rpkiAggPoint("2026-06-01T00:00:00Z", 1.0, 1.0, 1.0, 1.0, 1.0, 1),
		rpkiAggPoint("2026-07-01T00:00:00Z", 2.0, 2.0, 2.0, 2.0, 2.0, 2),
		rpkiAggPoint("2026-08-01T00:00:00Z", 3.0, 3.0, 3.0, 3.0, 3.0, 3),
	}))
	c := &Client{BaseURL: addr}
	res := c.RPKIObservatory(context.Background(), RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "m"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Points) != 3 {
		t.Fatalf("Points = %d, want 3", len(res.Points))
	}
	want := []string{"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z"}
	for i, w := range want {
		if res.Points[i].Time != w {
			t.Errorf("Points[%d].Time = %q, want %q — source order must be preserved exactly", i, res.Points[i].Time, w)
		}
	}
}
