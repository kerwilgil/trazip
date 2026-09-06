package bgp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// NOTE — Gate 2 test items 2 and 8 ("full decode fixture de prefix-count
// IPv4/IPv6", "HTTP failure prefix-count") do not apply: prefix-count was
// verified (live + docs) to require resource=AS<n> and was removed from
// this file's DTO before implementation — see global_observatory.go's
// package doc comment. There is no prefix-count code path here to test.

func risAsnsFixtureBody(total int, queryTime string) string {
	data := map[string]any{
		"counts":     map[string]any{"total": total},
		"query_time": queryTime,
		"list_asns":  false,
	}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

func risPeerCountFixtureBody(start, end, ts string, v4Total, v4FullFeed, v6Total, v6FullFeed int) string {
	point := func(count int) []map[string]any {
		return []map[string]any{{"timestamp": ts, "count": count}}
	}
	data := map[string]any{
		"starttime": start,
		"endtime":   end,
		"peer_count": map[string]any{
			"v4": map[string]any{"total": point(v4Total), "full_feed": point(v4FullFeed)},
			"v6": map[string]any{"total": point(v6Total), "full_feed": point(v6FullFeed)},
		},
	}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

// risAsnsFixtureBodyNoTotal builds a ris-asns response whose "counts"
// object exists but never carries "total" — Gate 2 P1 test case A.
func risAsnsFixtureBodyNoTotal(queryTime string) string {
	data := map[string]any{
		"counts":     map[string]any{},
		"query_time": queryTime,
	}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

// risPeerCountFixtureBodyCustom lets each of the four series be either a
// real point (non-nil *int) or an empty array (nil) — Gate 2 P1 test
// cases C/D/E.
func risPeerCountFixtureBodyCustom(start, end, ts string, v4Total, v4FullFeed, v6Total, v6FullFeed *int) string {
	series := func(count *int) []map[string]any {
		if count == nil {
			return []map[string]any{}
		}
		return []map[string]any{{"timestamp": ts, "count": *count}}
	}
	data := map[string]any{
		"starttime": start,
		"endtime":   end,
		"peer_count": map[string]any{
			"v4": map[string]any{"total": series(v4Total), "full_feed": series(v4FullFeed)},
			"v6": map[string]any{"total": series(v6Total), "full_feed": series(v6FullFeed)},
		},
	}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

// risPeerCountFixtureBodyNoPeerCount builds a ris-peer-count response
// with no "peer_count" object at all — Gate 2 P1 test case F.
func risPeerCountFixtureBodyNoPeerCount(start, end string) string {
	data := map[string]any{"starttime": start, "endtime": end}
	env := map[string]any{"status": "ok", "data": data}
	b, _ := json.Marshal(env)
	return string(b)
}

// globalObservatoryFixtureServer routes by path — ris-asns vs
// ris-peer-count — since GlobalRISObservatory calls both endpoints on the
// same Client/BaseURL. A body of "" together with a non-200 status
// simulates that datasource failing; a body of "malformed" sends invalid
// JSON with a 200 status to simulate a decode failure instead.
func globalObservatoryFixtureServer(t *testing.T, asnsBody string, asnsStatus int, peersBody string, peersStatus int) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "ris-asns"):
			if asnsStatus != http.StatusOK {
				w.WriteHeader(asnsStatus)
				return
			}
			w.Write([]byte(asnsBody))
		case strings.Contains(r.URL.Path, "ris-peer-count"):
			if peersStatus != http.StatusOK {
				w.WriteHeader(peersStatus)
				return
			}
			w.Write([]byte(peersBody))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// --- 1: full decode fixture of ris-asns (via the combined call) ---

func TestGlobalRISObservatory_RISAsnsDecoded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.VisibleASNs == nil || *res.VisibleASNs != 87726 {
		t.Errorf("VisibleASNs = %v, want 87726", res.VisibleASNs)
	}
	if res.ASNsQueryTime != "2026-08-20T16:00:00" {
		t.Errorf("ASNsQueryTime = %q, want %q", res.ASNsQueryTime, "2026-08-20T16:00:00")
	}
}

// --- 3: full decode fixture of ris-peer-count ---

func TestGlobalRISObservatory_RISPeerCountDecoded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.PeersStartTime != "2026-08-20T00:00:00" || res.PeersEndTime != "2026-08-20T00:00:00" {
		t.Errorf("PeersStartTime/EndTime = %q/%q", res.PeersStartTime, res.PeersEndTime)
	}
	cases := []struct {
		name string
		got  *int
		want int
	}{
		{"RISPeersIPv4Total", res.RISPeersIPv4Total, 792},
		{"RISPeersIPv4FullFeed", res.RISPeersIPv4FullFeed, 335},
		{"RISPeersIPv6Total", res.RISPeersIPv6Total, 664},
		{"RISPeersIPv6FullFeed", res.RISPeersIPv6FullFeed, 375},
	}
	for _, tc := range cases {
		if tc.got == nil || *tc.got != tc.want {
			t.Errorf("%s = %v, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// --- 4: combined result correct ---

func TestGlobalRISObservatory_CombinedResult(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — both datasources succeeded")
	}
	if len(res.Evidence) != 2 {
		t.Fatalf("Evidence = %+v, want 2 entries", res.Evidence)
	}
	for _, e := range res.Evidence {
		if e.Status != ComponentOK {
			t.Errorf("Evidence[%s].Status = %s, want %s", e.Component, e.Status, ComponentOK)
		}
	}
}

// --- 5: real zero preserved as real zero ---

func TestGlobalRISObservatory_RealZeroPreserved(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(0, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 0, 0, 0, 0), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.VisibleASNs == nil {
		t.Fatal("VisibleASNs = nil, want a real zero pointer")
	}
	if *res.VisibleASNs != 0 {
		t.Errorf("VisibleASNs = %d, want 0", *res.VisibleASNs)
	}
	if res.RISPeersIPv4Total == nil || *res.RISPeersIPv4Total != 0 {
		t.Errorf("RISPeersIPv4Total = %v, want pointer to 0", res.RISPeersIPv4Total)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — a real zero is still a successful observation")
	}
}

// --- 6: absent data never silently converted to zero ---

func TestGlobalRISObservatory_AbsentData_NeverZero(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		"", http.StatusInternalServerError,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err == "" {
		t.Fatal("Err empty, want a partial-failure error")
	}
	if res.VisibleASNs != nil {
		t.Errorf("VisibleASNs = %v, want nil — never fabricated to 0 on failure", res.VisibleASNs)
	}
	if res.ASNsQueryTime != "" {
		t.Errorf("ASNsQueryTime = %q, want empty — never fabricated", res.ASNsQueryTime)
	}
}

// --- 7: HTTP failure ris-asns ---

func TestGlobalRISObservatory_RISAsnsHTTPFailure_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		"", http.StatusInternalServerError,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	var asns *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-asns" {
			asns = &res.Evidence[i]
		}
	}
	if asns == nil || asns.Status != ComponentDegraded {
		t.Errorf("ris-asns Evidence = %+v, want ComponentDegraded", asns)
	}
}

// --- 9: HTTP failure ris-peer-count ---

func TestGlobalRISObservatory_RISPeerCountHTTPFailure_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		"", http.StatusInternalServerError,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	var peers *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-peer-count" {
			peers = &res.Evidence[i]
		}
	}
	if peers == nil || peers.Status != ComponentDegraded {
		t.Errorf("ris-peer-count Evidence = %+v, want ComponentDegraded", peers)
	}
	if res.PeersStartTime != "" {
		t.Errorf("PeersStartTime = %q, want empty on failure", res.PeersStartTime)
	}
}

// --- 10: malformed JSON on each relevant datasource ---

func TestGlobalRISObservatory_RISAsnsMalformedJSON_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		`{not valid json`, http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if res.VisibleASNs != nil {
		t.Errorf("VisibleASNs = %v, want nil", res.VisibleASNs)
	}
}

func TestGlobalRISObservatory_RISPeerCountMalformedJSON_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		`{not valid json`, http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if res.RISPeersIPv4Total != nil {
		t.Errorf("RISPeersIPv4Total = %v, want nil", res.RISPeersIPv4Total)
	}
}

// --- 11: context cancellation ---

func TestGlobalRISObservatory_ContextCanceled_BothDegraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.GlobalRISObservatory(ctx)
	if res.Err == "" {
		t.Fatal("Err empty, want a context-canceled error")
	}
	if len(res.Evidence) != 2 {
		t.Fatalf("Evidence = %+v, want 2 entries (one per datasource, even on cancellation)", res.Evidence)
	}
	for _, e := range res.Evidence {
		if e.Status != ComponentDegraded {
			t.Errorf("Evidence[%s].Status = %s, want %s", e.Component, e.Status, ComponentDegraded)
		}
	}
}

// --- 12: partial failure — mixed Evidence, DataSufficient=false ---

func TestGlobalRISObservatory_PartialFailure_MixedEvidence(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		"", http.StatusInternalServerError,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false — one datasource failed")
	}
	if len(res.Evidence) != 2 {
		t.Fatalf("Evidence = %+v, want 2 entries", res.Evidence)
	}
	var okCount, degradedCount int
	for _, e := range res.Evidence {
		switch e.Status {
		case ComponentOK:
			okCount++
		case ComponentDegraded:
			degradedCount++
		}
	}
	if okCount != 1 || degradedCount != 1 {
		t.Errorf("Evidence statuses = %+v, want exactly one OK and one Degraded", res.Evidence)
	}
	if res.VisibleASNs == nil || *res.VisibleASNs != 87726 {
		t.Errorf("VisibleASNs = %v, want 87726 — the succeeding component's real value must still surface", res.VisibleASNs)
	}
}

// --- 13: datasource values preserved (distinct v4/v6, total/full-feed) ---

func TestGlobalRISObservatory_DistinctPeerValuesPreserved(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(1, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 111, 222, 333, 444), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	got := []*int{res.RISPeersIPv4Total, res.RISPeersIPv4FullFeed, res.RISPeersIPv6Total, res.RISPeersIPv6FullFeed}
	want := []int{111, 222, 333, 444}
	for i, w := range want {
		if got[i] == nil || *got[i] != w {
			t.Errorf("field %d = %v, want %d — the four counts must never be conflated/summed/reused", i, got[i], w)
		}
	}
}

// --- 14: no fabricated QueryTime ---

func TestGlobalRISObservatory_NoFabricatedQueryTime_OnFailure(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		"", http.StatusInternalServerError,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.ASNsQueryTime != "" {
		t.Errorf("ASNsQueryTime = %q, want empty — never fabricated when ris-asns failed", res.ASNsQueryTime)
	}
}

func intPtr(n int) *int { return &n }

// --- Gate 2 P1 fix case A: ris-asns HTTP 200 with "counts": {} (total
// genuinely absent, not zero) ---

func TestGlobalRISObservatory_RISAsns_CountsEmpty_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBodyNoTotal("2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.VisibleASNs != nil {
		t.Errorf("VisibleASNs = %v, want nil — counts.total was absent, never a fabricated value", res.VisibleASNs)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	var asns *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-asns" {
			asns = &res.Evidence[i]
		}
	}
	if asns == nil || asns.Status != ComponentDegraded {
		t.Errorf("ris-asns Evidence = %+v, want ComponentDegraded", asns)
	}
}

// --- Gate 2 P1 fix case B: ris-asns HTTP 200 with counts.total:0 (real
// zero, distinct from case A) ---

func TestGlobalRISObservatory_RISAsns_TotalZero_OK(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(0, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBody("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00", 792, 335, 664, 375), http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.VisibleASNs == nil {
		t.Fatal("VisibleASNs = nil, want a real zero pointer")
	}
	if *res.VisibleASNs != 0 {
		t.Errorf("VisibleASNs = %d, want 0", *res.VisibleASNs)
	}
	var asns *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-asns" {
			asns = &res.Evidence[i]
		}
	}
	if asns == nil || asns.Status != ComponentOK {
		t.Errorf("ris-asns Evidence = %+v, want ComponentOK", asns)
	}
}

// --- Gate 2 P1 fix case C: ris-peer-count with v4.total empty ---

func TestGlobalRISObservatory_RISPeerCount_V4TotalMissing_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBodyCustom("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00",
			nil, intPtr(335), intPtr(664), intPtr(375)),
		http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.RISPeersIPv4Total != nil {
		t.Errorf("RISPeersIPv4Total = %v, want nil", res.RISPeersIPv4Total)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	var peers *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-peer-count" {
			peers = &res.Evidence[i]
		}
	}
	if peers == nil || peers.Status != ComponentDegraded {
		t.Errorf("ris-peer-count Evidence = %+v, want ComponentDegraded", peers)
	}
	// The three series that DID decode must still be preserved, never
	// discarded just because a sibling series was missing.
	if res.RISPeersIPv4FullFeed == nil || *res.RISPeersIPv4FullFeed != 335 {
		t.Errorf("RISPeersIPv4FullFeed = %v, want pointer to 335 (preserved despite v4.total missing)", res.RISPeersIPv4FullFeed)
	}
	if res.RISPeersIPv6Total == nil || *res.RISPeersIPv6Total != 664 {
		t.Errorf("RISPeersIPv6Total = %v, want pointer to 664 (preserved despite v4.total missing)", res.RISPeersIPv6Total)
	}
	if res.RISPeersIPv6FullFeed == nil || *res.RISPeersIPv6FullFeed != 375 {
		t.Errorf("RISPeersIPv6FullFeed = %v, want pointer to 375 (preserved despite v4.total missing)", res.RISPeersIPv6FullFeed)
	}
}

// --- Gate 2 P1 fix case D: ris-peer-count with v6.full_feed empty —
// proves validation isn't limited to v4.total alone ---

func TestGlobalRISObservatory_RISPeerCount_V6FullFeedMissing_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBodyCustom("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00",
			intPtr(792), intPtr(335), intPtr(664), nil),
		http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.RISPeersIPv6FullFeed != nil {
		t.Errorf("RISPeersIPv6FullFeed = %v, want nil", res.RISPeersIPv6FullFeed)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	var peers *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-peer-count" {
			peers = &res.Evidence[i]
		}
	}
	if peers == nil || peers.Status != ComponentDegraded {
		t.Errorf("ris-peer-count Evidence = %+v, want ComponentDegraded", peers)
	}
	if res.RISPeersIPv4Total == nil || *res.RISPeersIPv4Total != 792 {
		t.Errorf("RISPeersIPv4Total = %v, want pointer to 792 (preserved despite v6.full_feed missing)", res.RISPeersIPv4Total)
	}
}

// --- Gate 2 P1 fix case E: all four series present with count=0 ---

func TestGlobalRISObservatory_AllFourPeerSeries_RealZero_OK(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBodyCustom("2026-08-20T00:00:00", "2026-08-20T00:00:00", "2026-08-20T00:00:00",
			intPtr(0), intPtr(0), intPtr(0), intPtr(0)),
		http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	for name, got := range map[string]*int{
		"RISPeersIPv4Total":    res.RISPeersIPv4Total,
		"RISPeersIPv4FullFeed": res.RISPeersIPv4FullFeed,
		"RISPeersIPv6Total":    res.RISPeersIPv6Total,
		"RISPeersIPv6FullFeed": res.RISPeersIPv6FullFeed,
	} {
		if got == nil {
			t.Errorf("%s = nil, want a real zero pointer", name)
			continue
		}
		if *got != 0 {
			t.Errorf("%s = %d, want 0", name, *got)
		}
	}
	var peers *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-peer-count" {
			peers = &res.Evidence[i]
		}
	}
	if peers == nil || peers.Status != ComponentOK {
		t.Errorf("ris-peer-count Evidence = %+v, want ComponentOK", peers)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — both datasources fully present, real zeros included")
	}
}

// --- Gate 2 P1 fix case F: peer_count entirely absent ---

func TestGlobalRISObservatory_PeerCountEntirelyAbsent_Degraded(t *testing.T) {
	addr := globalObservatoryFixtureServer(t,
		risAsnsFixtureBody(87726, "2026-08-20T16:00:00"), http.StatusOK,
		risPeerCountFixtureBodyNoPeerCount("2026-08-20T00:00:00", "2026-08-20T00:00:00"),
		http.StatusOK,
	)
	c := &Client{BaseURL: addr}
	res := c.GlobalRISObservatory(context.Background())
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	for name, got := range map[string]*int{
		"RISPeersIPv4Total":    res.RISPeersIPv4Total,
		"RISPeersIPv4FullFeed": res.RISPeersIPv4FullFeed,
		"RISPeersIPv6Total":    res.RISPeersIPv6Total,
		"RISPeersIPv6FullFeed": res.RISPeersIPv6FullFeed,
	} {
		if got != nil {
			t.Errorf("%s = %v, want nil — never a fabricated zero when peer_count is entirely absent", name, got)
		}
	}
	var peers *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "ris-peer-count" {
			peers = &res.Evidence[i]
		}
	}
	if peers == nil || peers.Status != ComponentDegraded {
		t.Errorf("ris-peer-count Evidence = %+v, want ComponentDegraded", peers)
	}
}
