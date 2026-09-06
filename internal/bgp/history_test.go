package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// bgpUpdatesEnvelope wraps a bgp-updates data payload in RIPEstat's real
// top-level envelope ({"status":"ok","data":{...}}) — same shape c.get
// already expects for every other endpoint in this package. nr_updates
// defaults to len(updates) — the normal/consistent shape confirmed live
// (Gate 4 P1-1 preflight probes) — every test that doesn't specifically
// exercise the nr_updates/len(updates) mismatch uses this.
func bgpUpdatesEnvelope(t *testing.T, updates []map[string]any) string {
	t.Helper()
	return bgpUpdatesEnvelopeWithNrUpdates(t, updates, len(updates))
}

// bgpUpdatesEnvelopeWithNrUpdates is bgpUpdatesEnvelope but with nr_updates
// set independently of len(updates) — used to exercise the P1-1 conservative
// handling of a source-declared total that disagrees with the array it
// actually returned.
func bgpUpdatesEnvelopeWithNrUpdates(t *testing.T, updates []map[string]any, nrUpdates int) string {
	t.Helper()
	data := map[string]any{
		"resource":        "1.1.1.0/24",
		"query_starttime": "2026-08-18T00:00:00",
		"query_endtime":   "2026-08-19T00:00:00",
		"nr_updates":      nrUpdates,
		"updates":         updates,
	}
	env := map[string]any{"status": "ok", "data": data}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

func bgpUpdatesFixtureServer(t *testing.T, body string) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
}

const (
	validStart = "2026-08-18T00:00:00Z"
	validEnd   = "2026-08-18T23:00:00Z" // < 24h from validStart
)

func validHistoryReq() BGPHistoryRequest {
	return BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: validStart, EndTime: validEnd}
}

// --- happy path decode ---

func TestHistory_Announcement_Decoded(t *testing.T) {
	updates := []map[string]any{
		{"seq": 775571759824898, "timestamp": "2026-08-18T00:01:35", "type": "A",
			"attrs": map[string]any{"source_id": "00-102.208.105.2", "target_prefix": "1.1.1.0/24",
				"path": []int{328840, 327727, 174, 13335}, "community": []string{"64525:10"}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != 1 {
		t.Fatalf("Updates = %d, want 1", len(res.Updates))
	}
	u := res.Updates[0]
	if u.Type != "A" {
		t.Errorf("Type = %q, want \"A\" (literal wire code, never rewritten)", u.Type)
	}
	if u.SourceID != "00-102.208.105.2" {
		t.Errorf("SourceID = %q", u.SourceID)
	}
	if len(u.Path) != 4 || u.Path[3] != 13335 {
		t.Errorf("Path = %v, want [328840 327727 174 13335]", u.Path)
	}
}

func TestHistory_Withdrawal_NoPathNoCommunity(t *testing.T) {
	updates := []map[string]any{
		{"seq": 775562469245006, "timestamp": "2026-08-18T00:00:35", "type": "W",
			"attrs": map[string]any{"source_id": "00-102.208.105.2", "target_prefix": "1.1.1.0/24"}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != 1 {
		t.Fatalf("Updates = %d, want 1", len(res.Updates))
	}
	u := res.Updates[0]
	if u.Type != "W" {
		t.Errorf("Type = %q, want \"W\"", u.Type)
	}
	if u.Path != nil {
		t.Errorf("Path = %v, want nil — withdrawal never fabricates a path", u.Path)
	}
	if u.Community != nil {
		t.Errorf("Community = %v, want nil — withdrawal never fabricates community", u.Community)
	}
}

func TestHistory_Community_StringShape(t *testing.T) {
	updates := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24",
				"path": []int{100}, "community": []string{"64525:10", "6453:86"}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	got := res.Updates[0].Community
	want := []string{"64525:10", "6453:86"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Community = %v, want %v (RIPEstat REST \"ASN:value\" string shape)", got, want)
	}
}

func TestHistory_SeqInt64_LargeValuePreserved(t *testing.T) {
	const bigSeq = int64(775571759824898) // real magnitude observed live — overflows int32
	updates := []map[string]any{
		{"seq": bigSeq, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24", "path": []int{100}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Updates[0].Seq != bigSeq {
		t.Errorf("Seq = %d, want %d", res.Updates[0].Seq, bigSeq)
	}
}

func TestHistory_Timestamp_PreservedHonestly(t *testing.T) {
	const ts = "2026-08-18T00:01:35"
	updates := []map[string]any{
		{"seq": 1, "timestamp": ts, "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24", "path": []int{100}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Updates[0].Timestamp != ts {
		t.Errorf("Timestamp = %q, want %q — never reformatted/reinterpreted", res.Updates[0].Timestamp, ts)
	}
}

// --- target_prefix (Gate 4 P1-2 closure) ---

func TestHistory_TargetPrefix_PreservedOnAnnouncement(t *testing.T) {
	updates := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24", "path": []int{100}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if got := res.Updates[0].TargetPrefix; got != "1.1.1.0/24" {
		t.Errorf("TargetPrefix = %q, want %q", got, "1.1.1.0/24")
	}
}

func TestHistory_TargetPrefix_ASNQuery_MultiplePrefixesDistinguishable(t *testing.T) {
	// A Resource=ASN query can legitimately span several announced
	// prefixes in one response — TargetPrefix is what keeps two updates
	// for different prefixes distinguishable, never collapsed or
	// substituted with the queried Resource itself.
	updates := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24", "path": []int{13335}}},
		{"seq": 2, "timestamp": "2026-08-18T00:00:01", "type": "A",
			"attrs": map[string]any{"source_id": "y", "target_prefix": "1.0.0.0/24", "path": []int{13335}}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "AS13335", StartTime: validStart, EndTime: validEnd})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != 2 {
		t.Fatalf("Updates = %d, want 2", len(res.Updates))
	}
	prefixes := map[string]bool{res.Updates[0].TargetPrefix: true, res.Updates[1].TargetPrefix: true}
	if !prefixes["1.1.1.0/24"] || !prefixes["1.0.0.0/24"] {
		t.Errorf("TargetPrefixes = %v, want both 1.1.1.0/24 and 1.0.0.0/24 distinguishable", prefixes)
	}
	for _, u := range res.Updates {
		if u.TargetPrefix == "AS13335" || u.TargetPrefix == res.Resource {
			t.Errorf("TargetPrefix = %q looks derived from the request's Resource, never allowed", u.TargetPrefix)
		}
	}
}

func TestHistory_TargetPrefix_PreservedOnWithdrawal(t *testing.T) {
	updates := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "W",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "1.1.1.0/24"}},
	}
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, updates))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if got := res.Updates[0].TargetPrefix; got != "1.1.1.0/24" {
		t.Errorf("TargetPrefix = %q, want %q — preserved on withdrawal too", got, "1.1.1.0/24")
	}
}

// --- nr_updates (Gate 4 P1-1 closure) ---

func TestHistory_NrUpdates_MatchesLen_Normal(t *testing.T) {
	const n = 5
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelopeWithNrUpdates(t, syntheticUpdates(n), n))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ObservedUpdates != n {
		t.Errorf("ObservedUpdates = %d, want %d", res.ObservedUpdates, n)
	}
	if len(res.Updates) != n {
		t.Errorf("len(Updates) = %d, want %d", len(res.Updates), n)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false")
	}
}

func TestHistory_NrUpdates_GreaterThanReturned_ObservedExactAndTruncated(t *testing.T) {
	// The source declares more updates existed than it actually returned
	// in this response — independent of TRAZIP's own historyMaxUpdates
	// cap (5 returned, well under the cap). ObservedUpdates must reflect
	// the source's real declared total, and Truncated must be true even
	// though len(Updates) never got anywhere near historyMaxUpdates.
	const returned = 5
	const declared = 4204 // real magnitude observed live for a 7-day window, §23.1 B.1
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelopeWithNrUpdates(t, syntheticUpdates(returned), declared))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ObservedUpdates != declared {
		t.Errorf("ObservedUpdates = %d, want %d (source-declared total, never silently reduced)", res.ObservedUpdates, declared)
	}
	if len(res.Updates) != returned {
		t.Errorf("len(Updates) = %d, want %d", len(res.Updates), returned)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true — the source declared more than it returned")
	}
}

func TestHistory_NrUpdates_ImpossibleLessThanReturned_Degraded(t *testing.T) {
	// nr_updates < len(updates) is a shape RIPEstat has never been
	// observed to send — a decode/datasource inconsistency, never
	// presented as a real (and necessarily fabricated) total.
	const returned = 5
	const declared = 2 // impossible: fewer than what the array itself contains
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelopeWithNrUpdates(t, syntheticUpdates(returned), declared))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode/datasource inconsistency error")
	}
	if len(res.Updates) != 0 {
		t.Errorf("Updates = %v, want empty — never a partial/fabricated result", res.Updates)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- truncation ---

func syntheticUpdates(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		out[i] = map[string]any{
			"seq": int64(i), "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": fmt.Sprintf("src-%d", i), "target_prefix": "1.1.1.0/24", "path": []int{100}},
		}
	}
	return out
}

func TestHistory_OverLimit_TruncatedAtMaxEvents(t *testing.T) {
	const n = historyMaxUpdates + 137
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, syntheticUpdates(n)))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != historyMaxUpdates {
		t.Errorf("len(Updates) = %d, want %d", len(res.Updates), historyMaxUpdates)
	}
	if res.ObservedUpdates != n {
		t.Errorf("ObservedUpdates = %d, want %d (real total, never silently reduced)", res.ObservedUpdates, n)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestHistory_UnderLimit_NotTruncated(t *testing.T) {
	const n = 5
	addr := bgpUpdatesFixtureServer(t, bgpUpdatesEnvelope(t, syntheticUpdates(n)))
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != n {
		t.Errorf("len(Updates) = %d, want %d", len(res.Updates), n)
	}
	if res.ObservedUpdates != n {
		t.Errorf("ObservedUpdates = %d, want %d", res.ObservedUpdates, n)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false")
	}
}

// --- local validation, zero HTTP ---

func TestHistory_InvalidResource_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "not-a-resource!!", StartTime: validStart, EndTime: validEnd})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
		t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
	}
}

func TestHistory_BadStartTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: "not-a-time", EndTime: validEnd})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestHistory_BadEndTime_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: validStart, EndTime: "not-a-time"})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestHistory_StartAfterEnd_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: validEnd, EndTime: validStart})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestHistory_StartEqualsEnd_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: validStart, EndTime: validStart})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

func TestHistory_RangeOver24h_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPHistory(context.Background(), BGPHistoryRequest{Resource: "1.1.1.0/24", StartTime: "2026-08-01T00:00:00Z", EndTime: "2026-08-02T00:00:01Z"})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection — range is 24h+1s, over the 24h cap")
	}
}

// --- datasource failure paths ---

func TestHistory_DatasourceHTTPError_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a datasource error")
	}
	if len(res.Updates) != 0 {
		t.Errorf("Updates = %v, want empty — never fabricated on failure", res.Updates)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestHistory_MalformedJSON_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPHistory(context.Background(), validHistoryReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if len(res.Updates) != 0 {
		t.Errorf("Updates = %v, want empty", res.Updates)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}
