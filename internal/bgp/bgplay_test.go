package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func bgplayEnvelope(t *testing.T, initialState, events, nodes, sources []map[string]any) string {
	t.Helper()
	data := map[string]any{
		"resource":        "1.1.1.0/24",
		"query_starttime": "2026-08-18T00:00:00",
		"query_endtime":   "2026-08-19T00:00:00",
		"initial_state":   initialState,
		"events":          events,
		"nodes":           nodes,
		"sources":         sources,
		"targets":         []map[string]any{{"prefix": "1.1.1.0/24"}},
	}
	env := map[string]any{"status": "ok", "data": data}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

func bgplayFixtureServer(t *testing.T, body string) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
}

func validBGPlayReq() BGPlayRequest {
	return BGPlayRequest{Resource: "1.1.1.0/24", StartTime: validStart, EndTime: validEnd}
}

// oneOfEach builds a minimal, real-shape single entry for each of the four
// bgplay collections — reused by tests that only care about one collection
// at a time.
func oneOfEach() (initialState, events, nodes, sources []map[string]any) {
	initialState = []map[string]any{
		{"source_id": "00-102.208.105.2", "target_prefix": "1.1.1.0/24", "path": []int{328840, 327727, 174, 13335}, "community": []string{"64525:10"}},
	}
	events = []map[string]any{
		{"seq": 775571759824898, "timestamp": "2026-08-18T00:01:35", "type": "A",
			"attrs": map[string]any{"source_id": "00-102.208.105.2", "target_prefix": "1.1.1.0/24", "path": []int{328840, 174, 13335}}},
	}
	nodes = []map[string]any{
		{"as_number": 174, "owner": "COGENT-174 - Cogent Communications, LLC, US"},
	}
	sources = []map[string]any{
		{"as_number": 328840, "id": "00-102.208.105.2", "ip": "102.208.105.2", "rrc": "00"},
	}
	return
}

// --- decode shape ---

func TestBGPlay_InitialState_Decoded(t *testing.T) {
	is, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.InitialState) != 1 {
		t.Fatalf("InitialState = %d, want 1", len(res.InitialState))
	}
	p := res.InitialState[0]
	if p.SourceID != "00-102.208.105.2" || p.TargetPrefix != "1.1.1.0/24" {
		t.Errorf("InitialState[0] = %+v", p)
	}
	if len(p.Path) != 4 || p.Path[0] != 328840 {
		t.Errorf("Path = %v", p.Path)
	}
}

func TestBGPlay_Events_ReuseBGPHistoryUpdate(t *testing.T) {
	is, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("Events = %d, want 1", len(res.Events))
	}
	var _ BGPHistoryUpdate = res.Events[0] // compile-time: same type as History, never a duplicate type
	if res.Events[0].Seq != 775571759824898 || res.Events[0].Type != "A" {
		t.Errorf("Events[0] = %+v", res.Events[0])
	}
	if res.Events[0].TargetPrefix != "1.1.1.0/24" {
		t.Errorf("TargetPrefix = %q, want %q — preserved through BGPlay's Events too (Gate 4 P1-2)", res.Events[0].TargetPrefix, "1.1.1.0/24")
	}
}

func TestBGPlay_ASNQuery_InitialStateAndEventsMultiplePrefixesCorrelate(t *testing.T) {
	initialState := []map[string]any{
		{"source_id": "src-a", "target_prefix": "1.1.1.0/24", "path": []int{13335}},
		{"source_id": "src-b", "target_prefix": "1.0.0.0/24", "path": []int{13335}},
	}
	events := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "src-a", "target_prefix": "1.1.1.0/24", "path": []int{13335}}},
		{"seq": 2, "timestamp": "2026-08-18T00:00:01", "type": "A",
			"attrs": map[string]any{"source_id": "src-b", "target_prefix": "1.0.0.0/24", "path": []int{13335}}},
	}
	_, _, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, initialState, events, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), BGPlayRequest{Resource: "AS13335", StartTime: validStart, EndTime: validEnd})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.InitialState) != 2 || len(res.Events) != 2 {
		t.Fatalf("InitialState=%d Events=%d, want 2/2", len(res.InitialState), len(res.Events))
	}
	// InitialState[i].SourceID correlates with Events[i].SourceID for the
	// SAME TargetPrefix — never collapsed into one just because the
	// request was ASN-scoped.
	bySource := map[string]string{}
	for _, p := range res.InitialState {
		bySource[p.SourceID] = p.TargetPrefix
	}
	for _, e := range res.Events {
		if bySource[e.SourceID] != e.TargetPrefix {
			t.Errorf("event source_id=%q target_prefix=%q does not correlate with initial_state's %q", e.SourceID, e.TargetPrefix, bySource[e.SourceID])
		}
	}
	if bySource["src-a"] != "1.1.1.0/24" || bySource["src-b"] != "1.0.0.0/24" {
		t.Errorf("bySource = %v, want distinct prefixes preserved", bySource)
	}
}

func TestBGPlay_TargetPrefix_NeverDerivedFromRequest(t *testing.T) {
	is, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), BGPlayRequest{Resource: "AS13335", StartTime: validStart, EndTime: validEnd})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	// The fixture's own target_prefix ("1.1.1.0/24") must survive
	// unchanged even though the request's Resource was "AS13335" —
	// TargetPrefix must never be substituted with/derived from Resource.
	if res.InitialState[0].TargetPrefix != "1.1.1.0/24" {
		t.Errorf("InitialState TargetPrefix = %q, want literal %q, never the request Resource", res.InitialState[0].TargetPrefix, "1.1.1.0/24")
	}
	if res.Events[0].TargetPrefix != "1.1.1.0/24" {
		t.Errorf("Events TargetPrefix = %q, want literal %q, never the request Resource", res.Events[0].TargetPrefix, "1.1.1.0/24")
	}
}

func TestBGPlay_WithdrawalEvent_NoPath(t *testing.T) {
	is, _, no, so := oneOfEach()
	events := []map[string]any{
		{"seq": 775562469245006, "timestamp": "2026-08-18T00:00:35", "type": "W",
			"attrs": map[string]any{"source_id": "00-102.208.105.2", "target_prefix": "1.1.1.0/24"}},
	}
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, events, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("Events = %d, want 1", len(res.Events))
	}
	if res.Events[0].Type != "W" {
		t.Errorf("Type = %q, want W", res.Events[0].Type)
	}
	if res.Events[0].Path != nil {
		t.Errorf("Path = %v, want nil for a withdrawal event", res.Events[0].Path)
	}
}

func TestBGPlay_Community_StringShape(t *testing.T) {
	initialState := []map[string]any{
		{"source_id": "x", "target_prefix": "1.1.1.0/24", "path": []int{100}, "community": []string{"64525:10", "6453:86"}},
	}
	_, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, initialState, ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	got := res.InitialState[0].Community
	want := []string{"64525:10", "6453:86"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Community = %v, want %v", got, want)
	}
}

func TestBGPlay_Nodes_ASNAndOwner(t *testing.T) {
	is, ev, _, so := oneOfEach()
	nodes := []map[string]any{{"as_number": 13335, "owner": "CLOUDFLARENET"}}
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, nodes, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Nodes) != 1 || res.Nodes[0].ASN != 13335 || res.Nodes[0].Owner != "CLOUDFLARENET" {
		t.Errorf("Nodes = %+v", res.Nodes)
	}
}

func TestBGPlay_Nodes_OwnerPreservedLiterally_NoRelationshipInference(t *testing.T) {
	// Owner is intentionally passed through verbatim, whatever RIPEstat
	// reports — never parsed/classified into a provider/customer/transit
	// label. This test just pins that the raw string round-trips exactly.
	raw := "COGENT-174 - Cogent Communications, LLC, US"
	is, ev, _, so := oneOfEach()
	nodes := []map[string]any{{"as_number": 174, "owner": raw}}
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, nodes, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Nodes[0].Owner != raw {
		t.Errorf("Owner = %q, want literal %q — never rewritten/classified", res.Nodes[0].Owner, raw)
	}
}

func TestBGPlay_Sources_IDASNIPRRC(t *testing.T) {
	is, ev, no, _ := oneOfEach()
	sources := []map[string]any{{"as_number": 328840, "id": "00-102.208.105.2", "ip": "102.208.105.2", "rrc": "00"}}
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, no, sources))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Sources) != 1 {
		t.Fatalf("Sources = %d, want 1", len(res.Sources))
	}
	s := res.Sources[0]
	if s.ASN != 328840 || s.ID != "00-102.208.105.2" || s.IP != "102.208.105.2" || s.RRC != "00" {
		t.Errorf("Sources[0] = %+v", s)
	}
}

// --- Observed* correctness ---

func TestBGPlay_ObservedCounts_MatchRawTotals(t *testing.T) {
	is := make([]map[string]any, 3)
	for i := range is {
		is[i] = map[string]any{"source_id": fmt.Sprintf("src-%d", i), "target_prefix": "1.1.1.0/24", "path": []int{100}}
	}
	ev := make([]map[string]any, 4)
	for i := range ev {
		ev[i] = map[string]any{"seq": int64(i), "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": fmt.Sprintf("src-%d", i), "target_prefix": "1.1.1.0/24", "path": []int{100}}}
	}
	no := make([]map[string]any, 5)
	for i := range no {
		no[i] = map[string]any{"as_number": 100 + i, "owner": "X"}
	}
	so := make([]map[string]any, 2)
	for i := range so {
		so[i] = map[string]any{"as_number": 100 + i, "id": fmt.Sprintf("src-%d", i), "ip": "1.2.3.4", "rrc": "00"}
	}
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ObservedInitialState != 3 {
		t.Errorf("ObservedInitialState = %d, want 3", res.ObservedInitialState)
	}
	if res.ObservedEvents != 4 {
		t.Errorf("ObservedEvents = %d, want 4", res.ObservedEvents)
	}
	if res.ObservedNodes != 5 {
		t.Errorf("ObservedNodes = %d, want 5", res.ObservedNodes)
	}
	if len(res.Sources) != 2 {
		t.Errorf("len(Sources) = %d, want 2", len(res.Sources))
	}
	if res.Truncated {
		t.Error("Truncated = true, want false — nothing exceeded its limit")
	}
}

// --- deterministic truncation ---

func syntheticInitialState(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		out[i] = map[string]any{"source_id": fmt.Sprintf("src-%d", i), "target_prefix": "1.1.1.0/24", "path": []int{100}}
	}
	return out
}

func syntheticNodes(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		out[i] = map[string]any{"as_number": 1000 + i, "owner": fmt.Sprintf("OWNER-%d", i)}
	}
	return out
}

func TestBGPlay_InitialStateOverLimit_TruncatedDeterministically(t *testing.T) {
	const n = bgplayMaxInitialState + 50
	_, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, syntheticInitialState(n), ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.InitialState) != bgplayMaxInitialState {
		t.Errorf("len(InitialState) = %d, want %d", len(res.InitialState), bgplayMaxInitialState)
	}
	if res.ObservedInitialState != n {
		t.Errorf("ObservedInitialState = %d, want %d", res.ObservedInitialState, n)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true")
	}
	// Deterministic: first N in source order, never reordered.
	for i := 0; i < len(res.InitialState); i++ {
		if want := fmt.Sprintf("src-%d", i); res.InitialState[i].SourceID != want {
			t.Fatalf("InitialState[%d].SourceID = %q, want %q — must preserve source order", i, res.InitialState[i].SourceID, want)
		}
	}
}

func TestBGPlay_EventsOverLimit_TruncatedDeterministically(t *testing.T) {
	const n = bgplayMaxEvents + 50
	is, _, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, syntheticUpdates(n), no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Events) != bgplayMaxEvents {
		t.Errorf("len(Events) = %d, want %d", len(res.Events), bgplayMaxEvents)
	}
	if res.ObservedEvents != n {
		t.Errorf("ObservedEvents = %d, want %d", res.ObservedEvents, n)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestBGPlay_NodesOverLimit_TruncatedDeterministically(t *testing.T) {
	const n = bgplayMaxNodes + 50
	is, ev, _, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, is, ev, syntheticNodes(n), so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Nodes) != bgplayMaxNodes {
		t.Errorf("len(Nodes) = %d, want %d", len(res.Nodes), bgplayMaxNodes)
	}
	if res.ObservedNodes != n {
		t.Errorf("ObservedNodes = %d, want %d", res.ObservedNodes, n)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true")
	}
	for i := 0; i < len(res.Nodes); i++ {
		if want := 1000 + i; res.Nodes[i].ASN != want {
			t.Fatalf("Nodes[%d].ASN = %d, want %d — must preserve source order", i, res.Nodes[i].ASN, want)
		}
	}
}

func TestBGPlay_Truncated_TrueIfAnyCollectionTruncated(t *testing.T) {
	// Only InitialState exceeds its limit — Truncated must still be true.
	const n = bgplayMaxInitialState + 1
	_, ev, no, so := oneOfEach()
	addr := bgplayFixtureServer(t, bgplayEnvelope(t, syntheticInitialState(n), ev, no, so))
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true — InitialState alone exceeded its limit")
	}
	if res.ObservedEvents > bgplayMaxEvents || res.ObservedNodes > bgplayMaxNodes {
		t.Fatal("test setup error: only InitialState should exceed its limit")
	}
}

// --- local validation, zero HTTP ---

func TestBGPlay_InvalidTemporalRequest_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPlay(context.Background(), BGPlayRequest{Resource: "1.1.1.0/24", StartTime: validEnd, EndTime: validStart})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
		t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
	}
}

func TestBGPlay_InvalidResource_ZeroHTTP(t *testing.T) {
	c := &Client{BaseURL: failIfCalledHTTP(t)}
	res := c.BGPlay(context.Background(), BGPlayRequest{Resource: "garbage!!", StartTime: validStart, EndTime: validEnd})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection")
	}
}

// --- datasource failure paths ---

func TestBGPlay_MalformedResponse_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if len(res.InitialState) != 0 || len(res.Events) != 0 || len(res.Nodes) != 0 || len(res.Sources) != 0 {
		t.Errorf("expected all collections empty on failure, got InitialState=%d Events=%d Nodes=%d Sources=%d",
			len(res.InitialState), len(res.Events), len(res.Nodes), len(res.Sources))
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

func TestBGPlay_DatasourceHTTPError_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	res := c.BGPlay(context.Background(), validBGPlayReq())
	if res.Err == "" {
		t.Fatal("Err empty, want a datasource error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}
