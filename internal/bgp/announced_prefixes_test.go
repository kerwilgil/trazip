package bgp

import (
	"context"
	"net/http"
	"testing"
)

func TestAnnouncedPrefixesRawMultiplePrefixesAndTimelines(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"3333",
			"query_starttime":"2024-11-28T12:00:00Z",
			"query_endtime":"2024-12-12T12:00:00Z",
			"earliest_time":"2024-11-28T12:00:00Z",
			"latest_time":"2024-12-12T12:00:00Z",
			"prefixes":[
				{"prefix":"192.0.2.0/24","timelines":[
					{"starttime":"2024-11-28T12:00:00Z","endtime":"2024-12-12T12:00:00Z"},
					{"starttime":"2024-12-01T08:30:00Z","endtime":"2024-12-05T14:15:00Z"}
				]},
				{"prefix":"203.0.113.0/25","timelines":[
					{"starttime":"2024-12-01T00:00:00Z","endtime":"2024-12-12T12:00:00Z"}
				]}
			]
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AnnouncedPrefixesRaw(context.Background(), 3333)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.QueryStartTime != "2024-11-28T12:00:00Z" || res.QueryEndTime != "2024-12-12T12:00:00Z" {
		t.Errorf("query range not preserved: start=%q end=%q", res.QueryStartTime, res.QueryEndTime)
	}
	if len(res.Prefixes) != 2 {
		t.Fatalf("Prefixes = %+v, want 2 entries", res.Prefixes)
	}
	if len(res.Prefixes[0].Timelines) != 2 {
		t.Fatalf("first prefix timelines = %+v, want 2", res.Prefixes[0].Timelines)
	}
	if res.Prefixes[0].Timelines[1].StartTime != "2024-12-01T08:30:00Z" {
		t.Errorf("second timeline start = %q", res.Prefixes[0].Timelines[1].StartTime)
	}
	if res.Evidence.Status != ComponentOK || res.Evidence.Component != "announced-prefixes" {
		t.Errorf("Evidence = %+v", res.Evidence)
	}
}

func TestAnnouncedPrefixesRawEmptyListIsValid(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"64500","prefixes":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AnnouncedPrefixesRaw(context.Background(), 64500)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Prefixes) != 0 {
		t.Errorf("Prefixes = %+v, want empty", res.Prefixes)
	}
	if res.Evidence.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s — an empty prefix list is a valid result", res.Evidence.Status, ComponentOK)
	}
}

func TestAnnouncedPrefixesRawMalformedResponse(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})
	c := &Client{BaseURL: addr}
	res := c.AnnouncedPrefixesRaw(context.Background(), 3333)

	if res.Err == "" {
		t.Fatal("expected Err on malformed response")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
	if len(res.Prefixes) != 0 {
		t.Errorf("Prefixes = %+v, want empty — never a partial list on a parse failure", res.Prefixes)
	}
}

func TestAnnouncedPrefixesRawInvalidASNNoHTTPCall(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"1","prefixes":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AnnouncedPrefixesRaw(context.Background(), 0)

	if res.Err == "" {
		t.Error("expected Err for invalid ASN")
	}
	if res.Evidence.Status != ComponentNotApplicable {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentNotApplicable)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0", requests)
	}
}

func TestAnnouncedPrefixesRawHTTPError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.AnnouncedPrefixesRaw(context.Background(), 3333)
	if res.Err == "" {
		t.Fatal("expected Err on HTTP failure")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}
