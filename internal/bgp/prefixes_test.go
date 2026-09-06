package bgp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func prefixesFixtureJSON(resource string, prefixes []string) string {
	var b strings.Builder
	b.WriteString(`{"status":"ok","data":{"resource":"`)
	b.WriteString(resource)
	b.WriteString(`","prefixes":[`)
	for i, p := range prefixes {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(`{"prefix":"%s","timelines":[{"starttime":"2026-01-01T00:00:00","endtime":"2026-01-02T00:00:00"}]}`, p))
	}
	b.WriteString(`]}}`)
	return b.String()
}

func routingStatusFixtureJSON(resource string, origins []int) string {
	var parts []string
	for _, o := range origins {
		parts = append(parts, fmt.Sprintf(`{"origin":%d}`, o))
	}
	return fmt.Sprintf(`{"status":"ok","data":{"resource":"%s","origins":[%s],"visibility":{"v4":{"ris_peers_seeing":8,"total_ris_peers":10},"v6":{"ris_peers_seeing":4,"total_ris_peers":10}}}}`,
		resource, strings.Join(parts, ","))
}

func ipv4PrefixList(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("10.%d.0.0/24", i)
	}
	return out
}

func ipv6PrefixList(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("2001:db8:%x::/48", i)
	}
	return out
}

// ---- PREFIX LIST ----

func TestPrefixListASNValid(t *testing.T) {
	prefixes := []string{"10.0.0.0/24", "10.0.1.0/24"}
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if page.Err != "" {
		t.Fatalf("Err = %q, want empty", page.Err)
	}
	if page.TotalItems != 2 || page.TotalPages != 1 {
		t.Fatalf("TotalItems=%d TotalPages=%d, want 2/1", page.TotalItems, page.TotalPages)
	}
	if len(page.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(page.Items))
	}
	for _, row := range page.Items {
		if row.State != PrefixLoaded {
			t.Errorf("row %s: State = %q, want %q", row.Prefix, row.State, PrefixLoaded)
		}
		if row.RPKI == nil || row.RPKI.State != RPKIValid {
			t.Errorf("row %s: RPKI = %+v, want VALID", row.Prefix, row.RPKI)
		}
		if len(row.Origins) != 1 || row.Origins[0] != 100 {
			t.Errorf("row %s: Origins = %v, want [100]", row.Prefix, row.Origins)
		}
		if row.MOAS {
			t.Errorf("row %s: MOAS = true, want false", row.Prefix)
		}
	}
}

func TestPrefixListInvalidASNNoHTTP(t *testing.T) {
	var calls int32
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS0","prefixes":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 0, Page: 1})

	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("calls = %d, want 0 — invalid ASN must never reach the network", calls)
	}
	if page.Err == "" {
		t.Fatalf("Err = empty, want a message for an invalid ASN")
	}
}

func TestPrefixListZeroPrefixes(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", nil)))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if page.Err != "" {
		t.Fatalf("Err = %q, want empty — zero prefixes is a valid, useful result", page.Err)
	}
	if page.TotalItems != 0 || page.TotalPages != 0 {
		t.Fatalf("TotalItems=%d TotalPages=%d, want 0/0", page.TotalItems, page.TotalPages)
	}
	if len(page.Items) != 0 {
		t.Fatalf("len(Items) = %d, want 0", len(page.Items))
	}
	ev := findEvidence(page.Evidence, "announced-prefixes")
	if ev == nil || ev.Status != ComponentOK {
		t.Fatalf("announced-prefixes evidence = %+v, want ComponentOK — empty is not ComponentUnavailable", ev)
	}
}

func TestPrefixListFamilyFilter(t *testing.T) {
	v4 := ipv4PrefixList(3)
	v6 := ipv6PrefixList(2)
	all := append(append([]string{}, v4...), v6...)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", all)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1, Family: "ipv6"})

	if page.TotalItems != len(v6) {
		t.Fatalf("TotalItems = %d, want %d", page.TotalItems, len(v6))
	}
	for _, row := range page.Items {
		if row.Family != "ipv6" {
			t.Errorf("row %s: Family = %q, want ipv6", row.Prefix, row.Family)
		}
	}
}

func TestPrefixListSearch(t *testing.T) {
	prefixes := []string{"10.0.0.0/24", "10.0.1.0/24", "192.168.0.0/24"}
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1, Search: "10.0."})

	if page.TotalItems != 2 {
		t.Fatalf("TotalItems = %d, want 2", page.TotalItems)
	}
	for _, row := range page.Items {
		if !strings.Contains(row.Prefix, "10.0.") {
			t.Errorf("row %s does not match search", row.Prefix)
		}
	}
}

func TestPrefixListSortAscDesc(t *testing.T) {
	prefixes := []string{"10.0.2.0/24", "10.0.0.0/24", "10.0.1.0/24"}
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	asc := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1, Sort: "prefix_asc"})
	wantAsc := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
	for i, row := range asc.Items {
		if row.Prefix != wantAsc[i] {
			t.Errorf("asc[%d] = %q, want %q", i, row.Prefix, wantAsc[i])
		}
	}

	desc := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1, Sort: "prefix_desc"})
	wantDesc := []string{"10.0.2.0/24", "10.0.1.0/24", "10.0.0.0/24"}
	for i, row := range desc.Items {
		if row.Prefix != wantDesc[i] {
			t.Errorf("desc[%d] = %q, want %q", i, row.Prefix, wantDesc[i])
		}
	}
}

func TestPrefixListPagination(t *testing.T) {
	prefixes := ipv4PrefixList(30)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	page1 := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})
	if len(page1.Items) != 25 {
		t.Fatalf("page1 len(Items) = %d, want 25", len(page1.Items))
	}
	if page1.TotalPages != 2 {
		t.Fatalf("TotalPages = %d, want 2", page1.TotalPages)
	}

	page2 := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 2})
	if len(page2.Items) != 5 {
		t.Fatalf("page2 len(Items) = %d, want 5", len(page2.Items))
	}
}

func TestPrefixListOutOfRange(t *testing.T) {
	prefixes := ipv4PrefixList(3)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 99})

	if page.Err != "" {
		t.Fatalf("Err = %q, want empty — out-of-range page is a valid empty page, not an error", page.Err)
	}
	if page.Page != 99 {
		t.Fatalf("Page = %d, want 99 (echoed verbatim)", page.Page)
	}
	if len(page.Items) != 0 {
		t.Fatalf("len(Items) = %d, want 0", len(page.Items))
	}
}

func TestPrefixListPageZeroIsOutOfRange(t *testing.T) {
	prefixes := ipv4PrefixList(3)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 0})

	if len(page.Items) != 0 {
		t.Fatalf("len(Items) = %d, want 0 (Page < 1 is out of range)", len(page.Items))
	}
	if page.Page != 0 {
		t.Fatalf("Page = %d, want 0 (echoed verbatim)", page.Page)
	}
}

func TestPrefixListTimelinesPreserved(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","prefixes":[{"prefix":"10.0.0.0/24","timelines":[{"starttime":"2026-01-01T00:00:00","endtime":"2026-01-02T00:00:00"},{"starttime":"2026-01-05T00:00:00","endtime":"2026-01-06T00:00:00"}]}]}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON("10.0.0.0/24", []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if len(page.Items) != 1 || len(page.Items[0].Timelines) != 2 {
		t.Fatalf("Items = %+v, want 1 row with 2 timelines", page.Items)
	}
	if page.Items[0].Timelines[0].StartTime != "2026-01-01T00:00:00" || page.Items[0].Timelines[1].EndTime != "2026-01-06T00:00:00" {
		t.Fatalf("Timelines = %+v, values not preserved", page.Items[0].Timelines)
	}
}

// ---- ENRICHMENT ----

func TestPrefixListExact50CallCap(t *testing.T) {
	var routingCalls, rpkiCalls int32
	prefixes := ipv4PrefixList(25)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&routingCalls, 1)
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&rpkiCalls, 1)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if len(page.Items) != 25 {
		t.Fatalf("len(Items) = %d, want 25", len(page.Items))
	}
	if atomic.LoadInt32(&routingCalls) != 25 {
		t.Fatalf("routingCalls = %d, want 25", routingCalls)
	}
	if atomic.LoadInt32(&rpkiCalls) != 25 {
		t.Fatalf("rpkiCalls = %d, want 25", rpkiCalls)
	}
	total := atomic.LoadInt32(&routingCalls) + atomic.LoadInt32(&rpkiCalls)
	if total != 50 {
		t.Fatalf("total calls = %d, want exactly 50, never 51", total)
	}
}

func TestPrefixListMOASDoesNotExceedCap(t *testing.T) {
	var routingCalls, rpkiCalls int32
	prefixes := ipv4PrefixList(25)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&routingCalls, 1)
			// Every row is a MOAS (3 origins) — RPKI must still be
			// validated exactly once per row, for the queried ASN only.
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100, 200, 300})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&rpkiCalls, 1)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	for _, row := range page.Items {
		if !row.MOAS {
			t.Errorf("row %s: MOAS = false, want true", row.Prefix)
		}
	}
	total := atomic.LoadInt32(&routingCalls) + atomic.LoadInt32(&rpkiCalls)
	if total != 50 {
		t.Fatalf("total calls = %d, want exactly 50 even with every row a MOAS", total)
	}
}

func TestPrefixListVisibilityFamilySelection(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", []string{"10.0.0.0/24", "2001:db8::/32"})))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	for _, row := range page.Items {
		if row.Visibility == nil {
			t.Fatalf("row %s: Visibility = nil, want populated", row.Prefix)
		}
		if row.Family == "ipv4" && row.Visibility.Family != "v4" {
			t.Errorf("row %s: Visibility.Family = %q, want v4", row.Prefix, row.Visibility.Family)
		}
		if row.Family == "ipv6" && row.Visibility.Family != "v6" {
			t.Errorf("row %s: Visibility.Family = %q, want v6", row.Prefix, row.Visibility.Family)
		}
	}
}

func TestPrefixListQueriedASNRPKI(t *testing.T) {
	var mu sync.Mutex
	var rpkiASNsQueried []string
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS777", []string{"10.0.0.0/24"})))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			// MOAS with an origin different from the queried ASN.
			w.Write([]byte(routingStatusFixtureJSON("10.0.0.0/24", []int{777, 999})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			rpkiASNsQueried = append(rpkiASNsQueried, r.URL.Query().Get("resource"))
			mu.Unlock()
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 777, Page: 1})

	if len(rpkiASNsQueried) != 1 || rpkiASNsQueried[0] != "777" {
		t.Fatalf("rpkiASNsQueried = %v, want exactly [\"777\"] — RPKI must validate only the queried ASN, never other origins", rpkiASNsQueried)
	}
	if len(page.Items) != 1 || page.Items[0].RPKI == nil || page.Items[0].RPKI.ASN != 777 {
		t.Fatalf("Items = %+v, want RPKI.ASN=777", page.Items)
	}
}

func latencyForPrefix(prefixes []string, prefix string) time.Duration {
	for i, p := range prefixes {
		if p == prefix {
			return time.Duration(len(prefixes)-i) * 2 * time.Millisecond
		}
	}
	return 0
}

func TestPrefixListOrderPreservedDespiteVariableLatency(t *testing.T) {
	prefixes := ipv4PrefixList(10)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			prefix := r.URL.Query().Get("resource")
			// Reverse-order artificial latency: the FIRST prefix responds
			// slowest, the LAST responds fastest — if ordering depended on
			// completion order rather than request index, this surfaces it.
			time.Sleep(latencyForPrefix(prefixes, prefix))
			w.Write([]byte(routingStatusFixtureJSON(prefix, []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if len(page.Items) != len(prefixes) {
		t.Fatalf("len(Items) = %d, want %d", len(page.Items), len(prefixes))
	}
	for i, row := range page.Items {
		if row.Prefix != prefixes[i] {
			t.Fatalf("Items[%d].Prefix = %q, want %q (order must match the requested page order, not completion order)", i, row.Prefix, prefixes[i])
		}
	}
}

func TestPrefixListPartialRowFailurePreservesPage(t *testing.T) {
	prefixes := ipv4PrefixList(3)
	failPrefix := prefixes[1]
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			prefix := r.URL.Query().Get("resource")
			if prefix == failPrefix {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(routingStatusFixtureJSON(prefix, []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if page.Err != "" {
		t.Fatalf("Err = %q, want empty — a single row failing must never fail the whole page", page.Err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("len(Items) = %d, want 3", len(page.Items))
	}
	for _, row := range page.Items {
		if row.Prefix == failPrefix {
			if row.State != PrefixDegraded {
				t.Errorf("row %s: State = %q, want %q", row.Prefix, row.State, PrefixDegraded)
			}
		} else if row.State != PrefixLoaded {
			t.Errorf("row %s: State = %q, want %q", row.Prefix, row.State, PrefixLoaded)
		}
	}
}

func TestPrefixListCancellationTerminatesWorkers(t *testing.T) {
	prefixes := ipv4PrefixList(5)
	ctx, cancel := context.WithCancel(context.Background())
	var cancelled int32

	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			if atomic.CompareAndSwapInt32(&cancelled, 0, 1) {
				cancel()
			}
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	done := make(chan PrefixPage, 1)
	go func() { done <- c.PrefixList(ctx, PrefixPageRequest{ASN: 100, Page: 1}) }()

	select {
	case page := <-done:
		if len(page.Items) != 5 {
			t.Fatalf("len(Items) = %d, want 5 (every row still gets a result, degraded where cancellation hit)", len(page.Items))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PrefixList did not return after context cancellation — a worker may be hanging (goroutine leak)")
	}
}

func TestPrefixListConcurrencyCapAtMostFour(t *testing.T) {
	var current, max int32
	trackStart := func() {
		v := atomic.AddInt32(&current, 1)
		for {
			m := atomic.LoadInt32(&max)
			if v <= m || atomic.CompareAndSwapInt32(&max, m, v) {
				break
			}
		}
	}
	trackEnd := func() { atomic.AddInt32(&current, -1) }

	prefixes := ipv4PrefixList(20)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			trackStart()
			defer trackEnd()
			time.Sleep(5 * time.Millisecond)
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			trackStart()
			defer trackEnd()
			time.Sleep(5 * time.Millisecond)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if len(page.Items) != 20 {
		t.Fatalf("len(Items) = %d, want 20", len(page.Items))
	}
	if atomic.LoadInt32(&max) > maxPrefixEnrichmentConcurrency {
		t.Fatalf("max concurrent in-flight requests = %d, want <= %d", max, maxPrefixEnrichmentConcurrency)
	}
}

// ---- CACHE ----

func TestPrefixListRepeatPageNoExtraHTTP(t *testing.T) {
	var routingCalls, rpkiCalls, prefixesCalls int32
	prefixes := ipv4PrefixList(5)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&prefixesCalls, 1)
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&routingCalls, 1)
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&rpkiCalls, 1)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})
	page2 := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if atomic.LoadInt32(&prefixesCalls) != 1 {
		t.Errorf("prefixesCalls = %d, want 1 (second call must hit cache)", prefixesCalls)
	}
	if atomic.LoadInt32(&routingCalls) != 5 {
		t.Errorf("routingCalls = %d, want 5 (no extra calls on the second page fetch)", routingCalls)
	}
	if atomic.LoadInt32(&rpkiCalls) != 5 {
		t.Errorf("rpkiCalls = %d, want 5 (no extra calls on the second page fetch)", rpkiCalls)
	}
	for _, row := range page2.Items {
		for _, ev := range row.Evidence {
			if !ev.FromCache {
				t.Errorf("row %s: evidence %s FromCache = false, want true on second page fetch", row.Prefix, ev.Component)
			}
		}
	}
}

func TestPrefixListTTLExpiryRefetch(t *testing.T) {
	var routingCalls, rpkiCalls int32
	prefixes := ipv4PrefixList(2)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", prefixes)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&routingCalls, 1)
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&rpkiCalls, 1)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	clk := newFakeClock()
	c.getCache().now = clk.Now

	c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})
	if atomic.LoadInt32(&routingCalls) != 2 || atomic.LoadInt32(&rpkiCalls) != 2 {
		t.Fatalf("initial calls = routing:%d rpki:%d, want 2/2", routingCalls, rpkiCalls)
	}

	clk.Advance(rpkiValidationTTL + time.Minute) // past every relevant TTL
	c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1})

	if atomic.LoadInt32(&routingCalls) != 4 || atomic.LoadInt32(&rpkiCalls) != 4 {
		t.Fatalf("calls after TTL expiry = routing:%d rpki:%d, want 4/4 (re-fetched)", routingCalls, rpkiCalls)
	}
}

// ---- FILTER/PAGE BUDGET ----

func TestPrefixListFilterBeforePageLimitsEnrichmentToFilteredCount(t *testing.T) {
	v4 := ipv4PrefixList(88)
	v6 := ipv6PrefixList(12)
	all := append(append([]string{}, v4...), v6...)
	var routingCalls, rpkiCalls int32
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(prefixesFixtureJSON("AS100", all)))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&routingCalls, 1)
			w.Write([]byte(routingStatusFixtureJSON(r.URL.Query().Get("resource"), []int{100})))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&rpkiCalls, 1)
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	page := c.PrefixList(context.Background(), PrefixPageRequest{ASN: 100, Page: 1, Family: "ipv6"})

	if page.TotalItems != 12 {
		t.Fatalf("TotalItems = %d, want 12", page.TotalItems)
	}
	if len(page.Items) != 12 {
		t.Fatalf("len(Items) = %d, want 12 — all 12 fit on one page", len(page.Items))
	}
	if atomic.LoadInt32(&routingCalls) != 12 || atomic.LoadInt32(&rpkiCalls) != 12 {
		t.Fatalf("calls = routing:%d rpki:%d, want 12/12 — only the filtered, visible rows must be enriched, never all 100", routingCalls, rpkiCalls)
	}
}
