package api

import (
	"net/http"
	"testing"

	"trazip/internal/bgp"
)

func TestBGPCountryObservatoryDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/country-resource-stats/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{
				"resource":"PA","starttime":"2026-01-01T00:00:00","endtime":"2026-01-02T00:00:00",
				"query_starttime":"2026-01-01T00:00:00","query_endtime":"2026-01-02T00:00:00",
				"earliest_time":"2000-01-01T00:00:00","latest_time":"2026-08-20T00:00:00",
				"hd_latest_time":"2026-08-20T00:00:00","resolution":"1d",
				"stats":[{"stat_time":"2026-01-01T00:00:00","resource_count":{"ipv4":10,"ipv6":5,"asn":2}}]
			}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPCountryObservatory(bgp.CountryObservatoryRequest{
		Country: "pa", StartTime: "2026-01-01T00:00:00Z", EndTime: "2026-01-02T00:00:00Z", Resolution: "1d",
	})

	if res.Country != "PA" {
		t.Fatalf("Country = %q, want PA — method must delegate to bgp.Client.CountryObservatory, not reimplement it", res.Country)
	}
	if !res.DataSufficient {
		t.Fatalf("DataSufficient = false, want true (stats non-empty)")
	}
}

func TestBGPGlobalObservatoryDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/ris-asns/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"query_time":"2026-08-20T00:00:00","counts":{"total":100000}}}`))
		},
		"/ris-peer-count/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"starttime":"2026-08-20T00:00:00","endtime":"2026-08-20T00:00:00","peer_count":{
				"v4":{"total":[{"timestamp":"2026-08-20T00:00:00","count":900}],"full_feed":[{"timestamp":"2026-08-20T00:00:00","count":800}]},
				"v6":{"total":[{"timestamp":"2026-08-20T00:00:00","count":700}],"full_feed":[{"timestamp":"2026-08-20T00:00:00","count":600}]}
			}}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPGlobalObservatory()

	if res.VisibleASNs == nil || *res.VisibleASNs != 100000 {
		t.Fatalf("VisibleASNs = %v, want 100000 — method must delegate to bgp.Client.GlobalRISObservatory", res.VisibleASNs)
	}
	if !res.DataSufficient {
		t.Fatalf("DataSufficient = false, want true")
	}
}

func TestBGPASNObservatoryDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","prefixes":[
				{"prefix":"1.1.1.0/24","timelines":[]},
				{"prefix":"2606:4700::/32","timelines":[]}
			]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPASNObservatory(bgp.ASNObservatoryRequest{ASN: "AS13335"})

	if res.ASN != 13335 {
		t.Fatalf("ASN = %d, want 13335 — method must delegate to bgp.Client.ASNObservatory", res.ASN)
	}
	if res.AnnouncedIPv4Prefixes != 1 || res.AnnouncedIPv6Prefixes != 1 {
		t.Fatalf("AnnouncedIPv4Prefixes=%d AnnouncedIPv6Prefixes=%d, want 1/1", res.AnnouncedIPv4Prefixes, res.AnnouncedIPv6Prefixes)
	}
	if !res.DataSufficient {
		t.Fatalf("DataSufficient = false, want true")
	}
}

func TestBGPRPKIObservatoryDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/rpki-history/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","rpki":{"vrp_count":42}}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPRPKIObservatory(bgp.RPKIObservatoryRequest{Resource: "AS13335", Family: 4, Resolution: "d"})

	if res.Resource != "AS13335" {
		t.Fatalf("Resource = %q, want AS13335 — method must delegate to bgp.Client.RPKIObservatory", res.Resource)
	}
	if res.ResourceKind != "asn" {
		t.Fatalf("ResourceKind = %q, want asn", res.ResourceKind)
	}
}

func TestBGPBogonLookupDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{})
	s := newTestServiceWithBGP(addr)

	res := s.BGPBogonLookup(bgp.BogonLookupRequest{Resource: "not-a-valid-resource!!"})
	if res.Resource != "not-a-valid-resource!!" {
		t.Fatalf("Resource = %q, want the trimmed original input — method must delegate to bgp.Client.BogonLookup", res.Resource)
	}
	if res.Err == "" {
		t.Fatalf("Err = empty, want a message for invalid input — local validation must short-circuit before any network access")
	}
}

func TestBGPObservatoryMethodsInvalidInputNeverPanics(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{})
	s := newTestServiceWithBGP(addr)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a BGP observatory method panicked on invalid input: %v", r)
		}
	}()

	country := s.BGPCountryObservatory(bgp.CountryObservatoryRequest{Country: "not-a-country"})
	if country.Err == "" {
		t.Errorf("BGPCountryObservatory: Err = empty, want a message for invalid country")
	}

	asn := s.BGPASNObservatory(bgp.ASNObservatoryRequest{ASN: "not-an-asn"})
	if asn.Err == "" {
		t.Errorf("BGPASNObservatory: Err = empty, want a message for invalid ASN")
	}

	rpki := s.BGPRPKIObservatory(bgp.RPKIObservatoryRequest{Resource: "not-a-valid-resource!!", Family: 4, Resolution: "d"})
	if rpki.Err == "" {
		t.Errorf("BGPRPKIObservatory: Err = empty, want a message for invalid input")
	}

	bogon := s.BGPBogonLookup(bgp.BogonLookupRequest{Resource: "not-a-valid-resource!!"})
	if bogon.Err == "" {
		t.Errorf("BGPBogonLookup: Err = empty, want a message for invalid input")
	}
}
