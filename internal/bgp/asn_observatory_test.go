package bgp

import (
	"context"
	"net/http"
	"testing"
)

func announcedPrefixesFixtureBody(prefixes ...string) string {
	entries := ""
	for i, p := range prefixes {
		if i > 0 {
			entries += ","
		}
		entries += `{"prefix":"` + p + `","timelines":[{"starttime":"2026-08-20T00:00:00Z","endtime":"2026-08-20T01:00:00Z"}]}`
	}
	return `{"status":"ok","data":{"resource":"AS13335","prefixes":[` + entries + `]}}`
}

// --- 15-17: valid ASN acceptance + normalization ---

func TestASNObservatory_ValidAS13335(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody("1.1.1.0/24", "2606:4700::/32")))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ASN != 13335 {
		t.Errorf("ASN = %d, want 13335", res.ASN)
	}
}

func TestASNObservatory_Valid13335_NoPrefix(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody("1.1.1.0/24", "2606:4700::/32")))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ASN != 13335 {
		t.Errorf("ASN = %d, want 13335", res.ASN)
	}
}

func TestASNObservatory_BothFormsNormalizeToSameASN(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody()))
	})
	a := (&Client{BaseURL: addr}).ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	b := (&Client{BaseURL: addr}).ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "13335"})
	if a.Err != "" || b.Err != "" {
		t.Fatalf("unexpected Err: a=%q b=%q", a.Err, b.Err)
	}
	if a.ASN != b.ASN {
		t.Errorf("ASN mismatch: %q -> %d, %q -> %d", "AS13335", a.ASN, "13335", b.ASN)
	}
}

// --- 18-24: local rejections, zero HTTP calls ---

func TestASNObservatory_InvalidInputs_ZeroHTTP(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"AS0":          "AS0",
		"zero":         "0",
		"negative":     "-5",
		"non-numeric":  "ASABC",
		"ip":           "1.1.1.1",
		"prefix":       "1.1.1.0/24",
		"country code": "PA",
		"out of range": "4294967296",
	}
	for name, asn := range cases {
		t.Run(name, func(t *testing.T) {
			c := &Client{BaseURL: failIfCalledHTTP(t)}
			res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: asn})
			if res.Err == "" {
				t.Fatalf("Err empty for %q, want a rejection", asn)
			}
			if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentNotApplicable {
				t.Errorf("Evidence = %+v, want single ComponentNotApplicable entry", res.Evidence)
			}
		})
	}
}

// --- 25: zero HTTP calls for every local validation, combined proof ---

func TestASNObservatory_EveryLocalRejection_ZeroNetworkCalls(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	for _, asn := range []string{"", "AS0", "0", "-5", "ASABC", "1.1.1.1", "1.1.1.0/24", "PA"} {
		c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: asn})
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0 across every local rejection", requests)
	}
}

// --- 26-27: IPv4/IPv6 counts correct ---

func TestASNObservatory_IPv4IPv6CountsCorrect(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody(
			"1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24",
			"2606:4700::/32", "2001:4860::/32",
		)))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.AnnouncedIPv4Prefixes != 3 {
		t.Errorf("AnnouncedIPv4Prefixes = %d, want 3", res.AnnouncedIPv4Prefixes)
	}
	if res.AnnouncedIPv6Prefixes != 2 {
		t.Errorf("AnnouncedIPv6Prefixes = %d, want 2", res.AnnouncedIPv6Prefixes)
	}
}

// --- 28: valid ASN with explicit zero prefixes ---

func TestASNObservatory_ExplicitZeroPrefixes_DataSufficient(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody()))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.AnnouncedIPv4Prefixes != 0 || res.AnnouncedIPv6Prefixes != 0 {
		t.Errorf("counts = %d/%d, want 0/0", res.AnnouncedIPv4Prefixes, res.AnnouncedIPv6Prefixes)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true — the source explicitly reported zero prefixes")
	}
}

// --- 29: datasource error ---

func TestASNObservatory_DatasourceHTTPError_Degraded(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err == "" {
		t.Fatal("Err empty, want a datasource error")
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false — datasource failure is never presented as zero prefixes")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- 30: malformed JSON — no decode of its own here, proves the failure
// still propagates correctly through the reused AnnouncedPrefixesRaw path
// (this file adds no new decode logic; see reuse note in asn_observatory.go) ---

func TestASNObservatory_MalformedJSON_PropagatesFromReusedDecoder(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err == "" {
		t.Fatal("Err empty, want a decode error")
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Status != ComponentDegraded {
		t.Errorf("Evidence = %+v, want single ComponentDegraded entry", res.Evidence)
	}
}

// --- 31: Evidence correct (component name, disclosure present on success) ---

func TestASNObservatory_Evidence_Correct(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(announcedPrefixesFixtureBody("1.1.1.0/24")))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Evidence) != 1 {
		t.Fatalf("Evidence = %+v, want exactly 1 entry", res.Evidence)
	}
	e := res.Evidence[0]
	if e.Component != "announced-prefixes" {
		t.Errorf("Evidence.Component = %q, want %q", e.Component, "announced-prefixes")
	}
	if e.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s", e.Status, ComponentOK)
	}
	if e.Disclosure.Source == "" {
		t.Error("Evidence.Disclosure.Source empty, want a real disclosure")
	}
}

// --- 32: DataSufficient correct across all three states ---

func TestASNObservatory_DataSufficient_AllStates(t *testing.T) {
	t.Run("local rejection", func(t *testing.T) {
		c := &Client{BaseURL: failIfCalledHTTP(t)}
		res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: ""})
		if res.DataSufficient {
			t.Error("DataSufficient = true, want false")
		}
	})
	t.Run("datasource failure", func(t *testing.T) {
		addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		c := &Client{BaseURL: addr}
		res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
		if res.DataSufficient {
			t.Error("DataSufficient = true, want false")
		}
	})
	t.Run("success", func(t *testing.T) {
		addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(announcedPrefixesFixtureBody("1.1.1.0/24")))
		})
		c := &Client{BaseURL: addr}
		res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
		if !res.DataSufficient {
			t.Error("DataSufficient = false, want true")
		}
	})
}

// --- 33: reuse of existing code proven — ASNObservatory must make exactly
// the same one HTTP call AnnouncedPrefixesRaw would make on its own, never
// a second query to the same or a different datasource.

func TestASNObservatory_ReusesAnnouncedPrefixes_ExactlyOneHTTPCall(t *testing.T) {
	var requests int
	var lastPath string
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		lastPath = r.URL.Path
		w.Write([]byte(announcedPrefixesFixtureBody("1.1.1.0/24")))
	})
	c := &Client{BaseURL: addr}
	res := c.ASNObservatory(context.Background(), ASNObservatoryRequest{ASN: "AS13335"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want exactly 1", requests)
	}
	if lastPath != "/announced-prefixes/data.json" {
		t.Errorf("path = %q, want the real announced-prefixes endpoint (proves reuse, not a new datasource)", lastPath)
	}
}
