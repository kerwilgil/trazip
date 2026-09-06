package dnsintel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

// startFakeServer runs a hermetic in-process authoritative DNS server so
// tests never depend on real network access, matching the synthetic-PCAP
// discipline used for the VoIP protocol tests.
func startFakeServer(t *testing.T, handler func(context.Context, dns.ResponseWriter, *dns.Msg)) string {
	t.Helper()
	cancel, addr, err := dnstest.UDPServer("127.0.0.1:0", func(s *dns.Server) {
		s.Handler = dns.HandlerFunc(handler)
	})
	if err != nil {
		t.Fatalf("dnstest.UDPServer: %v", err)
	}
	t.Cleanup(cancel)
	return addr
}

func reply(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)
	return m
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.New(s)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", s, err)
	}
	return rr
}

func TestQueryA(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "example.test. 300 IN A 203.0.113.10"))
		m.WriteTo(w)
	})

	res := Query(context.Background(), "example.test", "A", addr, false)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Records) != 1 || res.Records[0].Value != "203.0.113.10" {
		t.Fatalf("records = %+v, want one A 203.0.113.10", res.Records)
	}
	if res.Records[0].TTL != 300 {
		t.Errorf("TTL = %d, want 300", res.Records[0].TTL)
	}
	if res.RCode != "NOERROR" {
		t.Errorf("RCode = %s, want NOERROR", res.RCode)
	}
}

func TestQuerySOAAndCAA(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		switch dns.RRToType(r.Question[0]) {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, mustRR(t, "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026071401 7200 3600 1209600 3600"))
		case dns.TypeCAA:
			m.Answer = append(m.Answer, mustRR(t, `example.test. 3600 IN CAA 0 issue "letsencrypt.org"`))
		}
		m.WriteTo(w)
	})

	soa := Query(context.Background(), "example.test", "SOA", addr, false)
	if len(soa.Records) != 1 || !strings.Contains(soa.Records[0].Value, "serial=2026071401") {
		t.Fatalf("SOA record = %+v", soa.Records)
	}

	caa := Query(context.Background(), "example.test", "CAA", addr, false)
	if len(caa.Records) != 1 || !strings.Contains(caa.Records[0].Value, "letsencrypt.org") {
		t.Fatalf("CAA record = %+v", caa.Records)
	}
}

func TestQuerySRVDirectNamePreservesExactName(t *testing.T) {
	var gotQName string
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		gotQName = r.Question[0].Header().Name
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "cpbxa.example.test. 300 IN SRV 2 9 5060 cpbx02.example.test."))
		m.Answer = append(m.Answer, mustRR(t, "cpbxa.example.test. 300 IN SRV 1 9 5060 cpbx09.example.test."))
		m.WriteTo(w)
	})

	res := Query(context.Background(), "cpbxa.example.test", "SRV", addr, false)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}

	// A direct-name SRV query (no service/proto label) must reach the wire
	// exactly as entered — no automatic "_sip._udp." prefix synthesized.
	if gotQName != "cpbxa.example.test." {
		t.Errorf("query name on the wire = %q, want %q (must not synthesize _sip._udp.)", gotQName, "cpbxa.example.test.")
	}

	if len(res.Records) != 2 {
		t.Fatalf("records = %+v, want 2", res.Records)
	}
	want := map[string]bool{
		"prio=2 peso=9 cpbx02.example.test:5060": false,
		"prio=1 peso=9 cpbx09.example.test:5060": false,
	}
	for _, rec := range res.Records {
		if _, ok := want[rec.Value]; !ok {
			t.Errorf("unexpected record value: %q", rec.Value)
			continue
		}
		want[rec.Value] = true
		if rec.Name != "cpbxa.example.test" {
			t.Errorf("record.Name = %q, want %q", rec.Name, "cpbxa.example.test")
		}
		if rec.Type != "SRV" {
			t.Errorf("record.Type = %q, want SRV", rec.Type)
		}
		if rec.TTL != 300 {
			t.Errorf("record.TTL = %d, want 300", rec.TTL)
		}
	}
	for v, seen := range want {
		if !seen {
			t.Errorf("expected record %q not found", v)
		}
	}
}

func TestQuerySRVMultipleRecordsStructuredFields(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "pbx.example.test. 100 IN SRV 4 9 5060 host05.example.test."))
		m.Answer = append(m.Answer, mustRR(t, "pbx.example.test. 100 IN SRV 1 9 5060 host09.example.test."))
		m.WriteTo(w)
	})

	res := Query(context.Background(), "pbx.example.test", "SRV", addr, false)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("records = %+v, want 2", res.Records)
	}

	byTarget := map[string]*SRVData{}
	for _, rec := range res.Records {
		if rec.SRV == nil {
			t.Fatalf("record %+v has nil SRV field", rec)
		}
		byTarget[rec.SRV.Target] = rec.SRV
	}

	h5, ok := byTarget["host05.example.test"]
	if !ok {
		t.Fatal("missing host05.example.test target")
	}
	if h5.Priority != 4 || h5.Weight != 9 || h5.Port != 5060 {
		t.Errorf("host05 SRV = %+v, want {Priority:4 Weight:9 Port:5060}", h5)
	}

	h9, ok := byTarget["host09.example.test"]
	if !ok {
		t.Fatal("missing host09.example.test target")
	}
	if h9.Priority != 1 || h9.Weight != 9 || h9.Port != 5060 {
		t.Errorf("host09 SRV = %+v, want {Priority:1 Weight:9 Port:5060}", h9)
	}
}

func TestResolveSRVTargets(t *testing.T) {
	var mu sync.Mutex
	queryCount := map[string]int{}
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := q.Header().Name
		mu.Lock()
		queryCount[name]++
		mu.Unlock()
		m := reply(r)
		switch name {
		case "host05.example.test.":
			switch dns.RRToType(q) {
			case dns.TypeA:
				m.Answer = append(m.Answer, mustRR(t, "host05.example.test. 300 IN A 203.0.113.5"))
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, mustRR(t, "host05.example.test. 300 IN AAAA 2001:db8::5"))
			}
		case "host09.example.test.":
			if dns.RRToType(q) == dns.TypeA {
				m.Answer = append(m.Answer, mustRR(t, "host09.example.test. 300 IN A 203.0.113.9"))
			}
			// AAAA: NODATA (no answer appended) — must not be an error.
		case "nohost.example.test.":
			m.Rcode = dns.RcodeNameError
		}
		m.WriteTo(w)
	})

	targets := []string{
		"host05.example.test",
		"host05.example.test.", // trailing dot + duplicate: must still dedupe to one entry
		"host09.example.test",
		"nohost.example.test",
	}
	results := ResolveSRVTargets(context.Background(), targets, addr)

	if len(results) != 3 {
		t.Fatalf("results = %+v, want 3 deduplicated targets", results)
	}
	byTarget := map[string]TargetResolution{}
	for _, r := range results {
		byTarget[r.Target] = r
	}

	h5 := byTarget["host05.example.test"]
	wantIPs := map[string]bool{"203.0.113.5": true, "2001:db8::5": true}
	if len(h5.IPs) != 2 {
		t.Fatalf("host05 IPs = %+v, want 2 (one A, one AAAA)", h5.IPs)
	}
	for _, ip := range h5.IPs {
		if !wantIPs[ip] {
			t.Errorf("unexpected IP for host05: %s", ip)
		}
	}
	if h5.Err != "" {
		t.Errorf("host05 resolved fine, want no Err, got %q", h5.Err)
	}

	h9 := byTarget["host09.example.test"]
	if len(h9.IPs) != 1 || h9.IPs[0] != "203.0.113.9" {
		t.Errorf("host09 IPs = %+v, want [203.0.113.9]", h9.IPs)
	}
	if h9.Err != "" {
		t.Errorf("host09 has an A record and only lacks AAAA (NODATA) — must not be treated as an error, got %q", h9.Err)
	}

	nohost := byTarget["nohost.example.test"]
	if len(nohost.IPs) != 0 {
		t.Errorf("nohost IPs = %+v, want none", nohost.IPs)
	}
	// A genuinely failing target (NXDOMAIN on both A and AAAA) is reported
	// on its own entry, not surfaced as a batch-level failure — the caller
	// already got results for host05/host09 above regardless.

	// Deduplication must mean exactly one A + one AAAA query per unique
	// target reached the resolver, never once per input-list occurrence.
	if queryCount["host05.example.test."] != 2 {
		t.Errorf("host05 received %d queries, want exactly 2 (A + AAAA, deduplicated)", queryCount["host05.example.test."])
	}
}

func TestResolveSRVTargetsExcludesCNAMEFromIPs(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		if dns.RRToType(r.Question[0]) == dns.TypeA {
			m.Answer = append(m.Answer, mustRR(t, "alias.example.test. 300 IN CNAME real.example.test."))
			m.Answer = append(m.Answer, mustRR(t, "real.example.test. 300 IN A 203.0.113.10"))
		}
		// AAAA: NODATA.
		m.WriteTo(w)
	})

	results := ResolveSRVTargets(context.Background(), []string{"alias.example.test"}, addr)
	if len(results) != 1 {
		t.Fatalf("results = %+v, want 1", results)
	}
	r := results[0]
	if len(r.IPs) != 1 || r.IPs[0] != "203.0.113.10" {
		t.Fatalf("IPs = %+v, want exactly [203.0.113.10] — the CNAME target must never appear here", r.IPs)
	}
}

func TestResolveSRVTargetsRespectsExternalDeadline(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "slow1.example.test. 300 IN A 203.0.113.1"))
		m.WriteTo(w)
	})

	// An already-expired parent context must make every query in the batch
	// fail fast via its own deadline, instead of falling back to the
	// internal 5s-per-query timeout — proving the batch honors a tighter
	// caller-supplied deadline rather than always waiting out its own.
	parent, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	start := time.Now()
	results := ResolveSRVTargets(parent, []string{"slow1.example.test", "slow2.example.test"}, addr)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("batch took %s, want it bounded by the already-expired external deadline, not the internal 5s per-query timeout", elapsed)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2 — both targets reported, none dropped, even though both failed", results)
	}
	for _, r := range results {
		if len(r.IPs) != 0 {
			t.Errorf("target %s: IPs = %+v, want none (deadline already expired)", r.Target, r.IPs)
		}
		if r.Err == "" {
			t.Errorf("target %s: want a non-empty Err once the deadline has expired", r.Target)
		}
	}
	if results[0].Target != "slow1.example.test" || results[1].Target != "slow2.example.test" {
		t.Errorf("order not preserved: %+v", results)
	}
}

func TestDiscoverSRVSIP(t *testing.T) {
	var queried []string
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		name := r.Question[0].Header().Name
		queried = append(queried, name)
		m := reply(r)
		if name == "_sip._udp.pbx.example.test." {
			m.Answer = append(m.Answer, mustRR(t, "_sip._udp.pbx.example.test. 300 IN SRV 1 9 5060 host1.example.test."))
			m.Answer = append(m.Answer, mustRR(t, "_sip._udp.pbx.example.test. 300 IN SRV 2 9 5060 host2.example.test."))
		}
		// _sip._tcp and _sips._tcp: NODATA (no answer appended).
		m.WriteTo(w)
	})

	candidates := DiscoverSRVSIP(context.Background(), "pbx.example.test", addr, false)

	if len(candidates) != 3 {
		t.Fatalf("candidates = %+v, want exactly 3", candidates)
	}
	wantNames := []string{
		"_sip._udp.pbx.example.test",
		"_sip._tcp.pbx.example.test",
		"_sips._tcp.pbx.example.test",
	}
	for i, want := range wantNames {
		if candidates[i].Name != want {
			t.Errorf("candidate[%d].Name = %q, want %q (deterministic order)", i, candidates[i].Name, want)
		}
		if !strings.HasSuffix(candidates[i].Name, "pbx.example.test") {
			t.Errorf("candidate[%d].Name = %q leaked into a parent domain", i, candidates[i].Name)
		}
	}

	udp := candidates[0].Result
	if udp.Err != "" {
		t.Fatalf("udp candidate error: %s", udp.Err)
	}
	if len(udp.Records) != 2 {
		t.Fatalf("udp records = %+v, want 2", udp.Records)
	}
	for _, rec := range udp.Records {
		if rec.SRV == nil {
			t.Errorf("udp record missing structured SRV data: %+v", rec)
		}
	}

	if len(candidates[1].Result.Records) != 0 {
		t.Errorf("tcp records = %+v, want none (NODATA)", candidates[1].Result.Records)
	}
	if len(candidates[2].Result.Records) != 0 {
		t.Errorf("sips records = %+v, want none (NODATA)", candidates[2].Result.Records)
	}

	// Every candidate must reach the SAME resolver the caller asked for,
	// never a different one, and exactly 3 queries total — no extras (e.g.
	// an accidental parent-domain lookup).
	if len(queried) != 3 {
		t.Fatalf("resolver received %d queries, want exactly 3", len(queried))
	}
	for _, name := range queried {
		if !strings.HasSuffix(name, "pbx.example.test.") {
			t.Errorf("unexpected query reached the resolver: %s", name)
		}
	}
}

func TestQueryDNSSECFlags(t *testing.T) {
	// Built on the test's own goroutine: t.Fatalf inside a server handler
	// goroutine only calls runtime.Goexit() on that goroutine, leaving the
	// handler silently hung instead of failing the test (a real pitfall, not
	// hypothetical — this is exactly what happened before this record was
	// precomputed here).
	aRR := mustRR(t, "example.test. 300 IN A 203.0.113.10")
	sigRR := mustRR(t, "example.test. 300 IN RRSIG A 8 2 300 20260901000000 20260801000000 12345 example.test. AAAA")

	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.AuthenticatedData = true
		m.Answer = append(m.Answer, aRR, sigRR)
		m.WriteTo(w)
	})

	res := Query(context.Background(), "example.test", "A", addr, true)
	if !res.DNSSEC.Requested {
		t.Error("Requested should be true when dnssec=true")
	}
	if !res.DNSSEC.Authenticated {
		t.Error("Authenticated should reflect the response's AD bit")
	}
	if !res.DNSSEC.HasRRSIG {
		t.Error("HasRRSIG should be true when an RRSIG is present in the answer")
	}
}

func TestQueryNXDOMAIN(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Rcode = dns.RcodeNameError
		m.WriteTo(w)
	})

	res := Query(context.Background(), "nope.test", "A", addr, false)
	if res.RCode != "NXDOMAIN" {
		t.Errorf("RCode = %s, want NXDOMAIN", res.RCode)
	}
	if len(res.Records) != 0 {
		t.Errorf("expected no records, got %+v", res.Records)
	}
}

func TestQueryUnsupportedType(t *testing.T) {
	res := Query(context.Background(), "example.test", "BOGUS", "127.0.0.1:0", false)
	if res.Err == "" {
		t.Error("expected an error for an unsupported record type")
	}
}

func TestQuerySystemRejectsSOA(t *testing.T) {
	res := Query(context.Background(), "example.test", "SOA", SystemResolverAddr, false)
	if res.Err == "" {
		t.Error("system resolver should reject SOA with an explicit error, not guess a server")
	}
}

func TestCompareDetectsDivergence(t *testing.T) {
	addrA := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "example.test. 300 IN A 203.0.113.10"))
		m.WriteTo(w)
	})
	addrB := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "example.test. 300 IN A 198.51.100.99"))
		m.WriteTo(w)
	})

	cmp := Compare(context.Background(), "example.test", "A", []Resolver{
		{Addr: addrA, Label: "A"}, {Addr: addrB, Label: "B"},
	}, false)

	if cmp.Consistent {
		t.Error("expected divergence between two resolvers returning different A records")
	}
	if len(cmp.Divergences) != 2 {
		t.Errorf("Divergences = %+v, want 2 entries", cmp.Divergences)
	}
}

func TestCompareConsistent(t *testing.T) {
	handler := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "example.test. 300 IN A 203.0.113.10"))
		m.WriteTo(w)
	}
	addrA := startFakeServer(t, handler)
	addrB := startFakeServer(t, handler)

	cmp := Compare(context.Background(), "example.test", "A", []Resolver{
		{Addr: addrA, Label: "A"}, {Addr: addrB, Label: "B"},
	}, false)

	if !cmp.Consistent {
		t.Errorf("expected consistency, got divergences: %+v", cmp.Divergences)
	}
}

// V1 hardening finding #4: Compare() only compared record value sets,
// never RCODE — so NXDOMAIN (no records) against NOERROR (also no
// records, e.g. a different type at that name) read as "consistent"
// purely because both answer-sets were empty. Diagnose Full trusts
// cmp.Consistent to decide whether to raise dns_divergence, so this
// silently hid a genuine split-horizon/hijack signal.
func TestCompareDetectsRCodeDivergence(t *testing.T) {
	addrA := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN, no records
		m.WriteTo(w)
	})
	addrB := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r) // NOERROR by default, also no records
		m.WriteTo(w)
	})

	cmp := Compare(context.Background(), "example.test", "A", []Resolver{
		{Addr: addrA, Label: "A"}, {Addr: addrB, Label: "B"},
	}, false)

	if cmp.Consistent {
		t.Error("Consistent = true, want false: NXDOMAIN and NOERROR are not the same answer even when both have zero records")
	}
	if len(cmp.Divergences) != 2 {
		t.Fatalf("Divergences = %+v, want 2 entries", cmp.Divergences)
	}
	joined := strings.Join(cmp.Divergences, " | ")
	if !strings.Contains(joined, "NXDOMAIN") {
		t.Errorf("Divergences = %q, want it to identify the NXDOMAIN RCODE", joined)
	}
	if !strings.Contains(joined, "NOERROR") {
		t.Errorf("Divergences = %q, want it to identify the NOERROR RCODE", joined)
	}
}

// A resolver-transport error stays outside the answer-set comparison, same
// as before this finding — only real, comparable DNS answers are compared
// against each other. Mirrors TestQueryTimeoutRespectsContext's own
// never-answers-but-listens + short-context pattern so this fails fast
// instead of waiting out queryRaw's 5s internal timeout.
func TestCompareIgnoresTransportErrorsInAnswerComparison(t *testing.T) {
	addrOK := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, "example.test. 300 IN A 203.0.113.10"))
		m.WriteTo(w)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	cmp := Compare(ctx, "example.test", "A", []Resolver{
		{Addr: addrOK, Label: "OK"}, {Addr: pc.LocalAddr().String(), Label: "Unreachable"},
	}, false)

	if !cmp.Consistent {
		t.Errorf("expected consistency (the unreachable resolver's error must not itself count as a divergence), got: %+v", cmp.Divergences)
	}
}

func TestReversePTR(t *testing.T) {
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := reply(r)
		if strings.Contains(r.Question[0].Header().Name, "10.113.0.203.in-addr.arpa") {
			m.Answer = append(m.Answer, mustRR(t, "10.113.0.203.in-addr.arpa. 300 IN PTR host.example.test."))
		}
		m.WriteTo(w)
	})

	res := ReversePTR(context.Background(), "203.0.113.10", addr, false)
	if len(res.Records) != 1 || res.Records[0].Value != "host.example.test" {
		t.Fatalf("PTR result = %+v", res.Records)
	}
}

func TestReversePTRIPv6ExplicitResolverBuildsArpa(t *testing.T) {
	var gotQName string
	addr := startFakeServer(t, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		gotQName = r.Question[0].Header().Name
		m := reply(r)
		m.Answer = append(m.Answer, mustRR(t, gotQName+" 300 IN PTR host6.example.test."))
		m.WriteTo(w)
	})

	res := ReversePTR(context.Background(), "2001:db8::1", addr, false)
	if len(res.Records) != 1 || res.Records[0].Value != "host6.example.test" {
		t.Fatalf("PTR result = %+v", res.Records)
	}
	wantSuffix := "ip6.arpa."
	if !strings.HasSuffix(gotQName, wantSuffix) {
		t.Errorf("query name = %q, want a name ending in %q", gotQName, wantSuffix)
	}
}

func TestReversePTRSystemReceivesRawIPNotArpa(t *testing.T) {
	var gotArg string
	old := lookupAddr
	lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		gotArg = addr
		return []string{"host.example.test."}, nil
	}
	t.Cleanup(func() { lookupAddr = old })

	res := ReversePTR(context.Background(), "1.1.1.1", SystemResolverAddr, false)
	if gotArg != "1.1.1.1" {
		t.Fatalf("lookupAddr received %q, want the raw IP %q (not an ARPA name)", gotArg, "1.1.1.1")
	}
	if len(res.Records) != 1 || res.Records[0].Value != "host.example.test" {
		t.Fatalf("PTR result = %+v", res.Records)
	}
	if res.Domain != "1.1.1.1" {
		t.Errorf("res.Domain = %q, want the raw IP", res.Domain)
	}
}

func TestReversePTRSystemPropagatesLookupError(t *testing.T) {
	old := lookupAddr
	lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		return nil, errors.New("lookup 1.2.3.4: no such host")
	}
	t.Cleanup(func() { lookupAddr = old })

	res := ReversePTR(context.Background(), "1.2.3.4", SystemResolverAddr, false)
	if res.Err == "" {
		t.Fatal("want a non-empty Err when the system resolver genuinely fails")
	}
	if len(res.Records) != 0 {
		t.Errorf("records = %+v, want none", res.Records)
	}
}

func TestQueryTimeoutRespectsContext(t *testing.T) {
	// A server that never answers should surface as an error, not hang.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res := Query(ctx, "example.test", "A", pc.LocalAddr().String(), false)
	if res.Err == "" {
		t.Error("expected a timeout error when the resolver never answers")
	}
}
