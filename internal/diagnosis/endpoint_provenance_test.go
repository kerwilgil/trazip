package diagnosis

import (
	"net/netip"
	"strings"
	"testing"
)

// These tests drive applyResolvedAddresses/multiAddressLimitation directly
// with hand-built address lists — deterministic, no live DNS lookup — for
// Phase B.1 fix #3: a report with several resolved addresses must never
// imply every stage examined all of them.

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// 1. Single A record: ResolvedAddresses has exactly one entry, no
// multi-address limitation.
func TestApplyResolvedAddressesSingleA(t *testing.T) {
	var report DiagnosticReport
	ip, haveIP := applyResolvedAddresses(&report, resolvedTarget{kind: "host", host: "example.com"}, addrs("93.184.216.34"))
	if !haveIP || ip.String() != "93.184.216.34" {
		t.Fatalf("ip=%v haveIP=%v, want 93.184.216.34/true", ip, haveIP)
	}
	if len(report.ResolvedAddresses) != 1 || report.ResolvedAddresses[0] != "93.184.216.34" {
		t.Errorf("ResolvedAddresses = %v, want [93.184.216.34]", report.ResolvedAddresses)
	}
	if report.PrimaryAddress != "93.184.216.34" {
		t.Errorf("PrimaryAddress = %q, want 93.184.216.34", report.PrimaryAddress)
	}
	if _, ok := multiAddressLimitation(report); ok {
		t.Error("a single resolved address must not produce a multi-address limitation")
	}
}

// 2. Multiple A records: PrimaryAddress is the first, ResolvedAddresses has
// all of them, and the multi-address limitation fires naming the actual
// count and the probed address — never claiming all were tested.
func TestApplyResolvedAddressesMultipleA(t *testing.T) {
	var report DiagnosticReport
	ip, haveIP := applyResolvedAddresses(&report, resolvedTarget{kind: "host", host: "example.com"}, addrs("203.0.113.1", "203.0.113.2", "203.0.113.3"))
	if !haveIP || ip.String() != "203.0.113.1" {
		t.Fatalf("ip=%v haveIP=%v, want 203.0.113.1/true (the first resolved address)", ip, haveIP)
	}
	if len(report.ResolvedAddresses) != 3 {
		t.Fatalf("ResolvedAddresses = %v, want 3 entries", report.ResolvedAddresses)
	}
	report.PrimaryAddress = ip.String()
	l, ok := multiAddressLimitation(report)
	if !ok {
		t.Fatal("expected a multi-address limitation when more than one address resolved")
	}
	if !strings.Contains(l, "203.0.113.1") || !strings.Contains(l, "3 direcciones") {
		t.Errorf("limitation = %q, want it to name the probed address and the total count", l)
	}
	if strings.Contains(l, "203.0.113.2") || strings.Contains(l, "203.0.113.3") {
		t.Errorf("limitation must not claim the OTHER addresses were also tested: %q", l)
	}
}

// 3. A + AAAA mixed: the primary address is still simply the first entry
// resolveHost returned, regardless of family, and every family appears in
// ResolvedAddresses.
func TestApplyResolvedAddressesAPlusAAAA(t *testing.T) {
	var report DiagnosticReport
	ip, haveIP := applyResolvedAddresses(&report, resolvedTarget{kind: "host", host: "example.com"}, addrs("192.0.2.10", "2001:db8::1"))
	if !haveIP || ip.String() != "192.0.2.10" {
		t.Fatalf("ip=%v haveIP=%v, want the first entry 192.0.2.10", ip, haveIP)
	}
	if len(report.ResolvedAddresses) != 2 || report.ResolvedAddresses[1] != "2001:db8::1" {
		t.Errorf("ResolvedAddresses = %v, want both the A and AAAA records", report.ResolvedAddresses)
	}
}

// 4. Direct IP target: ResolvedAddresses is just that one address, no DNS
// involved, no multi-address limitation.
func TestApplyResolvedAddressesDirectIP(t *testing.T) {
	var report DiagnosticReport
	rt := resolvedTarget{kind: "ip", host: "8.8.8.8", isDirect: true, directIP: netip.MustParseAddr("8.8.8.8")}
	ip, haveIP := applyResolvedAddresses(&report, rt, nil)
	if !haveIP || ip.String() != "8.8.8.8" {
		t.Fatalf("ip=%v haveIP=%v, want 8.8.8.8/true", ip, haveIP)
	}
	if len(report.ResolvedAddresses) != 1 || report.ResolvedAddresses[0] != "8.8.8.8" {
		t.Errorf("ResolvedAddresses = %v, want just [8.8.8.8]", report.ResolvedAddresses)
	}
	if _, ok := multiAddressLimitation(report); ok {
		t.Error("a direct-IP target must not produce a multi-address limitation")
	}
}

// 5. Hostname where only the primary IP is probed: each IP-bound stage's
// own Subjects must name PrimaryAddress, never the full ResolvedAddresses
// set — checked here via the actual stage runners against a report that
// resolved to multiple addresses but only carries the primary one forward.
func TestHostnameOnlyPrimaryIPIsProbed(t *testing.T) {
	var report DiagnosticReport
	ip, haveIP := applyResolvedAddresses(&report, resolvedTarget{kind: "host", host: "example.com"}, addrs("198.51.100.7", "198.51.100.8"))
	if !haveIP {
		t.Fatal("expected an IP to probe")
	}
	reach := runReachability(nil, false, netip.Addr{}, ModeOffline) // offline: no live probe, just checking Subjects wiring below
	if reach.Status != StageSkipped {
		t.Fatalf("sanity check failed: %+v", reach)
	}
	// A stage that DID run (e.g. reputation, which is offline-safe) must
	// name exactly the primary address, never every resolved one.
	rep := runReputation(Dependencies{}, haveIP, ip)
	if len(rep.Subjects) != 1 || rep.Subjects[0] != report.PrimaryAddress {
		t.Errorf("Reputation Subjects = %v, want exactly [%s] (the primary address), not the full resolved set", rep.Subjects, report.PrimaryAddress)
	}
	if rep.Subjects[0] == "198.51.100.8" {
		t.Error("stage subjects must never silently pick a non-primary resolved address")
	}
}
