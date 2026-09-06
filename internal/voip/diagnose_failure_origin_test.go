package voip

import (
	"strings"
	"testing"

	"trazip/internal/model"
)

// These tests cover Diagnose's use of Call.FailureOrigin/SignalingPath for a
// failed call's conclusion (prompt maestro TRAZIP V1 §Phase A) — the address
// that actually sent the final SIP response, which can differ from Callee
// when a proxy/SBC/carrier relayed it. Organization enrichment is set
// directly on the fixtures here (rather than routed through a real GeoIP
// engine) because Diagnose itself never queries GeoIP — it only reads
// whatever Caller/Callee/SignalingPath already carry, exactly like
// partyOrganization already did for RTP evidence.

func findEvidence(evidence []model.Evidence, typ string) (model.Evidence, bool) {
	for _, e := range evidence {
		if e.Type == typ {
			return e, true
		}
	}
	return model.Evidence{}, false
}

// A. Direct failure: no intermediary, Callee itself is FailureOrigin.
func TestDiagnoseFailureOriginDirectFailure(t *testing.T) {
	c := Call{
		FailureCode: 486, FailureReason: "Busy Here",
		FailureOrigin: bAddr,
		Callee:        CallParty{Address: bAddr},
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: bAddr, Role: SignalingRoleDestination},
		},
		SignalingPathComplete: true,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en "+ipOf(bAddr)) {
		t.Errorf("Conclusion should attribute the failure to %s: %q", ipOf(bAddr), d.Conclusion)
	}
	ev, ok := findEvidence(d.Evidence, "sip_failure_origin")
	if !ok {
		t.Fatal("expected a sip_failure_origin evidence entry")
	}
	if ev.Value != bAddr {
		t.Errorf("sip_failure_origin evidence Value = %q, want %q", ev.Value, bAddr)
	}
}

// B. One proxy relays a rejection that actually originated at the
// destination — the exact 603 Decline fixture this feature was built for.
// The destination's real organization must be quoted, not the proxy's.
func TestDiagnoseFailureOriginOneProxy(t *testing.T) {
	c := Call{
		FailureCode: 603, FailureReason: "Decline",
		FailureOrigin: cAddr, // C actually originated it; B only relayed it
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: bAddr, Role: SignalingRoleIntermediary, Organization: "Proxy Networks", ASN: 111},
			{Address: cAddr, Role: SignalingRoleDestination, Organization: "The Constant Company", ASN: 20473},
		},
		SignalingPathComplete: true,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en "+ipOf(cAddr)) {
		t.Errorf("Conclusion should name the true origin %s, not the relaying proxy: %q", ipOf(cAddr), d.Conclusion)
	}
	if !strings.Contains(d.Conclusion, "AS20473 The Constant Company") {
		t.Errorf("Conclusion should quote the destination's own AS/org: %q", d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "Proxy Networks") {
		t.Errorf("Conclusion must not quote the intermediary's organization instead of the origin's: %q", d.Conclusion)
	}
}

// C. Multiple intermediaries — FailureOrigin still resolves to the last hop
// in the chain, not any of the relaying proxies in between.
func TestDiagnoseFailureOriginMultipleIntermediaries(t *testing.T) {
	c := Call{
		FailureCode: 480, FailureReason: "Temporarily Unavailable",
		FailureOrigin: dAddr,
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: bAddr, Role: SignalingRoleIntermediary},
			{Address: cAddr, Role: SignalingRoleIntermediary},
			{Address: dAddr, Role: SignalingRoleDestination, Organization: "Destino Telecom", ASN: 999},
		},
		SignalingPathComplete: true,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en "+ipOf(dAddr)) {
		t.Errorf("Conclusion should attribute the failure to the final hop %s: %q", ipOf(dAddr), d.Conclusion)
	}
	if !strings.Contains(d.Conclusion, "Destino Telecom") {
		t.Errorf("Conclusion should quote the final hop's organization: %q", d.Conclusion)
	}
}

// D. Fork unresolved: SignalingPath stops at the fork (SignalingPathComplete
// = false) but FailureOrigin — established independently from the call's own
// outcome, not from the path chain — must still drive the conclusion.
func TestDiagnoseFailureOriginForkUnresolved(t *testing.T) {
	c := Call{
		FailureCode: 486, FailureReason: "Busy Here",
		FailureOrigin: cAddr,
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: bAddr, Role: SignalingRoleIntermediary}, // fork stops here; C never made it into the path
		},
		SignalingPathComplete: false,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en "+ipOf(cAddr)) {
		t.Errorf("Conclusion should still attribute the failure to %s even though the signaling path fork was unresolved: %q", ipOf(cAddr), d.Conclusion)
	}
	// C isn't in SignalingPath here, so no organization could possibly be
	// found for it — the conclusion must show the bare address, never a
	// fabricated one.
	if strings.Contains(d.Conclusion, "(AS") {
		t.Errorf("Conclusion must not invent an organization for an address absent from SignalingPath: %q", d.Conclusion)
	}
}

// E. FailureCode is set but FailureOrigin could not be established — the
// conclusion must fall back to the pre-existing wording, with no "originado
// en" clause and no sip_failure_origin evidence.
func TestDiagnoseFailureOriginAbsent(t *testing.T) {
	c := Call{FailureCode: 500, FailureReason: "Server Internal Error"}
	d := Diagnose(c)
	if strings.Contains(d.Conclusion, "originado en") {
		t.Errorf("Conclusion must not claim an origin when FailureOrigin is empty: %q", d.Conclusion)
	}
	if _, ok := findEvidence(d.Evidence, "sip_failure_origin"); ok {
		t.Error("expected no sip_failure_origin evidence when FailureOrigin is empty")
	}
}

// F. FailureOrigin is a private address — no GeoIP/ASN organization can ever
// exist for it, so the conclusion must name the bare address and never a
// fabricated organization.
func TestDiagnoseFailureOriginPrivateIP(t *testing.T) {
	privateAddr := "192.168.1.50:5060"
	c := Call{
		FailureCode: 486, FailureReason: "Busy Here",
		FailureOrigin: privateAddr,
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: privateAddr, Role: SignalingRoleDestination}, // no Organization: private addresses never get one
		},
		SignalingPathComplete: true,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en 192.168.1.50") {
		t.Errorf("Conclusion should name the private address itself: %q", d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "(AS") {
		t.Errorf("Conclusion must not show an organization for a private address: %q", d.Conclusion)
	}
}

// G. FailureOrigin is a public address, but nothing in Caller/Callee/
// SignalingPath carries an Organization for it — the same "no dataset
// loaded" degrade enrichHop/enrichParty already apply upstream (geo.go).
// Distinct scenario from the private-IP case above (a real dataset gap, not
// an address that can never be enriched) even though Diagnose's own
// behavior for both is identical: show the bare address, invent nothing.
func TestDiagnoseFailureOriginGeoUnavailable(t *testing.T) {
	c := Call{
		FailureCode: 603, FailureReason: "Decline",
		FailureOrigin: cAddr,
		SignalingPath: []SignalingHop{
			{Address: aAddr, Role: SignalingRoleOrigin},
			{Address: cAddr, Role: SignalingRoleDestination}, // Organization empty: no GeoIP dataset loaded
		},
		SignalingPathComplete: true,
	}
	d := Diagnose(c)
	if !strings.Contains(d.Conclusion, "originado en "+ipOf(cAddr)) {
		t.Errorf("Conclusion should name %s even without enrichment: %q", ipOf(cAddr), d.Conclusion)
	}
	if strings.Contains(d.Conclusion, "(AS") {
		t.Errorf("Conclusion must not show an organization when none was resolved: %q", d.Conclusion)
	}
}
