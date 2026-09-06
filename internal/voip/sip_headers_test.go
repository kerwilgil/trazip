package voip

import (
	"testing"

	"trazip/internal/protocol/sip"
)

func TestApplyPartyHeadersAssignsBySenderAddress(t *testing.T) {
	c := &Call{Caller: CallParty{Address: "10.0.0.1:5060"}, Callee: CallParty{Address: "10.0.0.2:5060"}}
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"user-agent": "PhoneA/1.0"}}, "10.0.0.1:5060")
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"server": "PBX-B/2.0"}}, "10.0.0.2:5060")

	if c.Caller.UserAgent != "PhoneA/1.0" {
		t.Errorf("Caller.UserAgent = %q", c.Caller.UserAgent)
	}
	if c.Callee.Server != "PBX-B/2.0" {
		t.Errorf("Callee.Server = %q", c.Callee.Server)
	}
	if c.Caller.Server != "" || c.Callee.UserAgent != "" {
		t.Errorf("headers must not leak to the party that didn't send them: %+v / %+v", c.Caller, c.Callee)
	}
}

// A second, different User-Agent value from the same address must never
// silently replace the first — "sin sobrescribir silenciosamente información
// contradictoria" is the explicit requirement this guards.
func TestApplyPartyHeadersNeverOverwritesWithAContradictoryValue(t *testing.T) {
	c := &Call{Caller: CallParty{Address: "10.0.0.1:5060"}}
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"user-agent": "PhoneA/1.0"}}, "10.0.0.1:5060")
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"user-agent": "SomethingElse/9.9"}}, "10.0.0.1:5060")

	if c.Caller.UserAgent != "PhoneA/1.0" {
		t.Errorf("Caller.UserAgent = %q, want the first value preserved, not overwritten", c.Caller.UserAgent)
	}
}

func TestApplyPartyHeadersIgnoresUnknownSender(t *testing.T) {
	c := &Call{Caller: CallParty{Address: "10.0.0.1:5060"}, Callee: CallParty{Address: "10.0.0.2:5060"}}
	// A message from a third address (e.g. a proxy/SBC leg) must not be
	// attributed to either party.
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"user-agent": "Proxy/1.0"}}, "10.0.0.9:5060")

	if c.Caller.UserAgent != "" || c.Callee.UserAgent != "" {
		t.Errorf("a message from an unrelated address must not be attributed: %+v / %+v", c.Caller, c.Callee)
	}
}

func TestApplyPartyHeadersNoOpBeforeAddressesAreKnown(t *testing.T) {
	c := &Call{} // Caller/Callee addresses not yet set (no INVITE seen)
	applyPartyHeaders(c, &sip.Message{Headers: map[string]string{"user-agent": "PhoneA/1.0"}}, "10.0.0.1:5060")
	if c.Caller.UserAgent != "" {
		t.Errorf("must not attribute a header before Caller/Callee addresses are established: %+v", c.Caller)
	}
}
