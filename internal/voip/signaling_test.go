package voip

import (
	"fmt"
	"testing"
	"time"

	"trazip/internal/protocol/sip"
)

// These tests drive the real correlation pipeline (handleSIP + finalize)
// with directly-constructed sip.Message values rather than raw bytes or a
// synthetic PCAP — sip.Message is already a plain exported struct, so this
// exercises the actual retransmission detection (same top Via branch = same
// hop) and Established/FailureCode bookkeeping buildSignalingPath and
// FailureOrigin depend on, without the overhead of byte-level SIP/PCAP
// fixtures for logic that's fundamentally about Call-ID/Via/CSeq state.

func addr(ip string, port uint16) string { return fmt.Sprintf("%s:%d", ip, port) }

func inviteMsg(callID, via string, cseq int, headers map[string]string) *sip.Message {
	return &sip.Message{IsRequest: true, Method: "INVITE", CallID: callID, CSeqNum: cseq, CSeqMethod: "INVITE", ViaBranch: via, Headers: headers}
}

func respMsg(callID, via string, cseq, code int, reason string, headers map[string]string) *sip.Message {
	return &sip.Message{IsRequest: false, StatusCode: code, Reason: reason, CallID: callID, CSeqNum: cseq, CSeqMethod: "INVITE", ViaBranch: via, Headers: headers}
}

func ackMsg(callID, via string, cseq int) *sip.Message {
	return &sip.Message{IsRequest: true, Method: "ACK", CallID: callID, CSeqNum: cseq, CSeqMethod: "ACK", ViaBranch: via}
}

// signalingScenario is a small builder so each test reads as "who sent what,
// from where, to where, when" instead of repeating handleSIP's full
// six-argument signature at every step.
type signalingScenario struct {
	calls   map[string]*Call
	callID  string
	base    time.Time
	elapsed time.Duration
}

func newScenario(callID string) *signalingScenario {
	return &signalingScenario{calls: map[string]*Call{}, callID: callID, base: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (s *signalingScenario) send(msg *sip.Message, srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
	msg.CallID = s.callID
	s.elapsed += 10 * time.Millisecond
	handleSIP(s.calls, msg, s.base.Add(s.elapsed), srcIP, srcPort, dstIP, dstPort)
}

func (s *signalingScenario) finalize() Call {
	res := finalize(s.calls, nil)
	if len(res.Calls) != 1 {
		panic(fmt.Sprintf("scenario produced %d calls, want exactly 1", len(res.Calls)))
	}
	return res.Calls[0]
}

const (
	aIP, aPort = "198.51.100.11", uint16(5060)
	bIP, bPort = "198.51.100.12", uint16(5060)
	cIP, cPort = "198.51.100.13", uint16(5060)
	dIP, dPort = "198.51.100.14", uint16(5060)
)

var aAddr, bAddr, cAddr, dAddr = addr(aIP, aPort), addr(bIP, bPort), addr(cIP, cPort), addr(dIP, dPort)

func assertPath(t *testing.T, got []SignalingHop, wantAddrs []string, wantRoles []SignalingRole) {
	t.Helper()
	if len(got) != len(wantAddrs) {
		t.Fatalf("SignalingPath has %d hops, want %d: %+v", len(got), len(wantAddrs), got)
	}
	for i, h := range got {
		if h.Address != wantAddrs[i] {
			t.Errorf("hop %d address = %q, want %q", i, h.Address, wantAddrs[i])
		}
		if h.Role != wantRoles[i] {
			t.Errorf("hop %d (%s) role = %q, want %q", i, h.Address, h.Role, wantRoles[i])
		}
	}
}

// A. Direct call: A -> B INVITE, B -> A 200 OK.
func TestSignalingPathDirectCall(t *testing.T) {
	s := newScenario("call-a")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath, []string{aAddr, bAddr}, []SignalingRole{SignalingRoleOrigin, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true for an unambiguous direct call")
	}
}

// B. One intermediary: A -> B -> C, established back through B to A.
func TestSignalingPathOneIntermediary(t *testing.T) {
	s := newScenario("call-b")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 200, "OK", nil), cIP, cPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, cAddr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true")
	}
}

// C. Failed call through one intermediary — mirrors the real 603 Decline
// fixture this feature was built for: the intermediary (B) relays a
// rejection that actually originated at the destination (C), and each hop's
// own User-Agent/Server must be attributed to the address that actually
// sent it, never smeared across the whole call. B's forward carries the
// SAME Server header C sent (a real proxy relays it byte-for-byte) — this
// is the exact shape that used to misattribute VitalPBX to B too before
// V1 hardening finding #2's provenance fix (a nil-headers forward, as this
// fixture used before, could never have caught that bug: it never gave B a
// duplicate header to misattribute in the first place).
func TestSignalingPathFailedOneIntermediary(t *testing.T) {
	s := newScenario("call-c")
	s.send(inviteMsg(s.callID, "z1", 1, map[string]string{"user-agent": "Vozelia MS 2.0"}), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 603, "Decline", map[string]string{"server": "VitalPBX"}), cIP, cPort, bIP, bPort)
	s.send(ackMsg(s.callID, "z2", 1), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z1", 1, 603, "Decline", map[string]string{"server": "VitalPBX"}), bIP, bPort, aIP, aPort)
	s.send(ackMsg(s.callID, "z1", 1), aIP, aPort, bIP, bPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, cAddr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true")
	}
	if call.FailureCode != 603 {
		t.Fatalf("FailureCode = %d, want 603", call.FailureCode)
	}
	if call.FailureOrigin != cAddr {
		t.Errorf("FailureOrigin = %q, want %q (C actually originated the 603, B only relayed it)", call.FailureOrigin, cAddr)
	}
	if call.SignalingPath[0].UserAgent != "Vozelia MS 2.0" {
		t.Errorf("origin UserAgent = %q, want the one A itself sent", call.SignalingPath[0].UserAgent)
	}
	if call.SignalingPath[2].Server != "VitalPBX" {
		t.Errorf("destination Server = %q, want the one C itself sent", call.SignalingPath[2].Server)
	}
	if call.SignalingPath[1].UserAgent != "" || call.SignalingPath[1].Server != "" {
		t.Errorf("intermediary should have no UA/Server evidence in this scenario, got %+v", call.SignalingPath[1])
	}
}

// C.1. Forwarded request: A's User-Agent, relayed unchanged by the proxy on
// its own copy of the INVITE, must be attributed only to A (V1 hardening
// finding #2, test 1).
func TestSignalingPathForwardedRequestHeaderNotAttributedToProxy(t *testing.T) {
	s := newScenario("call-fwd-req")
	s.send(inviteMsg(s.callID, "z1", 1, map[string]string{"user-agent": "Vozelia"}), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, map[string]string{"user-agent": "Vozelia"}), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 200, "OK", nil), cIP, cPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, cAddr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleDestination})
	if call.SignalingPath[0].UserAgent != "Vozelia" {
		t.Errorf("origin UserAgent = %q, want Vozelia", call.SignalingPath[0].UserAgent)
	}
	if call.SignalingPath[1].UserAgent != "" {
		t.Errorf("proxy UserAgent = %q, want empty — it only forwarded A's unchanged header", call.SignalingPath[1].UserAgent)
	}
}

// C.2. Forwarded response: C's Server, relayed unchanged by the proxy on
// its own copy of the 200 OK, must be attributed only to C (V1 hardening
// finding #2, test 2).
func TestSignalingPathForwardedResponseHeaderNotAttributedToProxy(t *testing.T) {
	s := newScenario("call-fwd-resp")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 200, "OK", map[string]string{"server": "VitalPBX"}), cIP, cPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", map[string]string{"server": "VitalPBX"}), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, cAddr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleDestination})
	if call.SignalingPath[2].Server != "VitalPBX" {
		t.Errorf("destination Server = %q, want VitalPBX", call.SignalingPath[2].Server)
	}
	if call.SignalingPath[1].Server != "" {
		t.Errorf("proxy Server = %q, want empty — it only forwarded C's unchanged header", call.SignalingPath[1].Server)
	}
}

// C.3. An intermediary that REWRITES the header to a distinct value of its
// own is genuinely new evidence and must remain attributable to it (V1
// hardening finding #2, test 4).
func TestSignalingPathIntermediaryDistinctHeaderValueIsAttributable(t *testing.T) {
	s := newScenario("call-distinct")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 603, "Decline", map[string]string{"server": "VitalPBX"}), cIP, cPort, bIP, bPort)
	s.send(ackMsg(s.callID, "z2", 1), bIP, bPort, cIP, cPort)
	// B rewrites the Server header to its own product before relaying — a
	// distinct value, which IS attributable evidence of B itself.
	s.send(respMsg(s.callID, "z1", 1, 603, "Decline", map[string]string{"server": "SomeSBC"}), bIP, bPort, aIP, aPort)
	s.send(ackMsg(s.callID, "z1", 1), aIP, aPort, bIP, bPort)
	call := s.finalize()

	if call.SignalingPath[2].Server != "VitalPBX" {
		t.Errorf("destination Server = %q, want VitalPBX", call.SignalingPath[2].Server)
	}
	if call.SignalingPath[1].Server != "SomeSBC" {
		t.Errorf("intermediary Server = %q, want SomeSBC — a distinct value it introduced itself", call.SignalingPath[1].Server)
	}
}

// C.4. Retransmitting the proxy's own forward of an unchanged header must
// not eventually grant it attribution (V1 hardening finding #2, test 5).
func TestSignalingPathRetransmissionsDoNotCreateNewAttribution(t *testing.T) {
	s := newScenario("call-retx")
	s.send(inviteMsg(s.callID, "z1", 1, map[string]string{"user-agent": "Vozelia"}), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, map[string]string{"user-agent": "Vozelia"}), bIP, bPort, cIP, cPort)
	// B retransmits its own forward of the INVITE (same ViaBranch z2, no
	// response/ACK yet) — must not change attribution.
	s.send(inviteMsg(s.callID, "z2", 1, map[string]string{"user-agent": "Vozelia"}), bIP, bPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 200, "OK", nil), cIP, cPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	if call.SignalingPath[0].UserAgent != "Vozelia" {
		t.Errorf("origin UserAgent = %q, want Vozelia", call.SignalingPath[0].UserAgent)
	}
	if call.SignalingPath[1].UserAgent != "" {
		t.Errorf("proxy UserAgent = %q, want empty even after retransmitting its own forward", call.SignalingPath[1].UserAgent)
	}
}

// D. Two intermediaries: A -> B -> C -> D.
func TestSignalingPathTwoIntermediaries(t *testing.T) {
	s := newScenario("call-d")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, cIP, cPort)
	s.send(inviteMsg(s.callID, "z3", 1, nil), cIP, cPort, dIP, dPort)
	s.send(respMsg(s.callID, "z3", 1, 200, "OK", nil), dIP, dPort, cIP, cPort)
	s.send(respMsg(s.callID, "z2", 1, 200, "OK", nil), cIP, cPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, cAddr, dAddr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleIntermediary, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true")
	}
}

// E. A retransmitted INVITE (same top Via branch — a real retransmission,
// not a proxy hop) must not create a duplicate/extra hop.
func TestSignalingPathIgnoresRetransmissions(t *testing.T) {
	s := newScenario("call-e")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort) // same branch/CSeq -> retransmission
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	if call.Retransmissions != 1 {
		t.Fatalf("Retransmissions = %d, want 1 (sanity check that the resend was actually recognized as one)", call.Retransmissions)
	}
	assertPath(t, call.SignalingPath, []string{aAddr, bAddr}, []SignalingRole{SignalingRoleOrigin, SignalingRoleDestination})
}

// F. Provisional/final response traffic (100/180/200) must never alter the
// forward path derived from INVITE evidence alone.
func TestSignalingPathIgnoresResponseTraffic(t *testing.T) {
	s := newScenario("call-f")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 100, "Trying", nil), bIP, bPort, aIP, aPort)
	s.send(respMsg(s.callID, "z1", 1, 180, "Ringing", nil), bIP, bPort, aIP, aPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath, []string{aAddr, bAddr}, []SignalingRole{SignalingRoleOrigin, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true")
	}
}

// G. A capture that starts mid-dialog (no INVITE ever observed) must not
// invent a topology — Caller/Callee already stay empty in this case, and
// SignalingPath must too.
func TestSignalingPathMidDialogCaptureDegradesHonestly(t *testing.T) {
	s := newScenario("call-g")
	s.send(respMsg(s.callID, "z1", 1, 180, "Ringing", nil), bIP, bPort, aIP, aPort)
	s.send(respMsg(s.callID, "z1", 1, 200, "OK", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	if call.Caller.Address != "" {
		t.Fatalf("Caller.Address = %q, want empty for a mid-dialog capture (sanity check)", call.Caller.Address)
	}
	if call.SignalingPath != nil {
		t.Errorf("SignalingPath = %+v, want nil — no INVITE evidence to build any path from", call.SignalingPath)
	}
	if call.SignalingPathComplete {
		t.Error("SignalingPathComplete = true, want false with no path at all")
	}
}

// H. A genuine SIP fork (B tries two different next hops, C1 and C2) with no
// response tying the outcome to either branch must not assert a false
// linear destination — the path stops at the fork, incomplete.
func TestSignalingPathForkWithoutResolutionStaysIncomplete(t *testing.T) {
	c1IP, c1Port := "198.51.100.21", uint16(5060)
	c2IP, c2Port := "198.51.100.22", uint16(5060)

	s := newScenario("call-h")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, c1IP, c1Port)
	s.send(inviteMsg(s.callID, "z3", 1, nil), bIP, bPort, c2IP, c2Port)
	call := s.finalize()

	assertPath(t, call.SignalingPath, []string{aAddr, bAddr}, []SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary})
	if call.SignalingPathComplete {
		t.Error("SignalingPathComplete = true, want false: B forked to two branches with no evidence of which one is real")
	}
	// Neither fork branch may appear at all — showing one over the other
	// without evidence would be exactly the false claim this guards against.
	for _, h := range call.SignalingPath {
		if h.Address == addr(c1IP, c1Port) || h.Address == addr(c2IP, c2Port) {
			t.Errorf("unresolved fork branch %q leaked into SignalingPath: %+v", h.Address, call.SignalingPath)
		}
	}
}

// H2. Same fork as H, but one branch (C2) actually produces the call's final
// response (603 Decline) — the fork IS resolvable here, and TRAZIP should
// prefer that branch rather than degrading unnecessarily (§6's "path
// principal determinado por la rama que produce la respuesta final").
func TestSignalingPathForkResolvedByFailureOrigin(t *testing.T) {
	c1IP, c1Port := "198.51.100.21", uint16(5060)
	c2IP, c2Port := "198.51.100.22", uint16(5060)
	c2Addr := addr(c2IP, c2Port)

	s := newScenario("call-h2")
	s.send(inviteMsg(s.callID, "z1", 1, nil), aIP, aPort, bIP, bPort)
	s.send(inviteMsg(s.callID, "z2", 1, nil), bIP, bPort, c1IP, c1Port)
	s.send(inviteMsg(s.callID, "z3", 1, nil), bIP, bPort, c2IP, c2Port)
	s.send(respMsg(s.callID, "z3", 1, 603, "Decline", nil), c2IP, c2Port, bIP, bPort)
	s.send(respMsg(s.callID, "z1", 1, 603, "Decline", nil), bIP, bPort, aIP, aPort)
	call := s.finalize()

	assertPath(t, call.SignalingPath,
		[]string{aAddr, bAddr, c2Addr},
		[]SignalingRole{SignalingRoleOrigin, SignalingRoleIntermediary, SignalingRoleDestination})
	if !call.SignalingPathComplete {
		t.Error("SignalingPathComplete = false, want true: the branch that produced the final response is known")
	}
	if call.FailureOrigin != c2Addr {
		t.Errorf("FailureOrigin = %q, want %q", call.FailureOrigin, c2Addr)
	}
}
