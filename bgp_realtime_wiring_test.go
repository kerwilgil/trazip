package main

import (
	"context"
	"testing"
)

// This file proves the *wiring* from App down to bgp.PrepareRealtimeSession
// and back — not the WebSocket/dial behavior itself, which is already
// exhaustively covered with a fake dialer in internal/bgp and
// internal/api (see internal/api/bgp_realtime_test.go, which injects
// bgp.PrepareRealtimeSessionWithDialer against a local fake server).
//
// App itself has no dialer-injection seam (production always goes through
// api.Service's default bgpRealtimeStart field, which is
// bgp.PrepareRealtimeSession — the real RIS Live dialer/URL), so a
// package-main test can only safely exercise the real, non-mocked
// App.BGPRealtimeStart/Stop path for inputs that structurally never
// attempt a WebSocket dial: an invalid resource or an ASN (both are
// rejected inside bgp.PrepareRealtimeSession's own resource-kind
// classification, BEFORE any session.Manager entry is even created,
// v1.2 Gate 5 P1-1 closure, §23.2 "realtime v1.2 solo soporta IP/prefix")
// — see capture_wiring_test.go's own comment for the same established
// principle of testing what doesn't need Wails/network rather than
// fabricating a mock for what does.
//
// "App.bridgeSession installed exactly once, strictly before Run()"
// (v1.2 Gate 5 P1-2 "bridge-before-run") is verified structurally by
// code inspection instead of by a test here: api.BGPRealtimeStart has
// exactly one bridge(sess) call site, unconditionally before its one
// rs.Run() call site, no loop, no recursion — and internal/api's own
// TestBGPRealtimeStart_BridgeSeam_ReceivesFirstEventBeforeRunEverPublishes
// / TestBGPRealtimeStart_BridgeInstalledExactlyOnce already exercise that
// exact seam with a real local WebSocket fake (bridgeSession itself still
// requires a real Wails runtime here — see capture_wiring_test.go's own
// comment). The human click-through that would exercise a real CONNECTED
// session's bridged events through the actual Wails runtime is explicitly
// deferred to Gate 7.

// TestBGPRealtimeStart_InvalidResource_WiredEndToEnd — v1.2 Gate 5 P1-1
// closure: a rejected Start must return a real error, never a fabricated
// State=FAILED session with err=nil (the contract this test used to
// freeze incorrectly). Also proves App.BGPRealtimeStop still correctly
// rejects a SessionID that was never created.
func TestBGPRealtimeStart_InvalidResource_WiredEndToEnd(t *testing.T) {
	app := NewApp()
	defer app.svc.Close()

	info, err := app.BGPRealtimeStart("not a valid resource!!")
	if err == nil {
		t.Fatal("err = nil, want a rejection for an invalid resource")
	}
	if info.SessionID != "" {
		t.Errorf("SessionID = %q, want empty — a rejected Start must never hand back a usable session", info.SessionID)
	}
	// No SessionID was ever generated for a rejected Start — an arbitrary
	// unknown ID must still be correctly rejected by Stop, proving
	// App.BGPRealtimeStop is wired through to api.BGPRealtimeStop, not a
	// stub.
	if err := app.BGPRealtimeStop("does-not-exist"); err == nil {
		t.Error("BGPRealtimeStop on an unknown session ID: err = nil, want an error")
	}
}

// TestBGPRealtimeStart_ASN_WiredEndToEnd — same P1-1 contract: ASN is out
// of scope for v1.2 realtime (§23.2), and a rejected Start must return an
// error, never a fabricated FAILED session.
func TestBGPRealtimeStart_ASN_WiredEndToEnd(t *testing.T) {
	app := NewApp()
	defer app.svc.Close()

	info, err := app.BGPRealtimeStart("AS13335")
	if err == nil {
		t.Fatal("err = nil, want a rejection — ASN is out of scope for v1.2 realtime")
	}
	if info.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", info.SessionID)
	}
}

func TestBGPRealtimeStop_EmptyID_WiredEndToEnd(t *testing.T) {
	app := NewApp()
	defer app.svc.Close()

	if err := app.BGPRealtimeStop(""); err == nil {
		t.Error("err = nil, want a rejection for an empty sessionID")
	}
}

func TestBGPRealtimeStop_UnknownID_NeverTouchesOtherSessions(t *testing.T) {
	app := NewApp()
	defer app.svc.Close()

	// A plain, unrelated session created through the SAME shared Manager
	// app.svc uses — BGPRealtimeStop must never be able to reach it.
	other := app.sessions.New(context.Background(), "some-other-module")
	if err := app.BGPRealtimeStop(other.ID); err == nil {
		t.Fatal("err = nil, want a rejection — this ID was never created by BGPRealtimeStart")
	}
	if _, ok := app.sessions.Get(other.ID); !ok {
		t.Error("a non-BGP session was cancelled by BGPRealtimeStop")
	}
}
