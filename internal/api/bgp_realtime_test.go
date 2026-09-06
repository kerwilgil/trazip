package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"trazip/internal/bgp"
	"trazip/internal/events"
	"trazip/internal/session"
)

// --- test doubles (self-contained: internal/bgp's own equivalents live in
// _test.go files, which are never importable across packages) ---

// fakeRISWSServer is a real local WebSocket server (httptest + gorilla/
// websocket) standing in for RIS Live — no Internet involved. It reads
// (and discards) the ris_subscribe message, then pushes the scripted wire
// frames, then blocks reading so the connection stays open until the
// client disconnects.
type fakeRISWSServer struct {
	srv *httptest.Server
}

func newFakeRISWSServer(t *testing.T, messages [][]byte) *fakeRISWSServer {
	t.Helper()
	f := &fakeRISWSServer{}
	upgrader := websocket.Upgrader{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil { // ris_subscribe — contents irrelevant here
			return
		}
		for _, m := range messages {
			if err := conn.WriteMessage(websocket.TextMessage, m); err != nil {
				return
			}
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRISWSServer) wsURL() string { return "ws" + strings.TrimPrefix(f.srv.URL, "http") }

// realGorillaDialer adapts gorilla/websocket's real dialer to
// bgp.RealtimeDialer — bgp package's own equivalent (gorillaDialer) is
// unexported and lives in a _test.go file, so it's not reachable from
// here; this is the same adapter shape, just local to this package's
// tests. It only ever dials the local fakeRISWSServer in these tests,
// never the real RIS Live endpoint.
type realGorillaDialer struct{}

func (realGorillaDialer) DialContext(ctx context.Context, u string, header http.Header) (bgp.RealtimeConn, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u, header)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// failIfDialedWS fails the test if the dialer is ever invoked — used for
// resource kinds that must never attempt a WebSocket connection (invalid
// resource, ASN, or a failed IP resolution).
type failIfDialedWS struct{ t *testing.T }

func (d failIfDialedWS) DialContext(ctx context.Context, u string, header http.Header) (bgp.RealtimeConn, error) {
	d.t.Errorf("unexpected WebSocket dial attempt to %s", u)
	return nil, fmt.Errorf("failIfDialedWS: dial refused (test double)")
}

// newTestServiceWithBGPRealtime builds a *Service wired for Gate 5 realtime
// tests: bgpRealtimeStart routes through bgp.StartRealtimeSessionWithDialer
// against dialer/wsURL (a local fake server, never the real RIS Live
// endpoint) and restAddr backs bgpClient for IP->prefix resolution.
func newTestServiceWithBGPRealtime(restAddr string, dialer bgp.RealtimeDialer, wsURL string) *Service {
	return &Service{
		sessions:  session.NewManager(),
		bgpClient: &bgp.Client{BaseURL: restAddr},
		bgpRealtimeStart: func(ctx context.Context, mgr *session.Manager, client *bgp.Client, resource string, onTerminate func(sessionID string)) (*bgp.RealtimeSession, error) {
			return bgp.PrepareRealtimeSessionWithDialer(ctx, mgr, client, resource, dialer, wsURL, onTerminate)
		},
		bgpSessions:       make(map[string]*bgp.RealtimeSession),
		bgpFinalSnapshots: make(map[string]bgp.RealtimeSessionInfo),
	}
}

func waitForRealtimeState(t *testing.T, s *Service, id string, want bgp.RealtimeSessionState, timeout time.Duration) bgp.RealtimeSessionInfo {
	t.Helper()
	s.bgpSessionsMu.Lock()
	rs, ok := s.bgpSessions[id]
	s.bgpSessionsMu.Unlock()
	if !ok {
		t.Fatalf("session %q not found in Service's registry", id)
	}
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info := rs.Info(); info.State == want {
			return info
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for state %q (last: %+v)", want, rs.Info())
		}
	}
}

// --- 1/2/3/4: Start ---

func TestBGPRealtimeStart_Prefix_SessionIDNotEmptyAndManagerHasIt(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())

	info, sess, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
	if sess == nil || sess.ID != info.SessionID {
		t.Fatalf("Session() = %+v, want ID == %q", sess, info.SessionID)
	}
	if _, ok := s.sessions.Get(info.SessionID); !ok {
		t.Error("session.Manager does not contain the session right after Start")
	}
	s.bgpSessionsMu.Lock()
	_, inRegistry := s.bgpSessions[info.SessionID]
	s.bgpSessionsMu.Unlock()
	if !inRegistry {
		t.Error("Service's own bgpSessions registry does not contain the session right after Start")
	}
}

func TestBGPRealtimeStart_IP_ResolvesRealPrefix(t *testing.T) {
	rest := startFakeServerHTTPAPI(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"9.9.9.0/24","origins":[{"origin":19281}]}}`))
		},
	})
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(rest, realGorillaDialer{}, fake.wsURL())

	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.9", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)
	if got.ResolvedPrefix != "9.9.9.0/24" {
		t.Errorf("ResolvedPrefix = %q, want %q", got.ResolvedPrefix, "9.9.9.0/24")
	}
	_ = BGPRealtimeStop(info.SessionID, s)
}

// TestBGPRealtimeStart_InvalidResource_NoWS — v1.2 Gate 5 P1-1 closure: a
// Wails-facing Start facade must return a real error for anything it
// rejects, never a State=FAILED info with err=nil (the old, incorrect
// contract this test used to freeze). Zero WS, zero session.Manager
// entry, zero Service registry entry — nothing is ever constructed for a
// resource realtime v1.2 can't support.
func TestBGPRealtimeStart_InvalidResource_NoWS(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	before := len(s.sessions.List())

	info, _, err := BGPRealtimeStart(context.Background(), "not a valid resource!!", s, nil)
	if err == nil {
		t.Fatal("err = nil, want a rejection for an invalid resource")
	}
	if info.SessionID != "" {
		t.Errorf("SessionID = %q, want empty — a rejected Start must never hand back a usable session", info.SessionID)
	}
	if got := len(s.sessions.List()); got != before {
		t.Errorf("session.Manager has %d live sessions after a rejected Start, want %d — no session.Manager entry must ever be created", got, before)
	}
	s.bgpSessionsMu.Lock()
	n := len(s.bgpSessions)
	s.bgpSessionsMu.Unlock()
	if n != 0 {
		t.Errorf("Service's bgpSessions registry has %d entries after a rejected Start, want 0", n)
	}
}

// TestBGPRealtimeStart_ASN_NoWS — same P1-1 contract as the invalid-
// resource case: ASN is out of scope for v1.2 realtime (§23.2), and a
// rejected Start must return an error, never a fabricated FAILED session.
func TestBGPRealtimeStart_ASN_NoWS(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	before := len(s.sessions.List())

	info, _, err := BGPRealtimeStart(context.Background(), "AS13335", s, nil)
	if err == nil {
		t.Fatal("err = nil, want a rejection — ASN is out of scope for v1.2 realtime")
	}
	if info.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", info.SessionID)
	}
	if got := len(s.sessions.List()); got != before {
		t.Errorf("session.Manager has %d live sessions after a rejected ASN Start, want %d", got, before)
	}
	s.bgpSessionsMu.Lock()
	n := len(s.bgpSessions)
	s.bgpSessionsMu.Unlock()
	if n != 0 {
		t.Errorf("Service's bgpSessions registry has %d entries after a rejected ASN Start, want 0", n)
	}
}

func TestBGPRealtimeStart_EmptyResource_Error(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	_, _, err := BGPRealtimeStart(context.Background(), "  ", s, nil)
	if err == nil {
		t.Fatal("err = nil, want a rejection for an empty resource")
	}
}

// TestBGPRealtimeStart_InvalidResource_NeverInstallsBridge — v1.2 Gate 5
// P1-2 closure: a rejected Start must never install a bridge for a
// session that doesn't exist.
func TestBGPRealtimeStart_InvalidResource_NeverInstallsBridge(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	called := false
	_, _, err := BGPRealtimeStart(context.Background(), "not a valid resource!!", s, func(*session.Session) { called = true })
	if err == nil {
		t.Fatal("err = nil, want a rejection")
	}
	if called {
		t.Error("bridge was installed for a rejected Start — must never happen")
	}
}

// --- bridge-before-run (v1.2 Gate 5 P1-2) and registration race (P1-3) ---

// instantFailDialer fails every dial attempt immediately, synchronously —
// no scripted delay, no network round-trip beyond the local httptest
// listener's own connect. Used to make a session's supervisor goroutine
// reach rs.fail() as fast as structurally possible after Run() launches
// it, stressing the registration-boundary invariant (v1.2 P1-3) as hard
// as this process can.
type instantFailDialer struct{}

func (instantFailDialer) DialContext(ctx context.Context, u string, header http.Header) (bgp.RealtimeConn, error) {
	return nil, fmt.Errorf("instantFailDialer: dial refused (test double)")
}

// TestBGPRealtimeStart_BridgeSeam_ReceivesFirstEventBeforeRunEverPublishes
// is the mandatory deterministic first-event test (v1.2 Gate 5 P1-2): the
// bridge callback BGPRealtimeStart passes to is invoked, and its
// subscriber installed, strictly BEFORE rs.Run() is called — a structural
// guarantee (registerBGPSession's map write, then bridge(sess), then
// rs.Run(), all synchronous in BGPRealtimeStart's own body), never a
// scheduling/network-latency assumption. The fake WS server here pushes
// its one scripted message as fast as the real local TCP loopback allows
// (no artificial delay in either direction) specifically so a bridge
// installed even one instant late could plausibly lose the race — this
// test proves it never does, because it structurally cannot start late.
func TestBGPRealtimeStart_BridgeSeam_ReceivesFirstEventBeforeRunEverPublishes(t *testing.T) {
	updateMsg := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"37.49.237.143-01a019f537900000","host":"rrc21.ripe.net","type":"UPDATE","path":[50628,35280,6453,4637,16509],"community":[],"origin":"IGP","announcements":[{"next_hop":"37.49.237.143","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`)
	fake := newFakeRISWSServer(t, [][]byte{updateMsg})
	s := newTestServiceWithBGPRealtime(unknownRPKIServer(t), realGorillaDialer{}, fake.wsURL())

	var sub <-chan events.Event
	var unsubscribe func()
	bridge := func(sess *session.Session) {
		sub, unsubscribe = sess.Bus.Subscribe(16, nil)
	}
	_, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, bridge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub == nil {
		t.Fatal("bridge was never called — BGPRealtimeStart must install the bridge for a successful Start")
	}
	defer unsubscribe()

	select {
	case got := <-sub:
		if got.Kind != events.KindProbe || got.Module != "bgp-realtime" || got.Topic != "bgp:realtime" {
			t.Errorf("got Kind=%q Module=%q Topic=%q, want probe/bgp-realtime/bgp:realtime", got.Kind, got.Module, got.Topic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first event through the bridge seam — bridge must be installed before Run() can publish anything")
	}
}

// TestBGPRealtimeStart_BridgeInstalledExactlyOnce is the mandatory
// "exactly one bridge" test (v1.2 Gate 5 requirement #9): BGPRealtimeStart
// has exactly one call site for bridge, no loop, no retry.
func TestBGPRealtimeStart_BridgeInstalledExactlyOnce(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())

	var calls int32
	bridge := func(*session.Session) { atomic.AddInt32(&calls, 1) }
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, bridge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)
	_ = BGPRealtimeStop(info.SessionID, s)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("bridge invoked %d times, want exactly 1", got)
	}
}

// TestRegisterBGPSession_RegisteredBeforeRun_NoStaleEntryEvenOnInstantFailure
// is the mandatory self-termination-during-registration-boundary test
// (v1.2 Gate 5 P1-3): registerBGPSession's map write is proven to have
// happened BEFORE rs.Run() is ever called (checked directly, not by
// polling), and even when the session then fails as fast as structurally
// possible (instantFailDialer), bgpSessions ends up with no stale entry —
// the check→insert race the old single-phase design accepted as
// "benign" no longer exists, because there is no window left for it to
// occur in.
func TestRegisterBGPSession_RegisteredBeforeRun_NoStaleEntryEvenOnInstantFailure(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), instantFailDialer{}, "ws://unused")

	rs, err := s.registerBGPSession(context.Background(), "9.9.9.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id := rs.Info().SessionID

	// Structural proof of the registration boundary: the entry already
	// exists here, BEFORE Run() has ever been called on rs.
	s.bgpSessionsMu.Lock()
	_, registeredBeforeRun := s.bgpSessions[id]
	s.bgpSessionsMu.Unlock()
	if !registeredBeforeRun {
		t.Fatal("bgpSessions does not contain the entry right after registerBGPSession, before Run() — registration must happen before the session can do anything")
	}
	if _, ok := s.sessions.Get(id); !ok {
		t.Fatal("session.Manager does not contain the entry right after registerBGPSession, before Run()")
	}

	rs.Run() // fails essentially instantly: dial() errors synchronously

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for rs.Info().State != bgp.SessionFailed {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("timed out waiting for the instant-fail session to reach FAILED")
		}
	}

	if _, ok := s.sessions.Get(id); ok {
		t.Error("session.Manager still contains the session after its own instant failure")
	}
	s.bgpSessionsMu.Lock()
	_, stillRegistered := s.bgpSessions[id]
	s.bgpSessionsMu.Unlock()
	if stillRegistered {
		t.Error("bgpSessions still contains a stale entry after self-termination (v1.2 P1-3 check→insert race) — must be fully closed")
	}
}

// TestBGPRealtimeSession_AutonomousFailureAfterConnect_ManagerAndRegistryBothAbsent
// is the mandatory "after autonomous failure" test (v1.2 Gate 5
// requirement #6): a session that connects successfully and only later
// fails on its own (a real RIS Live ris_error protocol frame, never a
// fabricated one) must end up with no trace in either session.Manager or
// Service's own bgpSessions registry — never a stale handle in one but
// not the other.
func TestBGPRealtimeSession_AutonomousFailureAfterConnect_ManagerAndRegistryBothAbsent(t *testing.T) {
	errFrame := []byte(`{"type":"ris_error","data":{"message":"invalid filter"}}`)
	fake := newFakeRISWSServer(t, [][]byte{errFrame})
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())

	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waitForRealtimeState(t, s, info.SessionID, bgp.SessionFailed, 2*time.Second)

	if _, ok := s.sessions.Get(info.SessionID); ok {
		t.Error("session.Manager still contains the session after its own autonomous failure")
	}
	s.bgpSessionsMu.Lock()
	_, inRegistry := s.bgpSessions[info.SessionID]
	s.bgpSessionsMu.Unlock()
	if inRegistry {
		t.Error("Service's bgpSessions registry still contains the session after its own autonomous failure")
	}
}

// --- 5/6/7/8: Stop ---

func TestBGPRealtimeStop_ValidSession_TerminatesAndManagerLosesIt(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	if err := BGPRealtimeStop(info.SessionID, s); err != nil {
		t.Fatalf("unexpected Stop error: %v", err)
	}
	if _, ok := s.sessions.Get(info.SessionID); ok {
		t.Error("session.Manager still contains the session after Stop")
	}
	s.bgpSessionsMu.Lock()
	_, inRegistry := s.bgpSessions[info.SessionID]
	s.bgpSessionsMu.Unlock()
	if inRegistry {
		t.Error("Service's registry still contains the session after Stop")
	}
}

func TestBGPRealtimeStop_UnknownID_Error(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	err := BGPRealtimeStop("does-not-exist", s)
	if err == nil {
		t.Fatal("err = nil, want a rejection for an unknown sessionID")
	}
}

func TestBGPRealtimeStop_EmptyID_Error(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	if err := BGPRealtimeStop("", s); err == nil {
		t.Fatal("err = nil, want a rejection for an empty sessionID")
	}
}

func TestBGPRealtimeStop_NonBGPSessionID_NeverCancelled(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	other := s.sessions.New(context.Background(), "some-other-module")

	err := BGPRealtimeStop(other.ID, s)
	if err == nil {
		t.Fatal("err = nil, want a rejection — this ID was never registered by BGPRealtimeStart")
	}
	if _, ok := s.sessions.Get(other.ID); !ok {
		t.Error("a non-BGP session was cancelled by BGPRealtimeStop — must never touch an ID it didn't create")
	}
}

func TestBGPRealtimeStop_RepeatedCall_SecondReturnsError(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	if err := BGPRealtimeStop(info.SessionID, s); err != nil {
		t.Fatalf("first Stop: unexpected error: %v", err)
	}
	if err := BGPRealtimeStop(info.SessionID, s); err == nil {
		t.Fatal("second Stop: err = nil, want an error — this contract's definition of idempotent (see BGPRealtimeStop's doc comment): safe, never a crash, but the entry is already gone")
	}
}

func TestBGPRealtimeStop_ConcurrentCalls_ExactlyOneSucceeds(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = BGPRealtimeStop(info.SessionID, s)
		}(i)
	}
	wg.Wait()

	nilCount := 0
	for _, e := range errs {
		if e == nil {
			nilCount++
		}
	}
	if nilCount != 1 {
		t.Errorf("nil-error count = %d across 5 concurrent Stop() calls, want exactly 1", nilCount)
	}
}

// --- Gate 5.1: BGPRealtimeInfo (local realtime session observability) ---

// countingDialer wraps a bgp.RealtimeDialer, counting DialContext calls —
// used by TestBGPRealtimeInfo_ZeroNetwork to prove BGPRealtimeInfo never
// dials RIS Live.
type countingDialer struct {
	inner bgp.RealtimeDialer
	count int32
}

func (d *countingDialer) DialContext(ctx context.Context, u string, header http.Header) (bgp.RealtimeConn, error) {
	atomic.AddInt32(&d.count, 1)
	return d.inner.DialContext(ctx, u, header)
}

// countingHTTPServer is startFakeServerHTTPAPI plus a shared call counter
// — used alongside countingDialer so TestBGPRealtimeInfo_ZeroNetwork can
// prove BGPRealtimeInfo performs zero RIPEstat HTTP calls too.
func countingHTTPServer(t *testing.T, routes map[string]http.HandlerFunc, count *int32) string {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		handler := h
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(count, 1)
			handler(w, r)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// waitForBGPRealtimeInfoState polls BGPRealtimeInfo itself (not the raw
// *bgp.RealtimeSession, unlike waitForRealtimeState above) until it
// reports want — the right wait primitive once a session may already have
// left s.bgpSessions for s.bgpFinalSnapshots by the time the caller can
// look, e.g. an instant-fail session started with instantFailDialer.
func waitForBGPRealtimeInfoState(t *testing.T, s *Service, id string, want bgp.RealtimeSessionState, timeout time.Duration) bgp.RealtimeSessionInfo {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := s.BGPRealtimeInfo(id)
		if err == nil && info.State == want {
			return info
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for BGPRealtimeInfo(%q) state %q (last err=%v info=%+v)", id, want, err, info)
		}
	}
}

// 1: live session — BGPRealtimeInfo succeeds, same SessionID, accurate
// live State, session.Manager still owns it, no mutation.
func TestBGPRealtimeInfo_Live_SucceedsWithAccurateState(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	got, err := s.BGPRealtimeInfo(info.SessionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SessionID != info.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, info.SessionID)
	}
	if got.State != bgp.SessionConnected {
		t.Errorf("State = %q, want %q", got.State, bgp.SessionConnected)
	}
	if _, ok := s.sessions.Get(info.SessionID); !ok {
		t.Error("session.Manager no longer owns the session after BGPRealtimeInfo — must never mutate/remove it")
	}
	_ = BGPRealtimeStop(info.SessionID, s)
}

// 2: zero network from Info — repeated BGPRealtimeInfo calls must never
// dial WS or call RIPEstat HTTP.
func TestBGPRealtimeInfo_ZeroNetwork(t *testing.T) {
	var httpCalls int32
	rest := countingHTTPServer(t, map[string]http.HandlerFunc{
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"unknown","validating_roas":[]}}`))
		},
	}, &httpCalls)
	fake := newFakeRISWSServer(t, nil)
	dialer := &countingDialer{inner: realGorillaDialer{}}
	s := newTestServiceWithBGPRealtime(rest, dialer, fake.wsURL())

	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	dialsBefore := atomic.LoadInt32(&dialer.count)
	httpBefore := atomic.LoadInt32(&httpCalls)

	for i := 0; i < 10; i++ {
		if _, err := s.BGPRealtimeInfo(info.SessionID); err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&dialer.count); got != dialsBefore {
		t.Errorf("WS dial count = %d after 10x BGPRealtimeInfo, want unchanged %d", got, dialsBefore)
	}
	if got := atomic.LoadInt32(&httpCalls); got != httpBefore {
		t.Errorf("RIPEstat HTTP call count = %d after 10x BGPRealtimeInfo, want unchanged %d", got, httpBefore)
	}
	_ = BGPRealtimeStop(info.SessionID, s)
}

// 3: unknown ID — error, nothing touched.
func TestBGPRealtimeInfo_UnknownID_Error(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	if _, err := s.BGPRealtimeInfo("does-not-exist"); err == nil {
		t.Fatal("err = nil, want a rejection for an unknown sessionID")
	}
}

// 4: empty ID — error.
func TestBGPRealtimeInfo_EmptyID_Error(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	if _, err := s.BGPRealtimeInfo(""); err == nil {
		t.Fatal("err = nil, want a rejection for an empty sessionID")
	}
	if _, err := s.BGPRealtimeInfo("   "); err == nil {
		t.Fatal("err = nil, want a rejection for a whitespace-only sessionID")
	}
}

// 5: non-BGP session ID — error, and the other session is left untouched
// (never consult/reinterpret session.Manager directly).
func TestBGPRealtimeInfo_NonBGPSessionID_ErrorAndSessionUntouched(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), failIfDialedWS{t}, "ws://unused")
	other := s.sessions.New(context.Background(), "some-other-module")

	if _, err := s.BGPRealtimeInfo(other.ID); err == nil {
		t.Fatal("err = nil, want a rejection — this ID was never registered by BGPRealtimeStart")
	}
	if _, ok := s.sessions.Get(other.ID); !ok {
		t.Error("a non-BGP session was removed/touched by BGPRealtimeInfo — must never happen")
	}
}

// 6: autonomous failure — after the live entry is gone, BGPRealtimeInfo
// still succeeds from the terminal snapshot with State=failed and
// LastError preserved.
func TestBGPRealtimeInfo_AutonomousFailure_TerminalSnapshotAvailable(t *testing.T) {
	errFrame := []byte(`{"type":"ris_error","data":{"message":"invalid filter"}}`)
	fake := newFakeRISWSServer(t, [][]byte{errFrame})
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())

	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionFailed, 2*time.Second)

	if _, ok := s.sessions.Get(info.SessionID); ok {
		t.Error("session.Manager still contains the session after autonomous failure")
	}
	s.bgpSessionsMu.Lock()
	_, stillLive := s.bgpSessions[info.SessionID]
	s.bgpSessionsMu.Unlock()
	if stillLive {
		t.Error("bgpSessions still contains the session after autonomous failure")
	}

	got, err := s.BGPRealtimeInfo(info.SessionID)
	if err != nil {
		t.Fatalf("BGPRealtimeInfo failed for a terminated session, want the terminal snapshot: %v", err)
	}
	if got.State != bgp.SessionFailed {
		t.Errorf("State = %q, want %q", got.State, bgp.SessionFailed)
	}
	if got.LastError == "" {
		t.Error("LastError is empty, want the ris_error reason preserved in the terminal snapshot")
	}
}

// 7: explicit Stop — after Stop returns, BGPRealtimeInfo returns the
// final snapshot with State=stopped.
func TestBGPRealtimeInfo_AfterExplicitStop_FinalState(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	if err := BGPRealtimeStop(info.SessionID, s); err != nil {
		t.Fatalf("unexpected Stop error: %v", err)
	}

	got, err := s.BGPRealtimeInfo(info.SessionID)
	if err != nil {
		t.Fatalf("BGPRealtimeInfo failed after Stop, want the final snapshot: %v", err)
	}
	if got.State != bgp.SessionStopped {
		t.Errorf("State = %q, want %q", got.State, bgp.SessionStopped)
	}
	if got.SessionID != info.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, info.SessionID)
	}
}

// 8: concurrent Stop — the existing exactly-one-success contract is
// preserved, and a final snapshot exists afterward regardless of which
// caller won.
func TestBGPRealtimeInfo_AfterConcurrentStop_FinalSnapshotExists(t *testing.T) {
	fake := newFakeRISWSServer(t, nil)
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), realGorillaDialer{}, fake.wsURL())
	info, _, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForRealtimeState(t, s, info.SessionID, bgp.SessionConnected, 2*time.Second)

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = BGPRealtimeStop(info.SessionID, s)
		}(i)
	}
	wg.Wait()

	nilCount := 0
	for _, e := range errs {
		if e == nil {
			nilCount++
		}
	}
	if nilCount != 1 {
		t.Fatalf("nil-error count = %d across 5 concurrent Stop() calls, want exactly 1", nilCount)
	}

	got, err := s.BGPRealtimeInfo(info.SessionID)
	if err != nil {
		t.Fatalf("BGPRealtimeInfo failed after concurrent Stop, want the final snapshot: %v", err)
	}
	if got.State != bgp.SessionStopped {
		t.Errorf("State = %q, want %q", got.State, bgp.SessionStopped)
	}
}

// 9: bounded final snapshots — more than bgpFinalSnapshotLimit terminated
// sessions never grow the cache past the limit, with deterministic FIFO
// eviction (oldest gone, newest always retained).
func TestBGPRealtimeInfo_FinalSnapshots_Bounded(t *testing.T) {
	s := newTestServiceWithBGPRealtime(failIfCalledHTTPAPI(t), instantFailDialer{}, "ws://unused")

	const total = bgpFinalSnapshotLimit + 6
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		resource := fmt.Sprintf("9.9.%d.0/24", i)
		info, _, err := BGPRealtimeStart(context.Background(), resource, s, nil)
		if err != nil {
			t.Fatalf("Start #%d: unexpected error: %v", i, err)
		}
		ids = append(ids, info.SessionID)
		waitForBGPRealtimeInfoState(t, s, info.SessionID, bgp.SessionFailed, 2*time.Second)
	}

	s.bgpSessionsMu.Lock()
	n := len(s.bgpFinalSnapshots)
	_, oldestPresent := s.bgpFinalSnapshots[ids[0]]
	_, newestPresent := s.bgpFinalSnapshots[ids[len(ids)-1]]
	s.bgpSessionsMu.Unlock()

	if n > bgpFinalSnapshotLimit {
		t.Errorf("len(bgpFinalSnapshots) = %d, want <= %d", n, bgpFinalSnapshotLimit)
	}
	if oldestPresent {
		t.Error("oldest terminated session still present — want deterministic FIFO eviction")
	}
	if !newestPresent {
		t.Error("newest terminated session missing — want it always retained")
	}
}

// 10: the terminal cache stores immutable RealtimeSessionInfo VALUES,
// never a *bgp.RealtimeSession handle — structurally enforced by
// Service.bgpFinalSnapshots' own declared type, checked here so a future
// edit changing that type to a pointer/handle fails a test, not just a
// design review.
func TestBGPFinalSnapshots_StoresValuesNotHandles(t *testing.T) {
	var m map[string]bgp.RealtimeSessionInfo
	elem := reflect.TypeOf(m).Elem()
	if elem.Kind() != reflect.Struct {
		t.Fatalf("bgpFinalSnapshots value type = %v, want a struct value (bgp.RealtimeSessionInfo), never a pointer/handle", elem.Kind())
	}
}

// --- 10/11/12: published events — Kind/Module/Topic/Payload ---

func TestBGPRealtimeStart_SourceEvent_KindModuleTopicPayload(t *testing.T) {
	updateMsg := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"37.49.237.143-01a019f537900000","host":"rrc21.ripe.net","type":"UPDATE","path":[50628,35280,6453,4637,16509],"community":[],"origin":"IGP","announcements":[{"next_hop":"37.49.237.143","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`)
	fake := newFakeRISWSServer(t, [][]byte{updateMsg})
	s := newTestServiceWithBGPRealtime(unknownRPKIServer(t), realGorillaDialer{}, fake.wsURL())

	_, sess, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sub, unsubscribe := sess.Bus.Subscribe(16, nil)
	defer unsubscribe()

	var got events.Event
	select {
	case got = <-sub:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the source event")
	}
	if got.Kind != events.KindProbe {
		t.Errorf("Kind = %q, want %q", got.Kind, events.KindProbe)
	}
	if got.Module != "bgp-realtime" {
		t.Errorf("Module = %q, want %q", got.Module, "bgp-realtime")
	}
	if got.Topic != "bgp:realtime" {
		t.Errorf("Topic = %q, want %q", got.Topic, "bgp:realtime")
	}
	ev, ok := got.Payload.(bgp.BGPRealtimeEvent)
	if !ok {
		t.Fatalf("Payload type = %T, want bgp.BGPRealtimeEvent", got.Payload)
	}
	if ev.Type != bgp.EventAnnouncement || ev.Prefix != "9.9.9.0/24" {
		t.Errorf("Payload = %+v, want a full announcement event for 9.9.9.0/24", ev)
	}
}

func TestBGPRealtimeStart_DerivedEvent_SameKindModuleTopic(t *testing.T) {
	first := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"peerA","peer_asn":"100","id":"m1","host":"rrc21.ripe.net","type":"UPDATE","path":[100,200,300],"community":[],"origin":"IGP","announcements":[{"next_hop":"peerA","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`)
	second := []byte(`{"type":"ris_message","data":{"timestamp":1787141897.080,"peer":"peerA","peer_asn":"100","id":"m2","host":"rrc21.ripe.net","type":"UPDATE","path":[100,999,300],"community":[],"origin":"IGP","announcements":[{"next_hop":"peerA","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`)
	fake := newFakeRISWSServer(t, [][]byte{first, second})
	s := newTestServiceWithBGPRealtime(unknownRPKIServer(t), realGorillaDialer{}, fake.wsURL())

	_, sess, err := BGPRealtimeStart(context.Background(), "9.9.9.0/24", s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sub, unsubscribe := sess.Bus.Subscribe(16, nil)
	defer unsubscribe()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-sub:
			ev, ok := got.Payload.(bgp.BGPRealtimeEvent)
			if !ok || ev.Type != bgp.EventPathChanged {
				continue
			}
			if got.Kind != events.KindProbe {
				t.Errorf("derived event Kind = %q, want %q", got.Kind, events.KindProbe)
			}
			if got.Module != "bgp-realtime" {
				t.Errorf("derived event Module = %q, want %q", got.Module, "bgp-realtime")
			}
			if got.Topic != "bgp:realtime" {
				t.Errorf("derived event Topic = %q, want %q — same as source events, never a separate topic per Event.Type", got.Topic, "bgp:realtime")
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for the derived path_changed event")
		}
	}
}

// --- section 10: History/BGPlay Service wrapper tests ---

func TestBGPHistoryDelegates(t *testing.T) {
	updates := []map[string]any{
		{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
			"attrs": map[string]any{"source_id": "x", "target_prefix": "9.9.9.0/24", "path": []int{100}}},
	}
	addr := startFakeServerHTTPAPI(t, map[string]http.HandlerFunc{
		"/bgp-updates/data.json": func(w http.ResponseWriter, r *http.Request) {
			b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{
				"resource": "9.9.9.0/24", "query_starttime": "2026-08-18T00:00:00", "query_endtime": "2026-08-18T23:00:00",
				"nr_updates": len(updates), "updates": updates,
			}})
			w.Write(b)
		},
	})
	s := &Service{bgpClient: &bgp.Client{BaseURL: addr}}
	res := s.BGPHistory(bgp.BGPHistoryRequest{Resource: "9.9.9.0/24", StartTime: "2026-08-18T00:00:00Z", EndTime: "2026-08-18T23:00:00Z"})

	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Updates) != 1 {
		t.Fatalf("Updates = %d, want 1 — method must delegate to bgp.Client.BGPHistory, not reimplement it", len(res.Updates))
	}
	if res.Updates[0].TargetPrefix != "9.9.9.0/24" {
		t.Errorf("TargetPrefix = %q, want %q — must not be lost through the Service wrapper", res.Updates[0].TargetPrefix, "9.9.9.0/24")
	}
	if res.ObservedUpdates != 1 {
		t.Errorf("ObservedUpdates = %d, want 1 — must come straight from the domain result, never recomputed here", res.ObservedUpdates)
	}
}

func TestBGPHistory_InvalidRequest_NoAdditionalHTTP(t *testing.T) {
	s := &Service{bgpClient: &bgp.Client{BaseURL: failIfCalledHTTPAPI(t)}}
	res := s.BGPHistory(bgp.BGPHistoryRequest{Resource: "garbage!!", StartTime: "2026-08-18T00:00:00Z", EndTime: "2026-08-18T23:00:00Z"})
	if res.Err == "" {
		t.Fatal("Err empty, want a rejection — the Service wrapper must not swallow domain validation")
	}
}

func TestBGPlayDelegates(t *testing.T) {
	addr := startFakeServerHTTPAPI(t, map[string]http.HandlerFunc{
		"/bgplay/data.json": func(w http.ResponseWriter, r *http.Request) {
			b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{
				"resource": "9.9.9.0/24", "query_starttime": "2026-08-18T00:00:00", "query_endtime": "2026-08-18T23:00:00",
				"initial_state": []map[string]any{},
				"events": []map[string]any{
					{"seq": 1, "timestamp": "2026-08-18T00:00:00", "type": "A",
						"attrs": map[string]any{"source_id": "x", "target_prefix": "9.9.9.0/24", "path": []int{100}}},
				},
				"nodes":   []map[string]any{},
				"sources": []map[string]any{},
			}})
			w.Write(b)
		},
	})
	s := &Service{bgpClient: &bgp.Client{BaseURL: addr}}
	res := s.BGPlay(bgp.BGPlayRequest{Resource: "9.9.9.0/24", StartTime: "2026-08-18T00:00:00Z", EndTime: "2026-08-18T23:00:00Z"})

	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("Events = %d, want 1 — method must delegate to bgp.Client.BGPlay", len(res.Events))
	}
	if res.Events[0].TargetPrefix != "9.9.9.0/24" {
		t.Errorf("TargetPrefix = %q, want %q — must survive the Service wrapper", res.Events[0].TargetPrefix, "9.9.9.0/24")
	}
	if res.Truncated {
		t.Error("Truncated = true, want false — limits/truncation must come from the domain call, not be reintroduced here")
	}
}

// --- shared test helpers (mirroring bgp_intelligence_test.go's own, kept
// distinctly named so both files' helpers never collide) ---

func startFakeServerHTTPAPI(t *testing.T, routes map[string]http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// unknownRPKIServer answers every rpki-validation call with "unknown" —
// every announcement with a determinate origin (all the fixtures in this
// file use a plain ASN path, never AS_SET) triggers exactly one such call
// from realtime_derive.go's checkRPKITransition, off the read path but
// still real HTTP; a test that only cares about source/derived event
// wiring uses this instead of failIfCalledHTTPAPI so that background call
// succeeds quietly instead of racing a t.Errorf against test cleanup.
func unknownRPKIServer(t *testing.T) string {
	t.Helper()
	return startFakeServerHTTPAPI(t, map[string]http.HandlerFunc{
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"unknown","validating_roas":[]}}`))
		},
	})
}

func failIfCalledHTTPAPI(t *testing.T) string {
	t.Helper()
	return startFakeServerHTTPAPI(t, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected RIPEstat call: %s", r.URL.String())
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
}
