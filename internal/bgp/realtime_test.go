package bgp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"trazip/internal/session"
)

// --- test doubles ---

// recordingDialer never actually dials — it records call count and, when
// fail is set, fails the test outright. Used by the "zero WebSocket
// attempts" tests (#2 invalid resource, #3 IP resolution failure).
type recordingDialer struct {
	t    *testing.T
	fail bool

	mu    sync.Mutex
	calls int
}

func (d *recordingDialer) DialContext(ctx context.Context, u string, header http.Header) (RealtimeConn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	if d.fail {
		d.t.Errorf("unexpected WebSocket dial attempt to %s", u)
	}
	return nil, fmt.Errorf("recordingDialer: dial refused (test double)")
}

func (d *recordingDialer) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// fakeRISServer is a real local WebSocket server (net/http/httptest +
// gorilla/websocket) — no Internet involved. It captures the
// ris_subscribe message and can optionally push scripted frames, then
// blocks reading (so the connection stays open until the client
// disconnects, letting Stop()-during-read tests be deterministic).
type fakeRISServer struct {
	srv        *httptest.Server
	subscribed chan risSubscribeMessage
}

func newFakeRISServer(t *testing.T, messages [][]byte, blockAfter bool) *fakeRISServer {
	t.Helper()
	f := &fakeRISServer{subscribed: make(chan risSubscribeMessage, 1)}
	upgrader := websocket.Upgrader{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var sub risSubscribeMessage
		if err := conn.ReadJSON(&sub); err != nil {
			return
		}
		select {
		case f.subscribed <- sub:
		default:
		}
		for _, m := range messages {
			if err := conn.WriteMessage(websocket.TextMessage, m); err != nil {
				return
			}
		}
		if blockAfter {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRISServer) wsURL() string {
	return "ws" + strings.TrimPrefix(f.srv.URL, "http")
}

// failIfCalledHTTP returns a BaseURL for a bgp.Client that fails the test
// if RIPEstat is ever queried — used for resource kinds that must never
// trigger IP resolution (prefix resources, invalid resources).
func failIfCalledHTTP(t *testing.T) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected RIPEstat call: %s", r.URL.String())
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// waitForState polls Info() with a bounded, short-interval ticker (never a
// single blind sleep) until want is reached or timeout elapses.
func waitForState(t *testing.T, rs *RealtimeSession, want RealtimeSessionState, timeout time.Duration) RealtimeSessionInfo {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		info := rs.Info()
		if info.State == want {
			return info
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for state %q, last state = %q (err=%q)", want, info.State, info.LastError)
		}
	}
}

// --- 1. no auto-connect ---

func TestRealtimeSession_NoAutoConnect(t *testing.T) {
	dialer := &recordingDialer{t: t, fail: true}
	// Nothing in this test calls StartRealtimeSession/startRealtimeSession
	// at all — building the collaborators alone must never dial anything.
	_ = session.NewManager()
	_ = NewClient()
	if dialer.Calls() != 0 {
		t.Fatalf("dialer was called %d times before any Start() — auto-connect is forbidden", dialer.Calls())
	}
}

// --- 2. invalid resource -> zero network ---

func TestRealtimeSession_InvalidResource_ZeroNetwork(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "not a valid resource!!", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	info := waitForState(t, rs, SessionFailed, time.Second)
	if info.LastError == "" {
		t.Error("LastError must be set when a session fails")
	}
	if dialer.Calls() != 0 {
		t.Errorf("dialer called %d times for an invalid resource, want 0", dialer.Calls())
	}
}

// --- 3. IP resolve failure -> zero WS ---

func TestRealtimeSession_IPResolutionFailure_ZeroWebSocket(t *testing.T) {
	mgr := session.NewManager()
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[]}}`))
	})
	client := &Client{BaseURL: ripestat}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	info := waitForState(t, rs, SessionFailed, 2*time.Second)
	if info.ResolvedPrefix != "" {
		t.Errorf("ResolvedPrefix = %q, want empty when resolution fails", info.ResolvedPrefix)
	}
	if dialer.Calls() != 0 {
		t.Errorf("dialer called %d times when resolution failed, want 0", dialer.Calls())
	}
}

// --- 4. IP resolve success -> subscribe con CIDR real ---

func TestRealtimeSession_IPResolutionSuccess_SubscribesWithResolvedPrefix(t *testing.T) {
	mgr := session.NewManager()
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[{"origin":15169}]}}`))
	})
	client := &Client{BaseURL: ripestat}
	fake := newFakeRISServer(t, nil, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	select {
	case sub := <-fake.subscribed:
		if sub.Type != "ris_subscribe" {
			t.Errorf("Type = %q, want ris_subscribe", sub.Type)
		}
		if sub.Data.Prefix != "8.8.8.0/24" {
			t.Errorf("subscribe Prefix = %q, want resolved CIDR 8.8.8.0/24 (never the raw IP, never a fabricated /32)", sub.Data.Prefix)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ris_subscribe")
	}

	info := waitForState(t, rs, SessionConnected, 2*time.Second)
	if info.ResolvedPrefix != "8.8.8.0/24" {
		t.Errorf("ResolvedPrefix = %q, want 8.8.8.0/24", info.ResolvedPrefix)
	}
}

// --- 5. prefix -> subscribe directo (+ zero RIPEstat calls) ---

func TestRealtimeSession_PrefixResource_SubscribesDirectly(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)} // prefix resources skip resolution entirely
	fake := newFakeRISServer(t, nil, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	select {
	case sub := <-fake.subscribed:
		if sub.Data.Prefix != "9.9.9.0/24" {
			t.Errorf("subscribe Prefix = %q, want 9.9.9.0/24", sub.Data.Prefix)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ris_subscribe")
	}

	waitForState(t, rs, SessionConnected, 2*time.Second)
}

// --- 6. subscribe nunca vacío ---

func TestRealtimeSession_SubscribeNeverEmpty(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	select {
	case sub := <-fake.subscribed:
		if sub.Data.Prefix == "" {
			t.Error("ris_subscribe sent with an empty prefix filter — forbidden (never a firehose subscription)")
		}
		if sub.Data.Type != "UPDATE" {
			t.Errorf("subscribe Type = %q, want UPDATE", sub.Data.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ris_subscribe")
	}
}

// --- 20. Start state transitions ---

func TestRealtimeSession_StateTransitions_ConnectingToConnected(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	// Immediately after Start, the session must be in a valid pre-connect
	// state — never skip straight to Connected without having gone
	// through Connecting.
	first := rs.Info().State
	if first != SessionConnecting && first != SessionConnected {
		t.Errorf("initial state = %q, want connecting or connected (already raced ahead)", first)
	}

	waitForState(t, rs, SessionConnected, 2*time.Second)
}

// --- 21/22. Cancel during read + supervisor terminates cleanly ---

func TestRealtimeSession_StopDuringActiveRead_TerminatesCleanly(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true) // blocks reading after subscribe — an active read in progress

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())

	select {
	case <-fake.subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the session to reach an active read")
	}
	waitForState(t, rs, SessionConnected, 2*time.Second)

	stopped := make(chan struct{})
	go func() {
		rs.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5s — supervisor goroutine did not terminate (possible leak)")
	}

	info := rs.Info()
	if info.State != SessionStopped {
		t.Errorf("State after Stop() = %q, want stopped", info.State)
	}
}

// --- Gate 2 runtime closure: watcher lifecycle (v1.2 P1-1) ---

func TestRealtimeSession_TerminalDialFailureWithoutStop_WatcherTerminates(t *testing.T) {
	mgr := session.NewManager()
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[{"origin":15169}]}}`))
	})
	client := &Client{BaseURL: ripestat}
	dialer := &recordingDialer{t: t, fail: false} // dial is expected to be called and refused

	rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	// No Stop() call anywhere before this point — the terminal dial
	// failure itself must unwind the supervisor AND the watcher goroutine
	// on its own (v1.2 P1-1 closure).
	waitForState(t, rs, SessionFailed, 2*time.Second)

	select {
	case <-rs.done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor goroutine did not terminate after a terminal dial failure without Stop()")
	}
	select {
	case <-rs.watcherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher goroutine did not terminate after a terminal dial failure without Stop() — goroutine leak (v1.2 P1-1)")
	}
	if rs.sess.Context().Err() == nil {
		t.Error("session context was never canceled after a terminal failure without Stop() — would leak the watcher indefinitely")
	}
}

// --- Gate 2 runtime closure: session manager lifecycle (v1.2 P1-2) ---

func TestRealtimeSession_Stop_RemovesFromManager(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	waitForState(t, rs, SessionConnected, 2*time.Second)

	sessionID := rs.sess.ID
	rs.Stop()

	if _, ok := mgr.Get(sessionID); ok {
		t.Error("session still registered in Manager after Stop() — registry leak (v1.2 P1-2)")
	}
}

func TestRealtimeSession_TerminalResolutionFailure_NoRegistryLeak(t *testing.T) {
	mgr := session.NewManager()
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[]}}`))
	})
	client := &Client{BaseURL: ripestat}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionFailed, 2*time.Second)
	sessionID := rs.sess.ID
	if _, ok := mgr.Get(sessionID); ok {
		t.Error("session still registered in Manager after a terminal resolution failure, without ever calling Stop() — registry leak (v1.2 P1-2)")
	}
}

func TestRealtimeSession_TerminalDialFailure_NoRegistryLeak(t *testing.T) {
	mgr := session.NewManager()
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[{"origin":15169}]}}`))
	})
	client := &Client{BaseURL: ripestat}
	dialer := &recordingDialer{t: t, fail: false}

	rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionFailed, 2*time.Second)
	sessionID := rs.sess.ID
	if _, ok := mgr.Get(sessionID); ok {
		t.Error("session still registered in Manager after a terminal dial failure, without ever calling Stop() — registry leak (v1.2 P1-2)")
	}
}

func TestRealtimeSession_InternalSessionState_NeverActiveAfterTerminal(t *testing.T) {
	t.Run("failed", func(t *testing.T) {
		mgr := session.NewManager()
		ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[]}}`))
		})
		client := &Client{BaseURL: ripestat}
		dialer := &recordingDialer{t: t, fail: true}

		rs := startRealtimeSession(context.Background(), mgr, client, "8.8.8.8", dialer, "ws://unused")
		t.Cleanup(rs.Stop)
		waitForState(t, rs, SessionFailed, 2*time.Second)

		if got := rs.sess.State(); got == session.StateActive {
			t.Errorf("internal session.State() = %q after FAILED, want non-Active", got)
		}
	})

	t.Run("stopped", func(t *testing.T) {
		mgr := session.NewManager()
		client := &Client{BaseURL: failIfCalledHTTP(t)}
		fake := newFakeRISServer(t, nil, true)

		rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
		waitForState(t, rs, SessionConnected, 2*time.Second)
		rs.Stop()

		if got := rs.sess.State(); got == session.StateActive {
			t.Errorf("internal session.State() = %q after STOPPED, want non-Active", got)
		}
	})
}

// --- Gate 2 runtime closure: ris_error observable, never silent (v1.2 P1-3 / RIS_ERROR) ---

func TestRealtimeSession_RISError_TerminatesFailed(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	errFrame := []byte(`{"type":"ris_error","data":{"message":"invalid filter"}}`)
	fake := newFakeRISServer(t, [][]byte{errFrame}, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	info := waitForState(t, rs, SessionFailed, 2*time.Second)
	if !strings.Contains(info.LastError, "invalid filter") {
		t.Errorf("LastError = %q, want it to surface the RIPE ris_error message %q", info.LastError, "invalid filter")
	}
	if info.ReceivedEvents != 0 {
		t.Errorf("ReceivedEvents = %d, want 0 for a ris_error frame (never a fabricated BGP event)", info.ReceivedEvents)
	}
}

func TestRealtimeSession_StopIdempotent_NoGoroutineLaunched(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "invalid!!", dialer, "ws://unused")
	waitForState(t, rs, SessionFailed, time.Second)

	stopped := make(chan struct{})
	go func() {
		rs.Stop()
		rs.Stop() // second call must not hang/panic — idempotent
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() hung on a session whose goroutine never launched")
	}
	if got := rs.Info().State; got != SessionStopped {
		t.Errorf("State = %q, want stopped", got)
	}
}

// --- Gate 2 final lifecycle closure: parent context cancellation cleanup ---
//
// Both tests below cancel the PARENT context passed to
// startRealtimeSession directly — never rs.Stop() — to prove the
// supervise() defer catch-all (realtime.go) does the Manager
// cleanup/state-transition even when nobody explicitly stopped or failed
// the session.

func TestRealtimeSession_ParentContextCanceled_AfterConnected_CleansUp(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true) // blocks reading after subscribe — an active read in progress

	parentCtx, cancel := context.WithCancel(context.Background())
	rs := startRealtimeSession(parentCtx, mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())

	waitForState(t, rs, SessionConnected, 2*time.Second)
	sessionID := rs.sess.ID

	// Parent canceled directly — rs.Stop() is never called.
	cancel()

	select {
	case <-rs.done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor goroutine did not terminate after parent context cancellation (no Stop() call)")
	}
	select {
	case <-rs.watcherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher goroutine did not terminate after parent context cancellation (no Stop() call)")
	}

	info := rs.Info()
	if info.State != SessionStopped {
		t.Errorf("State = %q, want stopped (parent cancellation is not a datasource failure — must never surface as FAILED)", info.State)
	}
	if _, ok := mgr.Get(sessionID); ok {
		t.Error("session still registered in Manager after parent context cancellation — registry leak")
	}
	if got := rs.sess.State(); got == session.StateActive {
		t.Errorf("internal session.State() = %q after parent cancellation, want non-Active", got)
	}
}

func TestRealtimeSession_ParentContextCanceled_DuringResolution_CleansUp(t *testing.T) {
	mgr := session.NewManager()
	hit := make(chan struct{})
	unblock := make(chan struct{})
	ripestat := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		close(hit)
		<-unblock
		w.Write([]byte(`{"status":"ok","data":{"resource":"8.8.8.0/24","origins":[{"origin":15169}]}}`))
	})
	client := &Client{BaseURL: ripestat}
	dialer := &recordingDialer{t: t, fail: true} // WS must never be attempted

	parentCtx, cancel := context.WithCancel(context.Background())
	rs := startRealtimeSession(parentCtx, mgr, client, "8.8.8.8", dialer, "ws://unused")

	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the resolution request to reach the fake RIPEstat server")
	}

	// Parent canceled WHILE IP->prefix resolution is in flight (still
	// CONNECTING) — rs.Stop() is never called.
	cancel()
	close(unblock) // release the blocked handler so its goroutine doesn't leak past the test

	select {
	case <-rs.done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor goroutine did not terminate after parent context cancellation during resolution")
	}
	select {
	case <-rs.watcherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher goroutine did not terminate after parent context cancellation during resolution")
	}

	info := rs.Info()
	if info.State != SessionStopped {
		t.Errorf("State = %q, want stopped (parent cancellation during resolution is not a datasource failure)", info.State)
	}
	if info.ResolvedPrefix != "" {
		t.Errorf("ResolvedPrefix = %q, want empty — resolution never completed", info.ResolvedPrefix)
	}
	if _, ok := mgr.Get(rs.sess.ID); ok {
		t.Error("session still registered in Manager after parent context cancellation during resolution — registry leak")
	}
	if got := rs.sess.State(); got == session.StateActive {
		t.Errorf("internal session.State() = %q after parent cancellation during resolution, want non-Active", got)
	}
	if dialer.Calls() != 0 {
		t.Errorf("dialer called %d times — WebSocket must never be attempted when resolution never completes", dialer.Calls())
	}
}

// --- v1.2 Gate 5 "REALTIME OWNERSHIP" bridge seam: Session() / onTerminate ---

func TestRealtimeSession_Session_ReturnsUnderlyingSession(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "invalid!!", dialer, "ws://unused")
	t.Cleanup(rs.Stop)

	if rs.Session() == nil {
		t.Fatal("Session() = nil, want the underlying *session.Session")
	}
	if rs.Session().ID != rs.sess.ID {
		t.Errorf("Session().ID = %q, want %q — must be the exact same session, never a second ID", rs.Session().ID, rs.sess.ID)
	}
}

func TestRealtimeSession_OnTerminate_FiresOnceOnSynchronousFail(t *testing.T) {
	// KindInvalid resources call fail() SYNCHRONOUSLY inside the
	// constructor, before it even returns — onTerminate must already be
	// wired up by then (v1.2 Gate 5 registerBGPSession race the doc
	// comment on the onTerminate field describes).
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	dialer := &recordingDialer{t: t, fail: true}

	var calls int
	var gotID string
	rs := newRealtimeSession(context.Background(), mgr, client, "not a valid resource!!", dialer, "ws://unused", realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, func(id string) {
		calls++
		gotID = id
	})
	t.Cleanup(rs.Stop)

	if calls != 1 {
		t.Fatalf("onTerminate called %d times, want exactly 1", calls)
	}
	if gotID != rs.sess.ID {
		t.Errorf("onTerminate got id %q, want %q", gotID, rs.sess.ID)
	}
}

func TestRealtimeSession_OnTerminate_FiresOnceOnExplicitStop(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	fake := newFakeRISServer(t, nil, true)

	var calls int32
	rs := newRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL(), realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, func(id string) {
		atomic.AddInt32(&calls, 1)
	})
	waitForState(t, rs, SessionConnected, 2*time.Second)

	rs.Stop()
	rs.Stop() // second call must not fire the hook again (terminateOnce)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("onTerminate called %d times across two Stop() calls, want exactly 1", got)
	}
}

func TestRealtimeSession_OnTerminate_NilIsSafe(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	dialer := &recordingDialer{t: t, fail: true}

	rs := startRealtimeSession(context.Background(), mgr, client, "invalid!!", dialer, "ws://unused")
	rs.Stop() // must not panic when onTerminate is nil (every Gate 2/3/4 test path)
}
