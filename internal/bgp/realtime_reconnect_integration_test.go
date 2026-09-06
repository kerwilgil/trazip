package bgp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"trazip/internal/session"
)

// scriptedConn is a fully in-memory RealtimeConn double — no real network,
// no real timing — used by the Gate 3 reconnect/backoff integration tests
// so they never depend on real WebSocket wire behavior or wall-clock
// timing (only realtime_test.go's Gate 2 tests need the real
// httptest+gorilla/websocket fakeRISServer for wire-format fidelity).
type scriptedConn struct {
	mu     sync.Mutex
	closed bool
	reads  chan readResult
}

type readResult struct {
	data []byte
	err  error
}

func newScriptedConn() *scriptedConn {
	return &scriptedConn{reads: make(chan readResult, 4)}
}

func (c *scriptedConn) WriteJSON(v any) error { return nil }

func (c *scriptedConn) ReadMessage() (int, []byte, error) {
	r, ok := <-c.reads
	if !ok {
		return 0, nil, fmt.Errorf("scriptedConn: closed")
	}
	return 1, r.data, r.err
}

// Close interrupts any blocked ReadMessage() exactly like a real
// gorilla/websocket Close() would — closing c.reads makes the blocked
// receive return immediately.
func (c *scriptedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.reads)
	}
	return nil
}

func (c *scriptedConn) SetReadDeadline(time.Time) error { return nil }

func (c *scriptedConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// pushDisconnect enqueues a single read error, simulating the connection
// dying — the SUT's readLoop will treat this exactly like a real dropped
// TCP/WebSocket connection.
func (c *scriptedConn) pushDisconnect() {
	c.reads <- readResult{err: errors.New("scriptedConn: simulated disconnect")}
}

// scriptedConnDialer returns pre-scripted results (a fresh conn, or an
// error) in order, one per DialContext call; the last step repeats if the
// SUT dials more times than scripted (defensive — most tests script
// exactly as many calls as they expect).
type scriptedConnDialer struct {
	mu    sync.Mutex
	steps []func() (RealtimeConn, error)
	idx   int
}

func (d *scriptedConnDialer) DialContext(ctx context.Context, u string, h http.Header) (RealtimeConn, error) {
	d.mu.Lock()
	i := d.idx
	if i >= len(d.steps) {
		i = len(d.steps) - 1
	}
	d.idx++
	step := d.steps[i]
	d.mu.Unlock()
	return step()
}

func (d *scriptedConnDialer) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.idx
}

func okStep(c *scriptedConn) func() (RealtimeConn, error) {
	return func() (RealtimeConn, error) { return c, nil }
}

func failStep(msg string) func() (RealtimeConn, error) {
	return func() (RealtimeConn, error) { return nil, errors.New(msg) }
}

// waitForReconnectCount polls Info() until ReconnectCount >= want.
func waitForReconnectCount(t *testing.T, rs *RealtimeSession, want int, timeout time.Duration) RealtimeSessionInfo {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		info := rs.Info()
		if info.ReconnectCount >= want {
			return info
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for ReconnectCount >= %d, last = %d (state=%q, err=%q)", want, info.ReconnectCount, info.State, info.LastError)
		}
	}
}

func waitForDialerCalls(t *testing.T, dialer interface{ Calls() int }, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		if dialer.Calls() >= want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for dialer.Calls() >= %d, last = %d", want, dialer.Calls())
		}
	}
}

// --- disconnect -> RECONNECTING, then reconnect success -> CONNECTED ---

func TestReconnect_DisconnectThenSuccess_TransitionsAndCounts(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	first := newScriptedConn()
	second := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(first), okStep(second)}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0.5}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	waitForDialerCalls(t, dialer, 1, 2*time.Second)

	first.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	// First backoff attempt requested — release it to let the (scripted,
	// successful) 2nd dial proceed instantly, no real sleep.
	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)

	info := waitForState(t, rs, SessionConnected, 2*time.Second)
	if info.ReconnectCount != 1 {
		t.Errorf("ReconnectCount = %d, want 1 after one successful reconnect", info.ReconnectCount)
	}
	if dialer.Calls() != 2 {
		t.Errorf("dialer.Calls() = %d, want 2 (initial connect + 1 reconnect)", dialer.Calls())
	}
}

func TestReconnect_OldConnNotReusedAfterReconnect(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	first := newScriptedConn()
	second := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(first), okStep(second)}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0.5}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	first.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)
	waitForState(t, rs, SessionConnected, 2*time.Second)

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for !first.isClosed() {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("old connection was never closed after a successful reconnect — must not be reused/left dangling")
		}
	}
	if second.isClosed() {
		t.Error("the new (current) connection was closed prematurely — Stop should still be able to close only the active one")
	}
}

// --- exact backoff interval sequence + jitter fixture ---

func TestReconnect_BackoffIntervalSequence(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(initial), failStep("dial 1"), failStep("dial 2"), failStep("dial 3"), failStep("dial 4"), failStep("dial 5"), failStep("dial 6"), failStep("dial 7")}}

	// r=0 -> jitter factor exactly 0.8x, so requested durations are
	// deterministically backoffDuration(n)*0.8 — exact assertions, no
	// tolerance window needed.
	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	wantBase := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, base := range wantBase {
		got := waiter.nextRequestedDuration(t, i)
		want := applyJitter(base, 0)
		if got != want {
			t.Errorf("attempt %d: requested backoff = %v, want %v (base %v with r=0 jitter)", i+1, got, want, base)
		}
		waiter.releaseNext(t) // let this (scripted) failed dial happen
	}
}

func TestReconnect_JitterAppliedToRequestedDuration(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(initial), failStep("dial 1")}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0.999999999}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	got := waiter.nextRequestedDuration(t, 0)
	if got < 1190*time.Millisecond || got > 1200*time.Millisecond {
		t.Errorf("requested backoff with r~1 jitter = %v, want ~1.2s (upper +20%% bound on a 1s base)", got)
	}
}

// --- max consecutive failures -> FAILED ---

func TestReconnect_TenConsecutiveFailures_TransitionsToFailed(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	steps := []func() (RealtimeConn, error){okStep(initial)}
	for i := 1; i <= maxConsecutiveFailures; i++ {
		steps = append(steps, failStep(fmt.Sprintf("dial %d", i)))
	}
	dialer := &scriptedConnDialer{steps: steps}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	for i := 0; i < maxConsecutiveFailures; i++ {
		waiter.nextRequestedDuration(t, i)
		waiter.releaseNext(t)
	}

	info := waitForState(t, rs, SessionFailed, 2*time.Second)
	if info.LastError == "" {
		t.Error("LastError must be set when reconnect gives up after max consecutive failures")
	}
	// No 11th Wait() call — the session must give up exactly at 10, never
	// keep retrying invisibly forever.
	if n := waiter.pendingCount(); n != maxConsecutiveFailures {
		t.Errorf("waiter received %d Wait() calls, want exactly %d (no 11th attempt after giving up)", n, maxConsecutiveFailures)
	}
	if _, ok := mgr.Get(rs.sess.ID); ok {
		t.Error("session still registered in Manager after max-consecutive-failures FAILED — registry leak")
	}
}

// --- stability reset ---

func TestReconnect_BriefConnection_DoesNotResetFailureStreak(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	afterFirstFail := newScriptedConn() // the reconnect that succeeds after 1 failure
	dialer := &scriptedConnDialer{
		steps: []func() (RealtimeConn, error){
			okStep(initial),
			failStep("first reconnect attempt fails"),
			okStep(afterFirstFail), // succeeds on 2nd reconnect attempt (streak becomes 1 going in)
			failStep("third dial — probing whether the streak reset"),
		},
	}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	// Attempt 1 (backoff 1s) fails.
	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)
	// Attempt 2 (backoff 2s, streak=1 going in) succeeds.
	got := waiter.nextRequestedDuration(t, 1)
	if want := applyJitter(backoffDuration(2), 0); got != want {
		t.Fatalf("attempt 2 backoff = %v, want %v", got, want)
	}
	waiter.releaseNext(t)
	waitForState(t, rs, SessionConnected, 2*time.Second)

	// Held CONNECTED for only 5s (<60s stability threshold) before dying
	// again.
	clock.Advance(5 * time.Second)
	afterFirstFail.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	// If the streak had reset, this would request backoffDuration(1)=1s.
	// Since the prior connection lasted <60s, streak must still be 1 ->
	// backoffDuration(2)=2s.
	got = waiter.nextRequestedDuration(t, 2)
	want := applyJitter(backoffDuration(2), 0)
	if got != want {
		t.Errorf("post-brief-connection backoff = %v, want %v (streak must NOT reset for a <60s connection)", got, want)
	}
}

func TestReconnect_StableConnection60s_ResetsStreakAndReconnectCount(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	afterFirstFail := newScriptedConn()
	dialer := &scriptedConnDialer{
		steps: []func() (RealtimeConn, error){
			okStep(initial),
			failStep("first reconnect attempt fails"),
			okStep(afterFirstFail),
			failStep("probing whether the streak reset"),
		},
	}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)
	waiter.nextRequestedDuration(t, 1)
	waiter.releaseNext(t)
	info := waitForState(t, rs, SessionConnected, 2*time.Second)
	if info.ReconnectCount != 1 {
		t.Fatalf("ReconnectCount = %d after first successful reconnect, want 1", info.ReconnectCount)
	}

	// Held CONNECTED for >=60s this time.
	clock.Advance(61 * time.Second)
	afterFirstFail.pushDisconnect()
	info = waitForState(t, rs, SessionReconnecting, 2*time.Second)
	if info.ReconnectCount != 0 {
		t.Errorf("ReconnectCount after a >=60s stable connection dropped = %d, want reset to 0 (§23.5 Reset)", info.ReconnectCount)
	}

	got := waiter.nextRequestedDuration(t, 2)
	want := applyJitter(backoffDuration(1), 0)
	if got != want {
		t.Errorf("post-stable-connection backoff = %v, want %v (streak must reset to attempt 1 after >=60s CONNECTED)", got, want)
	}
}

// --- cancellation during backoff ---

func TestReconnect_StopDuringShortBackoff_NoNextDial(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(initial), failStep("must never be called after Stop")}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	waiter.nextRequestedDuration(t, 0) // 1s backoff pending, never released

	stopped := make(chan struct{})
	go func() { rs.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return while a 1s backoff was pending — supervisor/reconnect did not unwind")
	}

	if got := rs.Info().State; got != SessionStopped {
		t.Errorf("State after Stop() during backoff = %q, want stopped", got)
	}
	if dialer.Calls() != 1 {
		t.Errorf("dialer.Calls() = %d, want exactly 1 (initial connect only) — no next dial after Stop() during backoff", dialer.Calls())
	}
}

func TestReconnect_StopDuringLongBackoff_NoNextDial(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	steps := []func() (RealtimeConn, error){okStep(initial)}
	for i := 1; i <= 6; i++ { // advance the streak to attempt 6 -> next backoff is 30s
		steps = append(steps, failStep(fmt.Sprintf("dial %d", i)))
	}
	steps = append(steps, failStep("must never be called after Stop"))
	dialer := &scriptedConnDialer{steps: steps}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)

	for i := 0; i < 5; i++ {
		waiter.nextRequestedDuration(t, i)
		waiter.releaseNext(t)
	}
	got := waiter.nextRequestedDuration(t, 5)
	if want := applyJitter(backoffDuration(6), 0); got != want {
		t.Fatalf("attempt 6 backoff = %v, want %v (30s cap)", got, want)
	}
	// This 30s wait is left pending — never released.

	stopped := make(chan struct{})
	go func() { rs.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return while a 30s backoff was pending")
	}
	if dialer.Calls() != 6 {
		t.Errorf("dialer.Calls() = %d, want exactly 6 (initial + 5 failed reconnects) — no 7th dial after Stop() during the 30s backoff", dialer.Calls())
	}
}

func TestReconnect_ParentCancelDuringBackoff_NoNextDial(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	initial := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(initial), failStep("must never be called after parent cancel")}}

	parentCtx, cancel := context.WithCancel(context.Background())
	rs := startRealtimeSessionFull(parentCtx, mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	initial.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	waiter.nextRequestedDuration(t, 0) // pending, never released

	cancel() // parent context canceled directly — rs.Stop() never called

	select {
	case <-rs.done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not terminate after parent context cancellation during backoff")
	}
	select {
	case <-rs.watcherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not terminate after parent context cancellation during backoff")
	}
	select {
	case <-rs.processorDone:
	case <-time.After(2 * time.Second):
		t.Fatal("processor did not terminate after parent context cancellation during backoff")
	}

	info := rs.Info()
	if info.State != SessionStopped {
		t.Errorf("State after parent cancel during backoff = %q, want stopped (never FAILED — not a datasource failure)", info.State)
	}
	if dialer.Calls() != 1 {
		t.Errorf("dialer.Calls() = %d, want exactly 1 — no next dial after parent cancellation during backoff", dialer.Calls())
	}
	if _, ok := mgr.Get(rs.sess.ID); ok {
		t.Error("session still registered in Manager after parent cancellation during backoff — registry leak")
	}
}

// --- stability reset observable at >=60s without waiting for the next
// disconnect (v1.2 Gate 3 P1-5 closure) ---

func TestReconnect_StabilityReset_ObservableAtSixtySeconds_WithoutDisconnect(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	first := newScriptedConn()
	second := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(first), okStep(second)}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)
	t.Cleanup(rs.Stop)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	first.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)
	info := waitForState(t, rs, SessionConnected, 2*time.Second)
	if info.ReconnectCount != 1 {
		t.Fatalf("ReconnectCount after first reconnect = %d, want 1", info.ReconnectCount)
	}

	clock.Advance(61 * time.Second)
	// No disconnect — the reset must be observable lazily via Info() while
	// still CONNECTED (v1.2 Gate 3 P1-5 closure), never only applied the
	// next time reconnect() happens to run.
	info = rs.Info()
	if info.State != SessionConnected {
		t.Fatalf("State = %q, want connected (advancing the clock alone must never disconnect)", info.State)
	}
	if info.ReconnectCount != 0 {
		t.Errorf("ReconnectCount = %d, want 0 — a >=60s-stable connection must reset it while still connected, not only at the next disconnect", info.ReconnectCount)
	}

	// Force a disconnect: the next backoff must be attempt 1 (failure
	// streak genuinely reset by the stability window), never a
	// continuation of any prior streak.
	second.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	// fakeWaiter.pending is cumulative across the session's whole
	// lifetime, never reset per reconnect cycle — the first reconnect
	// above already consumed Wait() call #0, so this second reconnect's
	// first backoff wait is call #1.
	got := waiter.nextRequestedDuration(t, 1)
	want := applyJitter(backoffDuration(1), 0)
	if got != want {
		t.Errorf("next backoff after a >=60s-stable disconnect = %v, want %v (attempt 1 — failure streak must be genuinely reset)", got, want)
	}
}

// --- no timer/goroutine leak across a full reconnect cycle ---

func TestReconnect_NoGoroutineLeak_AfterSuccessfulReconnectThenStop(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	clock := newFakeClock()
	waiter := newFakeWaiter()

	first := newScriptedConn()
	second := newScriptedConn()
	dialer := &scriptedConnDialer{steps: []func() (RealtimeConn, error){okStep(first), okStep(second)}}

	rs := startRealtimeSessionFull(context.Background(), mgr, client, "9.9.9.0/24", dialer, "ws://unused", clock, fixedJitter{0}, waiter)

	waitForState(t, rs, SessionConnected, 2*time.Second)
	first.pushDisconnect()
	waitForState(t, rs, SessionReconnecting, 2*time.Second)
	waiter.nextRequestedDuration(t, 0)
	waiter.releaseNext(t)
	waitForState(t, rs, SessionConnected, 2*time.Second)

	rs.Stop()

	// v1.2 Gate 3 P1-2 closure: Stop() now guarantees the supervisor has
	// joined BOTH child goroutines (watcher, processor — via
	// joinChildren(), see the defer-ordering comment in supervise()) BEFORE
	// closing rs.done. All three checks are therefore non-blocking
	// assertions valid immediately after Stop() returns — no bounded
	// timeout needed, unlike the older Gate 2-era pattern this replaces.
	select {
	case <-rs.done:
	default:
		t.Error("done channel not closed after Stop() — Stop() must not return before the supervisor confirms return")
	}
	select {
	case <-rs.watcherDone:
	default:
		t.Error("watcherDone channel not closed immediately after Stop() returned — Stop() must join the watcher goroutine, not just the supervisor (v1.2 Gate 3 P1-2)")
	}
	select {
	case <-rs.processorDone:
	default:
		t.Error("processorDone channel not closed immediately after Stop() returned — Stop() must join the processor goroutine, not just the supervisor (v1.2 Gate 3 P1-2)")
	}
	if _, ok := mgr.Get(rs.sess.ID); ok {
		t.Error("session still registered in Manager after Stop() following a reconnect cycle")
	}
}
