// Realtime session core for v1.2 (BGP_INTELLIGENCE_ROADMAP.md §23.2,
// §23.4, §23.5, §23.7). Owns the WebSocket connection to RIS Live, the
// session state machine, the bounded queue + backpressure (Gate 3), the
// full reconnect/backoff policy (Gate 3), and the supervisor goroutine.
// Reuses internal/session for SessionID/cancellation (never a parallel
// session mechanism) and the existing Client.RoutingStatusDetailedQuery /
// Client.RPKIValidateDetailed for IP->prefix resolution and RPKI
// validation (never a second implementation of either).
//
// Reader/processor split (§23.7, Gate 3): the WebSocket reader
// (readLoop) only reads frames, decodes them, and pushes onto the bounded
// queue (realtime_queue.go) — it never derives, never validates RPKI,
// never blocks on anything but the network read itself. A single
// processor goroutine (processLoop) drains the queue, derives
// path_changed/origin_changed/moas_*/rpki_transition (realtime_derive.go)
// and publishes to the session's existing *events.Bus. This is the seam
// Gate 2 deliberately left as a single well-defined boundary instead of
// ad-hoc logic.
package bgp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"trazip/internal/events"
	"trazip/internal/intel/external"
	"trazip/internal/session"
)

// RealtimeSessionState — estados públicos exactos (roadmap §23.2, v1.2
// P1-2 closure). Machine:
//
//	Start -> CONNECTING (classify + IP resolution + first WS dial)
//	CONNECTING   -> FAILED       (resolución falla de forma terminal, o el primer dial falla — nunca reintentado, Gate 2)
//	CONNECTING   -> CONNECTED    (primer intento WS conecta)
//	CONNECTED    -> RECONNECTING (conexión ya establecida se pierde)
//	RECONNECTING -> CONNECTED    (reconnect exitoso)
//	RECONNECTING -> FAILED       (10 fallos consecutivos, §23.5, Gate 3)
//	cualquier estado -> STOPPING -> STOPPED (Stop() explícito, o cancelación del context padre — Gate 2 final lifecycle closure)
type RealtimeSessionState string

const (
	SessionStopped      RealtimeSessionState = "stopped"
	SessionConnecting   RealtimeSessionState = "connecting"
	SessionConnected    RealtimeSessionState = "connected"
	SessionReconnecting RealtimeSessionState = "reconnecting"
	SessionStopping     RealtimeSessionState = "stopping"
	SessionFailed       RealtimeSessionState = "failed"
)

// RealtimeSessionInfo — estado público completo de una sesión (roadmap
// §23.2). QueueDroppedEvents y TransportDroppedEvents son ambos reales
// desde Gate 3: capa 1 (cola BGP acotada, §23.4) y capa 2 (sess.Bus.Dropped(),
// infraestructura ya existente) respectivamente — nunca fabricados,
// nunca double-counted entre sí.
type RealtimeSessionInfo struct {
	SessionID              string
	Resource               string
	ResourceKind           ResourceKind
	ResolvedPrefix         string
	StartedAt              string
	State                  RealtimeSessionState
	LastEventAt            string
	ReceivedEvents         int64
	QueueDroppedEvents     int64
	TransportDroppedEvents int64
	DroppedEventsTotal     int64
	ReconnectCount         int
	LastError              string
	Disclosure             external.Disclosure
	// DerivedStateEvictions is the total number of LRU evictions across
	// the bounded per-session derived-event trackers (per-peer
	// path/origin snapshots, per-ASN RPKI baselines — realtime_derive.go)
	// since the session started (v1.2 Gate 3 P1-4 closure). Always 0 for
	// a session that never exceeded maxTrackedPeers/maxTrackedASNs
	// distinct entries. A non-zero value means TRAZIP has lost track of
	// some peer/ASN state to stay memory-bounded — MOAS/path/origin/RPKI
	// derived events computed afterward may be based on incomplete
	// cross-peer visibility. Never silent: exposed here so that
	// degradation is transparent instead of presenting derived events as
	// if they reflected complete state.
	DerivedStateEvictions int64
}

const (
	risLiveDefaultURL  = "wss://ris-live.ripe.net/v1/ws/"
	risLiveClientQuery = "client=trazip"
)

// RealtimeConn is the minimal WebSocket surface realtime.go needs.
// *websocket.Conn satisfies it directly — this exists so tests can point
// at a fully scripted fake instead of only real TCP servers when needed.
type RealtimeConn interface {
	WriteJSON(v any) error
	ReadMessage() (messageType int, p []byte, err error)
	Close() error
	SetReadDeadline(t time.Time) error
}

// RealtimeDialer abstracts the WebSocket dial so tests never touch the
// Internet — they inject a dialer pointed at a local httptest server.
type RealtimeDialer interface {
	DialContext(ctx context.Context, url string, header http.Header) (RealtimeConn, error)
}

type gorillaDialer struct{}

func (gorillaDialer) DialContext(ctx context.Context, u string, header http.Header) (RealtimeConn, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u, header)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// risSubscribeMessage/risSubscribeData — mensaje ris_subscribe exacto del
// roadmap §23.1 A. Siempre filtrado por prefix (ResolvedPrefix); nunca
// vacío, nunca firehose.
type risSubscribeMessage struct {
	Type string           `json:"type"`
	Data risSubscribeData `json:"data"`
}

type risSubscribeData struct {
	Type          string               `json:"type"` // "UPDATE" — solo mensajes UPDATE, nunca OPEN/NOTIFICATION/KEEPALIVE/RIS_PEER_STATE
	Prefix        string               `json:"prefix"`
	MoreSpecific  bool                 `json:"moreSpecific"`
	SocketOptions risSocketOptionsData `json:"socketOptions"`
}

type risSocketOptionsData struct {
	IncludeRaw  bool `json:"includeRaw"`
	Acknowledge bool `json:"acknowledge"`
}

// RealtimeSession is a single live (or terminated) v1.2 realtime session.
type RealtimeSession struct {
	sess    *session.Session
	mgr     *session.Manager // ver terminate() — nunca un registry paralelo (v1.2 P1-2 closure)
	client  *Client
	dialer  RealtimeDialer
	baseURL string

	clock   Clock           // inyectable — rate-limit window (realtime_queue.go) y stability-reset (§23.5)
	jitter  JitterSource    // inyectable — ±20% jitter de backoff, nunca math/rand global (§23.5)
	waiter  reconnectWaiter // inyectable — espera de backoff cancelable vía ctx, nunca time.Sleep real
	queue   *realtimeQueue  // cola acotada capa 1 (§23.4) entre el reader y el processor
	derived *derivedState   // estado de derivación bounded por sesión (path/origin/MOAS/RPKI, realtime_derive.go)

	resource     string
	resourceKind ResourceKind

	mu             sync.RWMutex
	resolvedPrefix string
	state          RealtimeSessionState
	startedAt      string
	lastEventAt    string
	receivedEvents int64
	reconnectCount int
	failureStreak  int // fallos consecutivos de reconexión sin éxito intermedio (§23.5); reseteado por Stop/éxito no aplica aquí — solo por stability reset
	connectedSince time.Time
	lastError      string

	// connMu/conn track the currently active WebSocket connection so Stop()
	// can interrupt a blocking ReadMessage() — canceling ctx alone does
	// NOT unblock an in-progress read on an already-established
	// gorilla/websocket connection (only DialContext is context-aware).
	// The watcher goroutine started in supervise() closes whatever conn is
	// current the moment ctx is canceled (§23.5 "Cancelar el context...
	// interrumpe cualquier lectura del WebSocket en curso"). Every
	// reconnect installs the new conn here and closes the previous one
	// explicitly in readLoop before retrying (§23.7 "conexión anterior
	// cerrada/no reutilizada") — rs.conn always points at, at most, one
	// live connection.
	connMu sync.Mutex
	conn   RealtimeConn

	// normalized is the canonical form ClassifyResource returned for
	// resource (a normalized prefix, or the /32 or /128 an IP will resolve
	// through). Stored so Run() (v1.2 Gate 5 two-phase construction) can
	// launch supervise() with the exact same value newRealtimeSession's own
	// single-phase switch would have used — never recomputed, never
	// allowed to drift from what PrepareRealtimeSession already classified.
	normalized string

	terminateOnce sync.Once // ver terminate() — evita double-cancel/double-remove races (v1.2 P1-2 closure)

	// onTerminate, si no-nil, se invoca exactamente una vez desde dentro
	// de terminate() (mismo terminateOnce que protege la limpieza del
	// Manager) — v1.2 Gate 5 "REALTIME OWNERSHIP" bridge seam. Permite que
	// un índice SessionID -> *RealtimeSession mantenido por un caller
	// (api.Service.bgpSessions) se auto-limpie de forma determinista
	// cuando la sesión termina por CUALQUIER razón (Stop() explícito,
	// fail() por datasource/RIS_ERROR/reconexión agotada, o cancelación
	// externa del context padre) sin convertirse en una segunda autoridad
	// de lifecycle: session.Manager sigue siendo la única fuente de
	// verdad — este hook solo reacciona a lo que YA decidió, nunca decide
	// nada por su cuenta. Recibe el SessionID (nunca el propio *rs, para
	// evitar que el caller cierre sobre una variable que podría no estar
	// asignada todavía si terminate() corre síncronamente durante la
	// construcción — ver newRealtimeSession, caso KindASN/KindInvalid).
	onTerminate func(sessionID string)

	done          chan struct{} // cerrado cuando la goroutine supervisora retorna
	watcherDone   chan struct{} // cerrado cuando el watcher goroutine (ver supervise()) retorna — prueba determinista de que ninguna goroutine de RealtimeSession sobrevive a una terminación terminal, incluso sin Stop() explícito (v1.2 P1-1 closure)
	processorDone chan struct{} // cerrado cuando el processor goroutine (drena la cola, deriva, publica) retorna — mismo criterio de no-leak que watcherDone (Gate 3)
}

// terminate remueve la sesión interna del Manager exactamente una vez,
// sin importar cuántas veces (o desde cuántas goroutines/callers) se
// invoque — evita las carreras double-cancel/double-remove entre un
// Stop() del usuario, una terminación de fallo, y el defer catch-all de
// supervise() (v1.2 P1-2 closure, extendido por el cierre de "parent
// context cancellation cleanup"). Tres llamadores posibles, en cualquier
// orden, colapsados por terminateOnce a una sola ejecución real:
//   - Stop() explícito → terminate(true)
//   - fail() (terminación de trabajo, exitosa o fallida) → terminate(false)
//   - el defer al final de supervise() → terminate(true), catch-all que
//     solo tiene efecto real cuando NINGUNO de los dos anteriores corrió
//     (el context PADRE se canceló externamente sin Stop() ni fail())
//
// userInitiated distingue la semántica reutilizando los mecanismos
// existentes del Manager (nunca un registry paralelo): true → mgr.Cancel
// (session.State → Canceled); false → mgr.Complete (session.State →
// Finished). Todos los casos SIEMPRE quitan la sesión del registro vivo
// del Manager y cancelan su context — lo cual, como efecto colateral
// necesario, es también lo que garantiza que el watcher goroutine de
// supervise() (bloqueado en ctx.Done()) termine incluso cuando nadie
// llamó Stop() (v1.2 P1-1 closure).
func (rs *RealtimeSession) terminate(userInitiated bool) {
	rs.terminateOnce.Do(func() {
		if userInitiated {
			rs.mgr.Cancel(rs.sess.ID)
		} else {
			rs.mgr.Complete(rs.sess.ID)
		}
		if rs.onTerminate != nil {
			rs.onTerminate(rs.sess.ID)
		}
	})
}

// Session returns the underlying *session.Session — a Go-only accessor,
// never meant to be called from a Wails-bound method (v1.2 Gate 5: a raw
// *session.Session can never be a Wails-bound method's return type, so
// api.BGPRealtimeStart — itself never Wails-bound, see its own doc
// comment — is the only intended caller, handing it up to app.go so
// App.BGPRealtimeStart can bridge its Bus to Wails exactly once, the same
// way every other streaming feature in app.go already does).
func (rs *RealtimeSession) Session() *session.Session { return rs.sess }

func (rs *RealtimeSession) setActiveConn(conn RealtimeConn) {
	rs.connMu.Lock()
	rs.conn = conn
	rs.connMu.Unlock()
}

// joinChildren blocks until both the watcher and processor goroutines
// (launched in supervise()) have confirmed their own return via
// watcherDone/processorDone — never a sleep, never a timeout. Only called
// from supervise()'s own defer chain, AFTER terminate() has run (see the
// defer ordering comment in supervise()), so this can never deadlock: by
// that point rs.sess.Context() is guaranteed canceled, and both goroutines
// select on exactly that ctx.Done() to return promptly (v1.2 Gate 3 P1-2
// closure — this is what makes Stop() a true join point, not just a wait
// on the supervisor's own return).
func (rs *RealtimeSession) joinChildren() {
	<-rs.watcherDone
	<-rs.processorDone
}

func (rs *RealtimeSession) closeActiveConn() {
	rs.connMu.Lock()
	conn := rs.conn
	rs.connMu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// StartRealtimeSession begins a v1.2 realtime BGP session for resource.
// This call IS the explicit user action the roadmap requires — TRAZIP
// never auto-connects on its own (§23.2). mgr/client are reused, never a
// parallel session/HTTP mechanism. onTerminate is the Gate 5 bridge seam
// (see the RealtimeSession.onTerminate field doc comment) — pass nil when
// no caller-side index needs to track this session's lifecycle.
func StartRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, onTerminate func(sessionID string)) *RealtimeSession {
	return newRealtimeSession(ctx, mgr, client, resource, gorillaDialer{}, risLiveDefaultURL, realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, onTerminate)
}

// StartRealtimeSessionWithDialer is StartRealtimeSession with an
// injectable WebSocket dialer/baseURL — exported specifically so
// internal/api's own Gate 5 tests (Service.BGPRealtimeStart/Stop wiring)
// can exercise the full resolve->dial->bridge-ready path against a local
// fake WebSocket server instead of the real RIS Live endpoint. Production
// code always goes through StartRealtimeSession instead, which is the
// only constructor that ever uses the real dialer/URL.
func StartRealtimeSessionWithDialer(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, onTerminate func(sessionID string)) *RealtimeSession {
	return newRealtimeSession(ctx, mgr, client, resource, dialer, baseURL, realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, onTerminate)
}

// startRealtimeSession is the dialer/URL-injectable core used directly by
// Gate 2's tests against a local fake WebSocket server — zero Internet in
// go test. Preserved with its original signature so every existing Gate 2
// test keeps compiling/passing unmodified; it uses production
// clock/jitter/waiter/queue-limits (irrelevant to what those tests
// assert) and no onTerminate hook (irrelevant to Gate 2/3's own tests —
// only Gate 5's API layer needs it).
func startRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string) *RealtimeSession {
	return newRealtimeSession(ctx, mgr, client, resource, dialer, baseURL, realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, nil)
}

// startRealtimeSessionFull is the fully-injectable constructor Gate 3's
// queue/rate-limit/reconnect/backoff/derived-event tests use to control
// time and randomness deterministically — never a real sleep, never
// non-deterministic jitter in a test assertion. Uses the production queue
// limits (MaxQueueSize/MaxEventsPerWindow/RateWindow); see
// startRealtimeSessionWithQueueLimits for tests that need to override
// those independently.
func startRealtimeSessionFull(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, clock Clock, jitter JitterSource, waiter reconnectWaiter) *RealtimeSession {
	return newRealtimeSession(ctx, mgr, client, resource, dialer, baseURL, clock, jitter, waiter, MaxQueueSize, MaxEventsPerWindow, RateWindow, nil)
}

// startRealtimeSessionWithQueueLimits is a Gate 3 test-only constructor
// that lets a test override the BGP realtime queue's capacity/rate-cap
// independently of the frozen production constants (MaxQueueSize/
// MaxEventsPerWindow/RateWindow) — used specifically to exercise ONE
// backpressure condition (capacity or rate) end-to-end without the other
// tripping first and masking it. In production the rate cap (200/10s) is
// always far below capacity (500) and therefore always wins any realistic
// burst — an end-to-end test using the real constants can only ever
// exercise the rate cap, never true capacity drop-oldest (v1.2 Gate 3 P2
// closure).
func startRealtimeSessionWithQueueLimits(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, maxSize, rateMax int, rateWindow time.Duration) *RealtimeSession {
	return newRealtimeSession(ctx, mgr, client, resource, dialer, baseURL, realClock{}, newRealJitterSource(), realWaiter{}, maxSize, rateMax, rateWindow, nil)
}

func newRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, clock Clock, jitter JitterSource, waiter reconnectWaiter, queueMaxSize, queueRateMax int, queueRateWindow time.Duration, onTerminate func(sessionID string)) *RealtimeSession {
	kind, normalized := ClassifyResource(resource)
	rs := newUnstartedRealtimeSession(ctx, mgr, client, resource, kind, normalized, dialer, baseURL, clock, jitter, waiter, queueMaxSize, queueRateMax, queueRateWindow, onTerminate)

	switch kind {
	case KindPrefix4, KindPrefix6, KindIPv4, KindIPv6:
		go rs.supervise(normalized)
	default:
		// KindASN: fuera de alcance v1.2 (§23.2 — realtime solo IP/prefix
		// en esta fase). KindInvalid: recurso no reconocido. Ninguno de
		// los dos abre el WebSocket — cero intentos de red, y ningún
		// goroutine (watcher/processor) llega a lanzarse (se cierran sus
		// channels done de inmediato para que nada quede esperándolos).
		reason := unsupportedResourceReason(kind, resource)
		rs.fail(reason)
		close(rs.watcherDone)
		close(rs.processorDone)
		close(rs.done)
	}
	return rs
}

// newUnstartedRealtimeSession builds every field a RealtimeSession needs
// (registers sess in mgr, allocates the queue/derived-state, wires
// onTerminate) WITHOUT deciding what happens next — no goroutine, no
// dial, no fail() call, zero events possible yet. Both newRealtimeSession
// (single-phase: launches or fails synchronously right after this
// returns, v1.2 Gate 2/3, unchanged) and PrepareRealtimeSession
// (two-phase: caller installs a Bus subscriber, then calls Run() itself,
// v1.2 Gate 5 P1-2/P1-3 closure) share this exact construction so neither
// path can ever diverge in what a RealtimeSession looks like before it
// starts doing anything.
func newUnstartedRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, kind ResourceKind, normalized string, dialer RealtimeDialer, baseURL string, clock Clock, jitter JitterSource, waiter reconnectWaiter, queueMaxSize, queueRateMax int, queueRateWindow time.Duration, onTerminate func(sessionID string)) *RealtimeSession {
	sess := mgr.New(ctx, "bgp-realtime")
	return &RealtimeSession{
		sess:          sess,
		mgr:           mgr,
		client:        client,
		dialer:        dialer,
		baseURL:       baseURL,
		clock:         clock,
		jitter:        jitter,
		waiter:        waiter,
		queue:         newRealtimeQueue(clock, queueMaxSize, queueRateMax, queueRateWindow),
		derived:       newDerivedState(),
		resource:      resource,
		resourceKind:  kind,
		normalized:    normalized,
		state:         SessionConnecting,
		startedAt:     external.Now(),
		done:          make(chan struct{}),
		watcherDone:   make(chan struct{}),
		processorDone: make(chan struct{}),
		onTerminate:   onTerminate, // set BEFORE any caller can launch/fail — KindASN/KindInvalid's synchronous rs.fail() (single-phase path) must see this already populated
	}
}

func unsupportedResourceReason(kind ResourceKind, resource string) string {
	if kind == KindInvalid {
		return fmt.Sprintf("recurso inválido: %q", resource)
	}
	return fmt.Sprintf("tipo de recurso %q no soportado para realtime v1.2 (solo IP/prefix)", kind)
}

// PrepareRealtimeSession validates resource locally (v1.2 Gate 5 P1-1
// closure) and, when it's realtime-eligible (IP or prefix — ASN is out of
// scope for v1.2, §23.2), constructs but does NOT start the session:
// session.Manager already has an entry (so a caller-side lookup, e.g.
// api.Service.bgpSessions, can be populated race-free before anything can
// self-terminate — v1.2 P1-3 closure), but zero network I/O, zero events,
// and zero goroutines have happened yet. Run() is what actually
// dials/reads/derives/publishes. A caller is expected to install its own
// events.Bus subscriber (the Wails bridge, in api/app.go's case) between
// PrepareRealtimeSession and Run() — events.Bus has no replay, so a
// subscriber installed any later could miss the very first event (v1.2
// P1-2 closure).
//
// KindASN/KindInvalid return (nil, error) WITHOUT ever calling mgr.New —
// no session.Manager entry, no onTerminate call, nothing for any caller
// to track, look up, or clean up. This is the one behavioral difference
// from the single-phase newRealtimeSession/StartRealtimeSession family
// (which still construct-then-immediately-fail a session for these kinds,
// v1.2 Gate 2/3, deliberately left unchanged): a Wails-facing Start must
// be able to say "no session was created" instead of "a session was
// created and immediately failed" (v1.2 Gate 5, api.BGPRealtimeStart).
func PrepareRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, onTerminate func(sessionID string)) (*RealtimeSession, error) {
	return prepareRealtimeSession(ctx, mgr, client, resource, gorillaDialer{}, risLiveDefaultURL, onTerminate)
}

// PrepareRealtimeSessionWithDialer is PrepareRealtimeSession with an
// injectable WebSocket dialer/baseURL — exported specifically for Gate 5
// tests (internal/api's own Service.BGPRealtimeStart wiring), same reason
// StartRealtimeSessionWithDialer exists (see its own doc comment).
// Production code always goes through PrepareRealtimeSession instead.
func PrepareRealtimeSessionWithDialer(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, onTerminate func(sessionID string)) (*RealtimeSession, error) {
	return prepareRealtimeSession(ctx, mgr, client, resource, dialer, baseURL, onTerminate)
}

func prepareRealtimeSession(ctx context.Context, mgr *session.Manager, client *Client, resource string, dialer RealtimeDialer, baseURL string, onTerminate func(sessionID string)) (*RealtimeSession, error) {
	kind, normalized := ClassifyResource(resource)
	switch kind {
	case KindPrefix4, KindPrefix6, KindIPv4, KindIPv6:
	default:
		// Rejected before mgr.New is ever called — see this function's own
		// doc comment for why this differs from the single-phase family.
		return nil, errors.New(unsupportedResourceReason(kind, resource))
	}
	rs := newUnstartedRealtimeSession(ctx, mgr, client, resource, kind, normalized, dialer, baseURL, realClock{}, newRealJitterSource(), realWaiter{}, MaxQueueSize, MaxEventsPerWindow, RateWindow, onTerminate)
	return rs, nil
}

// Run starts the supervisor goroutine (dial/read/derive/publish) for a
// RealtimeSession built via PrepareRealtimeSession/
// PrepareRealtimeSessionWithDialer. Must be called at most once, and only
// after any Bus subscriber the caller needs is already installed (v1.2
// Gate 5 P1-2 closure — see PrepareRealtimeSession's own doc comment). A
// RealtimeSession returned by any other constructor (StartRealtimeSession,
// StartRealtimeSessionWithDialer, or the unexported single-phase
// newRealtimeSession family) has already launched its own goroutine —
// never call Run() on one of those.
func (rs *RealtimeSession) Run() {
	go rs.supervise(rs.normalized)
}

func (rs *RealtimeSession) supervise(normalized string) {
	// Orden de ejecución de estos tres defers (LIFO — el ÚLTIMO defer
	// registrado corre PRIMERO): terminate() -> joinChildren() ->
	// close(rs.done). Ese orden es el contrato de Stop()/cleanup completo
	// (v1.2 Gate 3 P1-2 closure):
	//   1. terminate(true) cancela rs.sess.Context() (ver comentario
	//      completo más abajo) — esto es lo que desbloquea al watcher
	//      (bloqueado en ctx.Done()) y al processor (select en ctx.Done())
	//      si todavía no habían terminado por su cuenta.
	//   2. joinChildren() bloquea hasta que AMBOS — watcherDone y
	//      processorDone — se hayan cerrado. Nunca puede colgarse: para
	//      cuando esta línea corre, ctx YA está cancelado (garantizado por
	//      el paso 1, sin importar si Stop()/fail() lo cancelaron antes o
	//      si esta es la primera vez que corre — sync.Once bloquea a
	//      cualquier llamador concurrente hasta que la cancelación real ya
	//      ocurrió), así que ambas goroutines child están garantizadas a
	//      terminar prontamente (el processor puede estar dentro de
	//      RPKIValidateDetailed(ctx,...), que también respeta ctx —
	//      verificado en rpki_detailed_test.go).
	//   3. close(rs.done) — SOLO ahora, con watcher y processor YA
	//      terminados. Esto es lo que hace que Stop() (que solo espera
	//      <-rs.done) sea un verdadero join point: cuando Stop() retorna,
	//      NINGUNA goroutine propia de RealtimeSession sigue viva. Antes
	//      de este fix, Stop() solo esperaba al supervisor —
	//      watcherDone/processorDone podían cerrarse un tiempo DESPUÉS de
	//      que Stop() ya había retornado.
	defer close(rs.done)
	defer rs.joinChildren()
	// Ownership centralizado del cleanup del Manager (v1.2 "parent context
	// cancellation cleanup" closure). Antes de ese fix, cada punto de
	// salida que detectaba ctx.Err()!=nil solo hacía
	// setState(SessionStopped) + return — correcto para el estado público,
	// pero si nadie había llamado Stop() ni fail() (p.ej. el context PADRE
	// pasado a StartRealtimeSession se cancela externamente, sin que el
	// dueño de la sesión invoque Stop()), terminate() nunca corría: la
	// sesión interna quedaba en session.StateActive y seguía registrada en
	// el Manager para siempre. Este defer garantiza que TODA salida de
	// supervise() — sin importar la razón — pase por terminate() al menos
	// una vez. terminateOnce (sync.Once) colapsa esta llamada en un no-op
	// cuando Stop() o fail() ya lo invocaron antes, así que nunca hay
	// double-cancel/double-remove ni se pisa la semántica de fail()
	// (mgr.Complete → Finished/FAILED). Cuando esta es la ÚNICA llamada
	// (cancelación externa pura del padre, sin Stop() ni fail()), usa
	// exactamente la misma semántica que Stop() (mgr.Cancel → Canceled) —
	// el estado público sigue siendo STOPPED, nunca FAILED, porque ningún
	// código de este defer toca rs.state: cancelación externa del padre no
	// es un fallo del datasource.
	defer rs.terminate(true)

	ctx := rs.sess.Context()

	// Cancelar ctx no interrumpe por sí solo un ReadMessage() ya bloqueado
	// en una conexión establecida (gorilla/websocket solo hace DialContext
	// context-aware, no los reads posteriores) — este watcher cierra la
	// conexión activa en cuanto ctx se cancela, exactamente el paso 1 de
	// la secuencia de Stop() en §23.5 ("interrumpe cualquier lectura del
	// WebSocket en curso"). ctx se cancela tanto por un Stop() explícito
	// como por CUALQUIER terminación de fallo vía fail()->terminate()
	// (v1.2 P1-2 closure) — así que este watcher SIEMPRE termina cuando la
	// sesión termina, incluso si nadie llamó Stop() (v1.2 P1-1 closure):
	// ya no puede quedar huérfano esperando un ctx que nunca se cancela.
	go func() {
		defer close(rs.watcherDone)
		<-ctx.Done()
		rs.closeActiveConn()
	}()

	// Processor goroutine — drena la cola acotada (capa 1, §23.4), deriva
	// path_changed/origin_changed/moas_*/rpki_transition
	// (realtime_derive.go) y publica al bus existente. Lanzado
	// incondicionalmente aquí (igual que el watcher), no solo tras
	// conectar: la cola/processor viven y mueren con la SESIÓN, no con una
	// conexión WS individual, así que sobreviven intactos a través de
	// reconexiones. Bounded y cancelable exactamente como el watcher —
	// nunca huérfano tras una terminación terminal, con o sin Stop()
	// explícito (mismo ctx compartido).
	go func() {
		defer close(rs.processorDone)
		rs.processLoop(ctx)
	}()

	resolvedPrefix, ok := rs.resolvePrefix(ctx, normalized)
	if !ok {
		return
	}
	rs.setResolvedPrefix(resolvedPrefix)

	conn, err := rs.dial(ctx, resolvedPrefix)
	if err != nil {
		if ctx.Err() != nil {
			rs.setState(SessionStopped)
			return
		}
		rs.fail("conexión WebSocket falló: " + err.Error())
		return
	}
	rs.setActiveConn(conn)
	if ctx.Err() != nil {
		// Stop() ganó la carrera justo después del dial — cerrar de
		// inmediato en vez de dejar la conexión abierta sin lector.
		conn.Close()
		rs.setState(SessionStopped)
		return
	}
	rs.markConnected()

	rs.readLoop(ctx, conn, resolvedPrefix)
}

// markConnected transiciona a SessionConnected y registra el instante
// exacto (vía el clock inyectable) usado por el stability-reset del
// reconnect (§23.5: una conexión que se mantiene CONNECTED >=60s resetea
// el failure streak / backoff / ReconnectCount la PRÓXIMA vez que se
// pierda). Llamado tanto en el primer connect como en cada reconnect
// exitoso.
func (rs *RealtimeSession) markConnected() {
	rs.mu.Lock()
	rs.state = SessionConnected
	rs.connectedSince = rs.clock.Now()
	rs.mu.Unlock()
}

// resolvePrefix implementa la resolución IP->prefijo del roadmap §23.2.
// Nunca abre el WebSocket si esto falla; nunca fabrica /32 o /128.
func (rs *RealtimeSession) resolvePrefix(ctx context.Context, normalized string) (string, bool) {
	switch rs.resourceKind {
	case KindPrefix4, KindPrefix6:
		return normalized, true
	case KindIPv4, KindIPv6:
		result := rs.client.RoutingStatusDetailedQuery(ctx, normalized)
		if ctx.Err() != nil {
			// Stop() ganó la carrera durante la resolución — cancelación
			// del usuario, no un fallo de resolución.
			rs.setState(SessionStopped)
			return "", false
		}
		if result.Err != "" || !result.Announced || result.Prefix == "" {
			reason := "recurso no anunciado, sin prefijo BGP que monitorear"
			if result.Err != "" {
				reason = result.Err
			}
			rs.fail(reason)
			return "", false
		}
		return result.Prefix, true
	default:
		rs.fail(fmt.Sprintf("tipo de recurso %q no soportado para realtime v1.2 (solo IP/prefix)", rs.resourceKind))
		return "", false
	}
}

func (rs *RealtimeSession) dial(ctx context.Context, resolvedPrefix string) (RealtimeConn, error) {
	u := rs.baseURL
	if strings.Contains(u, "?") {
		u += "&" + risLiveClientQuery
	} else {
		u += "?" + risLiveClientQuery
	}
	conn, err := rs.dialer.DialContext(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	sub := risSubscribeMessage{
		Type: "ris_subscribe",
		Data: risSubscribeData{
			Type:         "UPDATE",
			Prefix:       resolvedPrefix,
			MoreSpecific: false,
		},
	}
	if err := conn.WriteJSON(sub); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (rs *RealtimeSession) readLoop(ctx context.Context, conn RealtimeConn, resolvedPrefix string) {
	for {
		if ctx.Err() != nil {
			rs.setState(SessionStopped)
			return
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				rs.setState(SessionStopped)
				return
			}
			// Conexión perdida tras haber estado CONNECTED — cerrar
			// explícitamente la conexión rota antes de reintentar (§23.7:
			// "conexión anterior cerrada/no reutilizada"; nunca dejarla
			// abierta sin lector).
			conn.Close()
			newConn, ok := rs.reconnect(ctx, resolvedPrefix)
			if !ok {
				// reconnect() ya dejó la sesión en su estado terminal
				// correcto (Stopped por cancelación, o Failed por 10
				// fallos consecutivos) y ya limpió el Manager vía
				// fail()/terminate() — nada más que hacer aquí.
				return
			}
			conn = newConn
			continue
		}

		evs, decodeErr := DecodeRISMessage(rs.resource, raw)
		if decodeErr != nil {
			var risErr *RISFrameError
			if errors.As(decodeErr, &risErr) {
				// ris_error es un frame de protocolo real de RIPE — nunca
				// se ignora silenciosamente ni se confunde con JSON
				// malformado. Política conservadora: siempre observable
				// en LastError y siempre termina la sesión en FAILED,
				// nunca queda Connected como si nada hubiera pasado (v1.2
				// P1-3 / RIS_ERROR closure).
				rs.fail(decodeErr.Error())
				return
			}
			// Frame malformado, o ris_message con campos de wire inválidos
			// (peer_asn/timestamp/id) — nunca panic, nunca evento
			// fabricado; se descarta y la sesión sigue leyendo el
			// siguiente frame (v1.2 P1-3 closure).
			continue
		}
		resolved := rs.getResolvedPrefix()
		for _, ev := range evs {
			// v1.2 Gate 3 P1-1 closure: RIS Live's `prefix` subscribe
			// filter is not a guarantee that every event in an UPDATE
			// message refers to exactly ResolvedPrefix — a single wire
			// message can legitimately carry multiple announced/withdrawn
			// prefixes. TRAZIP never trusts the server to have pruned the
			// payload down to exactly what was subscribed; every event is
			// re-checked here by exact canonical CIDR match
			// (prefixMatchesResolved, realtime_event.go) before it can
			// enter the queue, trigger derivation/RPKI, or reach the Bus.
			// A mismatched prefix is silently dropped at this boundary —
			// never enqueued (so ReceivedEvents, incremented only inside
			// enqueue(), is never touched for it either). The event's
			// original wire-derived ID/ordinal is never renumbered —
			// filtering happens strictly after decode, untouched.
			if !prefixMatchesResolved(ev.Prefix, resolved) {
				continue
			}
			rs.enqueue(ev)
		}
	}
}

// reconnect implementa el contrato completo de §23.5: backoff exponencial
// con jitter ±20%, tope de 10 fallos consecutivos sin éxito intermedio,
// reset de estabilidad tras >=60s CONNECTED, y cancelación inmediata del
// timer de espera vía ctx (Stop() explícito o cancelación del context
// padre — Gate 2 final lifecycle closure, extendido aquí explícitamente a
// backoff: una frase antigua del roadmap decía "únicamente Stop", pero el
// lifecycle ya cerrado en Gate 2 trata la cancelación del padre igual que
// Stop en todo punto de la sesión, incluido mientras se espera un
// backoff).
//
// Devuelve (conn, true) en éxito — el caller continúa su readLoop con la
// nueva conexión. Devuelve (nil, false) cuando la sesión terminó: el
// estado terminal correcto (Stopped o Failed) y la limpieza del Manager ya
// quedaron hechos aquí mismo (vía setState/fail, exactamente como todo
// otro camino terminal de este archivo) — el caller simplemente retorna.
func (rs *RealtimeSession) reconnect(ctx context.Context, resolvedPrefix string) (RealtimeConn, bool) {
	// Stability reset (§23.5 "Reset") — ver maybeApplyStabilityReset: si la
	// conexión que se acaba de perder se mantuvo CONNECTED >=60s, el
	// failure streak (y por tanto el backoff/ReconnectCount) vuelve a 0
	// antes de calcular el intento de este ciclo.
	rs.maybeApplyStabilityReset()
	rs.setState(SessionReconnecting)

	for {
		streak := rs.getFailureStreak()
		if streak >= maxConsecutiveFailures {
			rs.fail(fmt.Sprintf("reconexión falló %d veces consecutivas sin éxito intermedio — se detiene el reintento automático (§23.5)", streak))
			return nil, false
		}

		base := backoffDuration(streak + 1)
		wait := applyJitter(base, rs.jitter.Float64())
		if !rs.waiter.Wait(ctx, wait) {
			// ctx cancelado (Stop() o cancelación del padre) mientras se
			// esperaba el backoff — nunca el próximo dial.
			rs.setState(SessionStopped)
			return nil, false
		}
		if ctx.Err() != nil {
			rs.setState(SessionStopped)
			return nil, false
		}

		newConn, dialErr := rs.dial(ctx, resolvedPrefix)
		if dialErr != nil {
			if ctx.Err() != nil {
				rs.setState(SessionStopped)
				return nil, false
			}
			rs.incrementFailureStreak()
			rs.setLastError("reconexión falló: " + dialErr.Error())
			continue // sigue en RECONNECTING, próximo intento con backoff incrementado
		}

		rs.setActiveConn(newConn)
		if ctx.Err() != nil {
			// Stop()/cancelación ganó la carrera justo después del dial.
			newConn.Close()
			rs.setState(SessionStopped)
			return nil, false
		}
		rs.incrementReconnect()
		rs.markConnected()
		return newConn, true
	}
}

// enqueue empuja un source event a la cola acotada (capa 1, §23.4). Nunca
// bloquea el reader. ReceivedEvents/LastEventAt se incrementan aquí — en
// el momento de ACEPTACIÓN en la cola BGP, exactamente la semántica
// congelada en el roadmap §23.2 ("eventos aceptados en la cola BGP...
// antes de cualquier publish al bus de transporte") — nunca en el
// processor, para que el contador refleje ingestión, no derivación/publish
// asíncronos. Un evento rechazado por backpressure (capacity o rate) no
// incrementa nada aquí — solo rs.queue.Dropped() (expuesto vía Info() como
// QueueDroppedEvents).
func (rs *RealtimeSession) enqueue(ev BGPRealtimeEvent) {
	if !rs.queue.Push(ev) {
		return
	}
	rs.mu.Lock()
	rs.receivedEvents++
	rs.lastEventAt = external.Now()
	rs.mu.Unlock()
}

// processLoop drena la cola y procesa un evento a la vez — 1 processor por
// sesión, nunca un worker pool ilimitado (§23.7). Termina en cuanto ctx se
// cancela, SIN drenar lo que quede pendiente (roadmap §23.4: "no hay
// 'drenar la cola antes de cerrar'").
func (rs *RealtimeSession) processLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-rs.queue.Notify():
		}
		for {
			if ctx.Err() != nil {
				return
			}
			ev, ok := rs.queue.Pop()
			if !ok {
				break
			}
			rs.processEvent(ctx, ev)
		}
	}
}

// processEvent publica el evento fuente y cualquier evento derivado que
// realtime_derive.go produzca a partir de él — nunca duplica el hecho del
// evento fuente (roadmap §23.3).
func (rs *RealtimeSession) processEvent(ctx context.Context, ev BGPRealtimeEvent) {
	rs.publishToBus(ev)
	for _, derived := range rs.deriveEvents(ctx, ev) {
		rs.publishToBus(derived)
	}
}

// bgpRealtimeTopic is the single, stable Wails transport topic for EVERY
// BGP realtime event — source (announcement/withdrawal) and derived
// (path_changed/origin_changed/moas_appeared/moas_disappeared/
// rpki_transition) alike (v1.2 Gate 5 §23.8 closure — the roadmap's own
// candidate). The frontend subscribes exactly once per session
// ("bgp:realtime:<sessionID>", via App.bridgeSession's existing
// e.Topic+":"+sess.ID pattern) and reads the actual kind from
// BGPRealtimeEvent.Type in the payload — never a per-Event.Type topic,
// which would force Gate 6's UI to open/track one Wails subscription per
// event type instead of one per session.
const bgpRealtimeTopic = "bgp:realtime"

func (rs *RealtimeSession) publishToBus(ev BGPRealtimeEvent) {
	rs.sess.Bus.Publish(events.Event{
		SessionID: rs.sess.ID,
		Kind:      events.KindProbe,
		Module:    "bgp-realtime",
		Topic:     bgpRealtimeTopic,
		Payload:   ev,
	})
}

// Stop cancela la sesión de forma determinista: remueve la sesión interna
// del Manager y cancela su contexto vía terminate() (interrumpe cualquier
// lectura WS/timer de backoff en curso — nunca deja la sesión "viva" en el
// registro del Manager, v1.2 P1-2 closure), espera a que la goroutine
// supervisora confirme su propio retorno vía el channel `done`, y solo
// entonces marca STOPPED — exactamente la secuencia de §23.5. Desde el
// cierre de Gate 3 P1-2, `done` no se cierra hasta que supervise() también
// haya confirmado el retorno de sus DOS goroutines child (watcher y
// processor, vía joinChildren() — ver el comentario de defers en
// supervise()): cuando Stop() retorna, NINGUNA goroutine propia de
// RealtimeSession sigue viva, y ninguna llamada RPKI/timer/backoff propio
// de la sesión sigue en vuelo — nunca un sleep/timeout arbitrario para
// lograrlo, solo channels de confirmación. Idempotente: llamar Stop() más
// de una vez, o sobre una sesión que nunca llegó a lanzar la goroutine
// (recurso inválido/no soportado), o sobre una sesión que ya falló por su
// cuenta, es seguro — terminate() garantiza que el Manager solo se toca
// una vez sin importar quién gane la carrera (v1.2 P1-2 closure).
func (rs *RealtimeSession) Stop() {
	rs.setState(SessionStopping)
	rs.terminate(true)
	<-rs.done
	rs.setState(SessionStopped)
}

// maybeApplyStabilityReset applies the same §23.5 "Reset" rule as
// reconnect() (a connection that has remained CONNECTED for
// >=stabilityThreshold resets failureStreak/ReconnectCount to 0), but
// evaluated lazily and event-drivenly from wherever it's called — never a
// dedicated timer/goroutine watching the 60s threshold live (v1.2 Gate 3
// P1-5 closure: the reset must be OBSERVABLE the moment 60s have elapsed,
// not only applied the next time the connection actually drops). Safe to
// call redundantly (idempotent once already reset) and safe to call on a
// session that has never connected (state won't be SessionConnected, so
// it's a no-op).
func (rs *RealtimeSession) maybeApplyStabilityReset() {
	rs.mu.Lock()
	if rs.state == SessionConnected && rs.clock.Now().Sub(rs.connectedSince) >= stabilityThreshold {
		rs.failureStreak = 0
		rs.reconnectCount = 0
	}
	rs.mu.Unlock()
}

// Info devuelve el estado público completo de la sesión.
func (rs *RealtimeSession) Info() RealtimeSessionInfo {
	// v1.2 Gate 3 P1-5 closure: aplicar el stability reset ANTES de leer
	// ReconnectCount/state — así una sesión que lleva >=60s CONNECTED
	// muestra el reset de inmediato, no solo la próxima vez que
	// reconnect() corra tras una caída real.
	rs.maybeApplyStabilityReset()
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	queueDropped := rs.queue.Dropped()
	transportDropped := int64(rs.sess.Bus.Dropped())
	return RealtimeSessionInfo{
		SessionID:              rs.sess.ID,
		Resource:               rs.resource,
		ResourceKind:           rs.resourceKind,
		ResolvedPrefix:         rs.resolvedPrefix,
		StartedAt:              rs.startedAt,
		State:                  rs.state,
		LastEventAt:            rs.lastEventAt,
		ReceivedEvents:         rs.receivedEvents,
		QueueDroppedEvents:     queueDropped,
		TransportDroppedEvents: transportDropped,
		DroppedEventsTotal:     queueDropped + transportDropped,
		ReconnectCount:         rs.reconnectCount,
		LastError:              rs.lastError,
		DerivedStateEvictions:  rs.derived.Evictions(),
		Disclosure: external.Disclosure{
			Source:      "RIS Live (RIPE NCC)",
			QueriedAt:   external.Now(),
			DataSent:    fmt.Sprintf("Resource=%q enviado por el usuario; ResolvedPrefix=%q realmente enviado a RIS Live como filtro prefix", rs.resource, rs.resolvedPrefix),
			CachePolicy: "sin caché — stream en vivo",
			Confidence:  "media",
			RateLimit:   "sin límites documentados explícitamente por RIPE NCC; TRAZIP nunca abre más de una conexión RIS Live por sesión ni reconecta en bucle sin backoff",
		},
	}
}

func (rs *RealtimeSession) setState(s RealtimeSessionState) {
	rs.mu.Lock()
	rs.state = s
	rs.mu.Unlock()
}

func (rs *RealtimeSession) setResolvedPrefix(p string) {
	rs.mu.Lock()
	rs.resolvedPrefix = p
	rs.mu.Unlock()
}

func (rs *RealtimeSession) getResolvedPrefix() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.resolvedPrefix
}

func (rs *RealtimeSession) incrementReconnect() {
	rs.mu.Lock()
	rs.reconnectCount++
	rs.mu.Unlock()
}

func (rs *RealtimeSession) getFailureStreak() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.failureStreak
}

func (rs *RealtimeSession) incrementFailureStreak() {
	rs.mu.Lock()
	rs.failureStreak++
	rs.mu.Unlock()
}

func (rs *RealtimeSession) setLastError(msg string) {
	rs.mu.Lock()
	rs.lastError = msg
	rs.mu.Unlock()
}

func (rs *RealtimeSession) fail(reason string) {
	rs.mu.Lock()
	rs.state = SessionFailed
	rs.lastError = reason
	rs.mu.Unlock()
	// Toda terminación de fallo remueve la sesión del Manager y cancela su
	// contexto — nunca queda "viva" en el registro indefinidamente (v1.2
	// P1-2 closure), y esto es lo que desbloquea al watcher/processor de
	// supervise() cuando nadie llamó Stop() (v1.2 P1-1 closure).
	rs.terminate(false)
}
