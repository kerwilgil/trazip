package api

import (
	"context"
	"fmt"
	"strings"

	"trazip/internal/bgp"
	"trazip/internal/session"
)

// BGPRealtimeStart begins a v1.2 BGP realtime session for resource and
// returns both the serializable RealtimeSessionInfo (safe to hand back
// through a Wails-bound method) and the underlying *session.Session.
//
// Deliberately NOT a *Service method (same reasoning as RunDiagnose/
// RunVoIPAnalysis in diagnose2.go/service.go): a raw *session.Session can
// never be a Wails-bound method's return type — main.go binds Service
// wholesale (`Bind: []interface{}{app, app.Service()}`), so Wails would
// try to reflect over every exported Service method, and a
// *session.Session return value has no JSON-safe shape. app.go's
// App.BGPRealtimeStart (the ONLY Wails-bound entry point the GUI uses)
// calls this and passes a.bridgeSession as bridge — exactly the existing
// pattern for every other streaming feature (Ping/Trace/MTR/Capture/VoIP/
// Diagnose all create or receive a *session.Session in app.go and bridge
// it there; BGP realtime differs only in that the session is created one
// level down, inside bgp.PrepareRealtimeSession, so this function owns
// the bridge-before-run sequencing itself instead of leaving it to the
// caller — v1.2 Gate 5 P1-2 closure).
//
// bridge, when non-nil, is called EXACTLY ONCE — after the session is
// constructed and registered in s.bgpSessions (v1.2 P1-3: race-free,
// nothing can have self-terminated yet, since Run() hasn't been called),
// but strictly BEFORE Run() launches the supervisor goroutine that can
// dial/read/derive/publish. events.Bus has no replay, so this order is
// what guarantees bridge's subscriber can never miss the first event
// (v1.2 P1-2 closure) — never a scheduling/network-latency assumption. A
// rejected Start (invalid resource, ASN, empty resource — v1.2 P1-1
// closure) never calls bridge at all: there is no session to bridge.
func BGPRealtimeStart(ctx context.Context, resource string, s *Service, bridge func(sess *session.Session)) (bgp.RealtimeSessionInfo, *session.Session, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return bgp.RealtimeSessionInfo{}, nil, fmt.Errorf("recurso vacío")
	}
	rs, err := s.registerBGPSession(ctx, resource)
	if err != nil {
		return bgp.RealtimeSessionInfo{}, nil, err
	}
	sess := rs.Session()
	if bridge != nil {
		bridge(sess)
	}
	rs.Run()
	return rs.Info(), sess, nil
}

// BGPRealtimeStop cancels a running BGP realtime session by its
// backend-generated SessionID and blocks until it has fully,
// deterministically stopped (bgp.RealtimeSession.Stop's own join
// guarantee) — never a fire-and-forget context cancel like
// App.stopOperation, which only cancels and returns immediately.
//
// sessionID empty, unknown, or belonging to a non-BGP session (this
// lookup only ever contains entries registerBGPSession itself added)
// all return an error, never touching session.Manager for an ID this
// package didn't create — see Service.bgpSessions' own doc comment. A
// second Stop() call for the same ID also returns an error (the entry is
// removed atomically before the blocking Stop() call), which is this
// contract's deliberate, tested definition of "idempotent": harmless to
// call twice, never a crash or a double-cancel of something else, even
// though the second call's return value differs from the first's.
//
// v1.2 Gate 5.1: also maintains Service.bgpFinalSnapshots so
// BGPRealtimeInfo can keep answering for sessionID after this call
// returns. A PROVISIONAL snapshot (rs.Info() taken the instant the live
// entry is removed) is stored before the blocking rs.Stop() call so a
// concurrent BGPRealtimeInfo lookup never sees sessionID as fully unknown
// during the join — then overwritten with the true FINAL rs.Info() once
// rs.Stop() has returned (guaranteed post-join: State==stopped and every
// counter/error field final). The onTerminate hook registerBGPSession
// installed fires synchronously inside this rs.Stop() call too, but it
// only acts when its own bgpSessions lookup still finds the entry — by
// then this function has already removed it, so onTerminate is a no-op
// here and never double-writes the snapshot this function itself owns.
func BGPRealtimeStop(sessionID string, s *Service) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("sessionID vacío")
	}
	s.bgpSessionsMu.Lock()
	rs, ok := s.bgpSessions[sessionID]
	if ok {
		delete(s.bgpSessions, sessionID)
		s.storeFinalSnapshotLocked(rs.Info())
	}
	s.bgpSessionsMu.Unlock()
	if !ok {
		return fmt.Errorf("sesión BGP realtime desconocida: %q", sessionID)
	}
	rs.Stop()
	s.bgpSessionsMu.Lock()
	s.storeFinalSnapshotLocked(rs.Info())
	s.bgpSessionsMu.Unlock()
	return nil
}

// BGPRealtimeInfo returns sessionID's current (live) or FINAL (terminated)
// RealtimeSessionInfo — v1.2 Gate 5.1's local-only observability seam for
// Gate 6. Read-only: zero RIPEstat HTTP calls, zero RIS Live WebSocket
// operations, never reconnects, never mutates the session. A direct
// *Service method (unlike BGPRealtimeStart/Stop) because it never needs
// the raw *session.Session — nothing here requires Wails-bridge access, so
// none of BGPRealtimeStart/Stop's App-level constraints apply (see this
// file's own package doc comment on BGPRealtimeStart).
//
// Lookup order: s.bgpSessions (live) first, then s.bgpFinalSnapshots
// (bounded terminal cache) — the exact same source-of-truth boundary
// BGPRealtimeStop already respects. Both maps only ever contain IDs this
// package itself created via registerBGPSession, so an empty ID, an
// unknown ID, or a non-BGP session.Manager ID all return an error without
// ever consulting session.Manager directly — never reinterpreting another
// module's session.
func (s *Service) BGPRealtimeInfo(sessionID string) (bgp.RealtimeSessionInfo, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return bgp.RealtimeSessionInfo{}, fmt.Errorf("sessionID vacío")
	}
	s.bgpSessionsMu.Lock()
	defer s.bgpSessionsMu.Unlock()
	if rs, ok := s.bgpSessions[sessionID]; ok {
		return rs.Info(), nil
	}
	if info, ok := s.bgpFinalSnapshots[sessionID]; ok {
		return info, nil
	}
	return bgp.RealtimeSessionInfo{}, fmt.Errorf("sesión BGP realtime desconocida: %q", sessionID)
}

// storeFinalSnapshotLocked records info as sessionID's terminal snapshot,
// evicting the single oldest entry (deterministic FIFO, bgpFinalOrder)
// once the bounded cache is already at bgpFinalSnapshotLimit — v1.2 Gate
// 5.1. Overwrites in place without consuming another eviction slot when
// sessionID already has an entry (BGPRealtimeStop's own provisional ->
// final overwrite), so a single session's termination can never itself
// evict a different, older session out of turn. Caller must hold
// s.bgpSessionsMu.
func (s *Service) storeFinalSnapshotLocked(info bgp.RealtimeSessionInfo) {
	id := info.SessionID
	if _, exists := s.bgpFinalSnapshots[id]; !exists {
		if len(s.bgpFinalOrder) >= bgpFinalSnapshotLimit {
			oldest := s.bgpFinalOrder[0]
			s.bgpFinalOrder = s.bgpFinalOrder[1:]
			delete(s.bgpFinalSnapshots, oldest)
		}
		s.bgpFinalOrder = append(s.bgpFinalOrder, id)
	}
	s.bgpFinalSnapshots[id] = info
}

// registerBGPSession constructs one BGP realtime session via
// s.bgpRealtimeStart (production: bgp.PrepareRealtimeSession; tests: a
// fake-dialer substitute — see the field's own doc comment) WITHOUT
// starting it (that's rs.Run(), called by BGPRealtimeStart itself, after
// any caller-side bridge is installed) and, on success, adds it to
// s.bgpSessions.
//
// v1.2 Gate 5 P1-1/P1-3 closure: s.bgpRealtimeStart itself never
// constructs anything for a resource realtime v1.2 doesn't support
// (invalid, ASN) — it returns an error instead, so there is nothing here
// to add to s.bgpSessions and nothing for BGPRealtimeStop to ever find
// for that attempt. For every resource it DOES construct, the returned
// *bgp.RealtimeSession has not launched its supervisor goroutine yet
// (Run() hasn't been called) — so it cannot possibly have self-terminated
// before this function's map write runs. The narrow "check→insert" race
// the previous single-phase design had (a session could terminate in the
// window between a liveness check and this map write) cannot exist
// anymore: there is no window, because self-termination requires Run(),
// and Run() only ever happens strictly after this function returns.
func (s *Service) registerBGPSession(ctx context.Context, resource string) (*bgp.RealtimeSession, error) {
	// v1.2 Gate 5.1: this closure is the ONLY path that handles AUTONOMOUS
	// termination (Stop() explícito ya se maneja, y ya guarda su propio
	// snapshot final, en BGPRealtimeStop — ver su doc comment). Cuando la
	// sesión termina por sí sola (fail() por datasource/RIS_ERROR/
	// reconexión agotada, o cancelación externa del context padre), el
	// bgpSessions[sessionID] lookup de abajo SIEMPRE la encuentra todavía
	// viva (nadie más la ha quitado), así que Info() aquí lee el estado
	// terminal correcto (fail() ya fijó State/LastError ANTES de invocar
	// terminate() → este hook — ver bgp.RealtimeSession.fail's own doc
	// comment). delete + storeFinalSnapshotLocked comparten la MISMA
	// sección crítica (un solo Lock/Unlock) — nunca hay una ventana en la
	// que sessionID esté ausente de ambos mapas a la vez.
	onTerminate := func(sessionID string) {
		s.bgpSessionsMu.Lock()
		if rs, ok := s.bgpSessions[sessionID]; ok {
			delete(s.bgpSessions, sessionID)
			s.storeFinalSnapshotLocked(rs.Info())
		}
		s.bgpSessionsMu.Unlock()
	}
	rs, err := s.bgpRealtimeStart(ctx, s.sessions, s.bgpClient, resource, onTerminate)
	if err != nil {
		return nil, err
	}
	s.bgpSessionsMu.Lock()
	s.bgpSessions[rs.Info().SessionID] = rs
	s.bgpSessionsMu.Unlock()
	return rs, nil
}
