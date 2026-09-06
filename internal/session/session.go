// Package session manages TRAZIP work sessions. A session bundles a cancellable
// context, an event bus for streaming results, and a scope guard for active
// operations (prompt maestro §7 "Session Orchestrator + Scope Guard").
package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"trazip/internal/events"
	"trazip/internal/scope"
)

// State is the lifecycle state of a session.
type State string

const (
	StateActive   State = "active"
	StateFinished State = "finished"
	StateCanceled State = "canceled"
)

// Session is a single unit of work with its own cancellation and event stream.
type Session struct {
	ID      string
	Label   string
	Bus     *events.Bus
	Scope   *scope.Guard
	Created time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	state State
}

// Context returns the session's cancellable context.
func (s *Session) Context() context.Context { return s.ctx }

// State returns the current lifecycle state.
func (s *Session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Cancel stops all work in the session immediately.
func (s *Session) Cancel() {
	s.mu.Lock()
	if s.state == StateActive {
		s.state = StateCanceled
	}
	s.mu.Unlock()
	s.cancel()
}

// Finish marks the session done without cancellation semantics.
func (s *Session) Finish() {
	s.mu.Lock()
	if s.state == StateActive {
		s.state = StateFinished
	}
	s.mu.Unlock()
	s.cancel()
}

// Manager owns the set of live sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewManager returns an empty session manager.
func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session)}
}

// New creates and registers a session derived from parent.
func (m *Manager) New(parent context.Context, label string) *Session {
	ctx, cancel := context.WithCancel(parent)
	s := &Session{
		ID:      uuid.NewString(),
		Label:   label,
		Bus:     events.NewBus(),
		Scope:   scope.NewGuard(),
		Created: time.Now(),
		ctx:     ctx,
		cancel:  cancel,
		state:   StateActive,
	}
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()
	return s
}

// BeginActive creates an operation session and enforces an explicit scope
// declaration before any active network work starts.
func (m *Manager) BeginActive(parent context.Context, label, target string, authorized bool) (*Session, error) {
	if !authorized {
		return nil, fmt.Errorf("debes confirmar que tienes autorización para operar sobre %q", target)
	}
	s := m.New(parent, label)
	if err := s.Scope.Authorize(label, []string{target}); err != nil {
		m.Remove(s.ID)
		return nil, err
	}
	if err := s.Scope.CheckTarget(target); err != nil {
		m.Remove(s.ID)
		return nil, err
	}
	return s, nil
}

// Get returns a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// List returns all live sessions.
func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Remove cancels and removes a session.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if ok {
		s.Cancel()
	}
}

// Complete marks and removes a finished session from the live registry.
func (m *Manager) Complete(id string) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if ok {
		s.Finish()
	}
}

// Cancel stops and removes a live session. It reports whether the ID existed.
func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if ok {
		s.Cancel()
	}
	return ok
}

// CancelAll stops every live session, used when the desktop app shuts down.
func (m *Manager) CancelAll() {
	m.mu.Lock()
	live := make([]*Session, 0, len(m.sessions))
	for id, s := range m.sessions {
		live = append(live, s)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, s := range live {
		s.Cancel()
	}
}
