// Pruebas unitarias de la máquina de estados pura del panel Tiempo real.
// Cobertura objetivo (FASE N): aislamiento de sesiones stale, generaciones,
// estados terminales congelados y cap de la timeline con conteo de evicted.
import { describe, expect, it } from 'vitest';
import {
  MAX_TIMELINE_EVENTS,
  EMPTY_REALTIME_TIMELINE,
  appendRealtimeEvent,
  decidePollCommit,
  isTerminalRealtimeState,
  type RealtimeTimelineState,
} from './realtimeSession';
import type { BGPRealtimeEvent } from './api';

const base = {
  mounted: true,
  currentSessionId: 'session-B',
  pollSessionId: 'session-B',
  currentGeneration: 2,
  pollGeneration: 2,
  currentState: 'connected',
  freshState: 'connected',
};

function ev(id: string): BGPRealtimeEvent {
  return { ID: id, Type: 'announcement', Timestamp: '2026-01-01T00:00:00Z' } as BGPRealtimeEvent;
}

describe('isTerminalRealtimeState', () => {
  it('solo stopped/failed son terminales', () => {
    expect(isTerminalRealtimeState('stopped')).toBe(true);
    expect(isTerminalRealtimeState('failed')).toBe(true);
    expect(isTerminalRealtimeState('connected')).toBe(false);
    expect(isTerminalRealtimeState('connecting')).toBe(false);
    expect(isTerminalRealtimeState('stopping')).toBe(false);
    expect(isTerminalRealtimeState(undefined)).toBe(false);
  });
});

describe('decidePollCommit', () => {
  it('permite committed update de la sesión/generación vigente', () => {
    expect(decidePollCommit(base)).toBe('update');
  });

  it('marca terminal cuando el snapshot nuevo es terminal', () => {
    expect(decidePollCommit({ ...base, freshState: 'failed' })).toBe('terminal');
    expect(decidePollCommit({ ...base, freshState: 'stopped' })).toBe('terminal');
  });

  it('ignora polls de una sesión anterior (session A ≠ session B)', () => {
    // Caso A: poll tardío de la sesión vieja nunca contamina la nueva.
    expect(decidePollCommit({ ...base, pollSessionId: 'session-A', freshState: 'failed' })).toBe('ignore');
  });

  it('ignora polls de una generación invalidada por Stop/Start', () => {
    expect(decidePollCommit({ ...base, pollGeneration: 1 })).toBe('ignore');
    expect(decidePollCommit({ ...base, currentGeneration: 3 })).toBe('ignore');
  });

  it('ignora polls tras el unmount del panel', () => {
    expect(decidePollCommit({ ...base, mounted: false })).toBe('ignore');
  });

  it('un estado terminal ya committed queda congelado: ningún update lo revierte', () => {
    expect(decidePollCommit({ ...base, currentState: 'stopped' })).toBe('ignore');
    expect(decidePollCommit({ ...base, currentState: 'failed', freshState: 'failed' })).toBe('ignore');
  });
});

describe('appendRealtimeEvent', () => {
  it('acumula eventos sin mutar el estado previo', () => {
    const next = appendRealtimeEvent(EMPTY_REALTIME_TIMELINE, ev('1'));
    expect(next.events).toHaveLength(1);
    expect(next.evicted).toBe(0);
    expect(EMPTY_REALTIME_TIMELINE.events).toHaveLength(0);
  });

  it('aplica el cap MAX_TIMELINE_EVENTS y cuenta evicted aparte', () => {
    let state: RealtimeTimelineState = EMPTY_REALTIME_TIMELINE;
    for (let i = 0; i < MAX_TIMELINE_EVENTS + 5; i++) state = appendRealtimeEvent(state, ev(String(i)));
    expect(state.events).toHaveLength(MAX_TIMELINE_EVENTS);
    expect(state.evicted).toBe(5);
    // El evento más antiguo fue eviccionado; los retenidos son los últimos.
    expect(state.events[0].ID).toBe('5');
    expect(state.events[MAX_TIMELINE_EVENTS - 1].ID).toBe(String(MAX_TIMELINE_EVENTS + 4));
  });

  it('evicted nunca se suma al contador del backend (capas distintas)', () => {
    let state: RealtimeTimelineState = EMPTY_REALTIME_TIMELINE;
    for (let i = 0; i < MAX_TIMELINE_EVENTS + 3; i++) state = appendRealtimeEvent(state, ev(String(i)));
    expect(state.events.length + state.evicted).toBe(MAX_TIMELINE_EVENTS + 3);
    expect(state.evicted).toBe(3);
  });
});
