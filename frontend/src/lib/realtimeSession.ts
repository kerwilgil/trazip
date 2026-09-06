// Pure state-machine helpers for BGP Intelligence's Tiempo real panel
// (v1.2 Gate 6 frontend lifecycle closure). Deliberately separated from
// BgpIntelligence.tsx: no hooks, no I/O, no timers — every function here
// is a pure function of its arguments, safe to call twice with the same
// input (React.StrictMode double-invokes state updaters) without any
// side effect beyond the value it returns. This is what makes the two
// invariants Gate 6 hardening depends on — "a stale poll can never
// revert an already-terminal state" and "the timeline updater never
// nests a second setState call" — mechanically checkable in isolation,
// without a running React tree or real timers.
import type { BGPRealtimeEvent } from './api';

export const MAX_TIMELINE_EVENTS = 500;

export function isTerminalRealtimeState(state: string | undefined): boolean {
  return state === 'stopped' || state === 'failed';
}

export interface RealtimeTimelineState {
  events: BGPRealtimeEvent[];
  evicted: number;
}

export const EMPTY_REALTIME_TIMELINE: RealtimeTimelineState = { events: [], evicted: 0 };

/**
 * Pure timeline append/eviction — the ONLY function that ever produces a
 * new RealtimeTimelineState. Both fields are computed together from
 * `prev` alone, in one return — never a second setState call nested
 * inside this one (Gate 6 P1-3: `setUiEvictedEvents` called from inside
 * a `setTimeline` updater was exactly the bug being closed here). `prev`
 * is never mutated — a fresh array/object is always returned.
 */
export function appendRealtimeEvent(prev: RealtimeTimelineState, ev: BGPRealtimeEvent): RealtimeTimelineState {
  if (prev.events.length >= MAX_TIMELINE_EVENTS) {
    return { events: [...prev.events.slice(1), ev], evicted: prev.evicted + 1 };
  }
  return { events: [...prev.events, ev], evicted: prev.evicted };
}

export type PollCommitAction = 'ignore' | 'terminal' | 'update';

/**
 * Decides what a resolved BGPRealtimeInfo poll is allowed to do to the
 * panel's committed state — the single choke point that makes a stale
 * poll structurally unable to revert an already-terminal state (Gate 6
 * P1-2). Two independent guards, either one sufficient on its own:
 *   1. generation mismatch (currentGeneration !== pollGeneration) — the
 *      poll belongs to a session/epoch that Start/Stop/unmount already
 *      invalidated (Stop bumps the generation and cancels the interval
 *      BEFORE awaiting the backend, so no poll scheduled before that
 *      point can ever land after it).
 *   2. currentState already terminal — frozen: once a stopped/failed
 *      snapshot has been committed, no later same-generation snapshot
 *      (which would only be non-terminal, since a poll is skipped
 *      entirely once decidePollCommit itself returns 'terminal' — see
 *      pollOnce's own caller, which cancels the interval on 'terminal')
 *      can ever overwrite it.
 * Pure: takes an exact snapshot of everything relevant as arguments and
 * returns a decision — never reads/writes refs or React state itself,
 * so it is independently testable and cannot itself race anything.
 */
export function decidePollCommit(params: {
  mounted: boolean;
  currentSessionId: string | null;
  pollSessionId: string;
  currentGeneration: number;
  pollGeneration: number;
  currentState: string | undefined;
  freshState: string;
}): PollCommitAction {
  if (!params.mounted) return 'ignore';
  if (params.currentSessionId !== params.pollSessionId) return 'ignore';
  if (params.currentGeneration !== params.pollGeneration) return 'ignore';
  if (isTerminalRealtimeState(params.currentState)) return 'ignore';
  return isTerminalRealtimeState(params.freshState) ? 'terminal' : 'update';
}
