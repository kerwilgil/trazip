// Pure, framework-free helpers for the Investigations view — kept separate
// from Investigations.tsx so they're independently testable if a test
// runner is ever added (Phase E: "extraer helpers puros ... mantener
// TypeScript estricto"), without introducing one just for this.
import type { investigation } from './api';

// Same 5-level -> 3-badge-class mapping every other TRAZIP view using
// model.Level already applies (see PcapAnalyzer.tsx's own LEVEL_CLASS).
export const LEVEL_CLASS: Record<string, string> = {
  informativo: 'ok',
  bajo: 'warn',
  medio: 'warn',
  alto: 'danger',
  critico: 'danger',
};

// Same severity ordering direction as internal/investigation's own
// levelSeverity — used only for display grouping here, never recomputed
// as a judgement (the HighestLevel value itself always comes from the
// backend's own Summary).
const LEVEL_ORDER: Record<string, number> = {
  critico: 4,
  alto: 3,
  medio: 2,
  bajo: 1,
  informativo: 0,
};

export function levelSeverity(level: string): number {
  return LEVEL_ORDER[level] ?? 0;
}

export function sourceLabel(kind: string): string {
  switch (kind) {
    case 'diagnose':
      return 'Diagnose';
    case 'pcap':
      return 'PCAP';
    case 'monitor':
      return 'Monitor';
    case 'voip':
      return 'VoIP';
    default:
      return kind;
  }
}

function entryTime(e: investigation.Entry): string {
  return e.snapshot.occurredAt || e.addedAt;
}

// entryEpoch parses entryTime(e) into a real instant (ms since epoch).
// Date.parse understands RFC3339's offset/Z suffix correctly, so two
// timestamps in different offsets compare by the moment they actually name
// — never by which string looks lexicographically smaller (E.1-4: e.g.
// "...T19:00:00Z" is 19:00 UTC and must sort before "...T14:30:00-05:00",
// which is 19:30 UTC, even though the second string starts with a smaller
// hour digit). An unparseable value falls back to 0 (sorts first) — mirrors
// internal/investigation.entryInstant's own zero-time fallback, and should
// be unreachable for any Entry that passed backend validation.
function entryEpoch(e: investigation.Entry): number {
  const parsed = Date.parse(entryTime(e));
  return Number.isNaN(parsed) ? 0 : parsed;
}

// Timeline order: Snapshot.occurredAt when set, falling back to
// Entry.addedAt — mirrors internal/investigation.Timeline exactly (Phase
// E: "NO inventar OccurredAt"). Returns a new array; never mutates entries.
export function sortTimeline(entries: investigation.Entry[]): investigation.Entry[] {
  return [...entries].sort((a, b) => entryEpoch(a) - entryEpoch(b));
}

// formatInstant renders a timestamp in the viewer's own local timezone —
// so entries from different modules, all stored with their own offsets,
// visibly read on one single clock (E.1-5). Never touches the stored
// value; this is presentation only. Falls back to the raw string if it
// somehow doesn't parse (validation should already prevent that).
export function formatInstant(timestamp: string): string {
  if (!timestamp) return '';
  const ms = Date.parse(timestamp);
  if (Number.isNaN(ms)) return timestamp;
  return new Date(ms).toLocaleString();
}
