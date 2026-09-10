import { describe, expect, it } from 'vitest';
import { NAV, findItem } from './nav';
import { MODULE_INFO } from './moduleInfo';
import {
  ACTIVITY_DESCRIPTORS,
  DISCLOSURE_DESCRIPTORS,
  OSINT_ERROR_KINDS,
  PROVENANCE_FIELDS,
  RESULT_STATES,
  capabilityOptionsFor,
  normalizeProvider,
  normalizeProviders,
  providerCapabilities,
  requiresAuthorizedScope,
  sortProviders,
  type OsintProvider,
} from './osint';
import type { OsintProviderInfo } from './api';

function raw(over: Partial<OsintProviderInfo> = {}): OsintProviderInfo {
  return {
    id: 'p.example',
    name: 'Example',
    capabilities: ['rdap'],
    activityClass: 'passive',
    disclosureClass: 'passive',
    requiresScope: false,
    ...over,
  };
}

describe('OSINT navigation entry', () => {
  it('exposes a single "osint" item under Inteligencia with a module description', () => {
    const item = findItem('osint');
    expect(item).toBeDefined();
    expect(item?.label).toBe('Inteligencia OSINT');

    const groups = NAV.filter((g) => g.items.some((i) => i.id === 'osint'));
    expect(groups).toHaveLength(1);
    expect(groups[0].label).toBe('Inteligencia');

    expect(MODULE_INFO.osint).toBeTruthy();
  });
});

describe('normalizeProvider', () => {
  it('keeps well-formed metadata intact', () => {
    const p = normalizeProvider(raw({ capabilities: ['rdap', 'asn_mapping'], rateLimit: '1/s' }));
    expect(p).toEqual<OsintProvider>({
      id: 'p.example',
      name: 'Example',
      capabilities: ['asn_mapping', 'rdap'],
      activityClass: 'passive',
      disclosureClass: 'passive',
      requiresScope: false,
      rateLimit: '1/s',
    });
  });

  it('guards a null capabilities array', () => {
    const p = normalizeProvider(raw({ capabilities: null as unknown as string[] }));
    expect(p.capabilities).toEqual([]);
  });

  it('maps an unknown activity/disclosure string to "unknown"', () => {
    const p = normalizeProvider(raw({ activityClass: 'weird', disclosureClass: '' }));
    expect(p.activityClass).toBe('unknown');
    expect(p.disclosureClass).toBe('unknown');
  });

  it('falls back to id when name is missing, and defaults rateLimit to ""', () => {
    const p = normalizeProvider(raw({ name: '', rateLimit: undefined }));
    expect(p.name).toBe('p.example');
    expect(p.rateLimit).toBe('');
  });
});

describe('providerCapabilities', () => {
  it('de-duplicates, drops empties, and sorts', () => {
    expect(providerCapabilities(['cve', 'rdap', 'cve', '', 'asn_mapping'])).toEqual([
      'asn_mapping',
      'cve',
      'rdap',
    ]);
  });
  it('treats null/undefined as empty', () => {
    expect(providerCapabilities(null)).toEqual([]);
    expect(providerCapabilities(undefined)).toEqual([]);
  });
});

describe('sortProviders / normalizeProviders', () => {
  it('orders by name then id, deterministically', () => {
    const list = normalizeProviders([
      raw({ id: 'b', name: 'Zeta' }),
      raw({ id: 'a', name: 'Alpha' }),
      raw({ id: 'c', name: 'Alpha' }),
    ]);
    expect(list.map((p) => p.id)).toEqual(['a', 'c', 'b']);
  });

  it('normalizeProviders tolerates null input', () => {
    expect(normalizeProviders(null)).toEqual([]);
    expect(normalizeProviders(undefined)).toEqual([]);
  });
});

describe('requiresAuthorizedScope', () => {
  it('is always true for an active provider', () => {
    const p = normalizeProvider(raw({ activityClass: 'active', disclosureClass: 'active', requiresScope: false }));
    expect(requiresAuthorizedScope(p)).toBe(true);
  });
  it('follows the flag for a passive provider', () => {
    expect(requiresAuthorizedScope(normalizeProvider(raw({ requiresScope: false })))).toBe(false);
    expect(requiresAuthorizedScope(normalizeProvider(raw({ requiresScope: true })))).toBe(true);
  });
});

describe('capabilityOptionsFor (provider/capability coherence)', () => {
  const providers = normalizeProviders([
    raw({ id: 'rdap.x', name: 'RDAP', capabilities: ['rdap', 'asn_mapping'] }),
    raw({ id: 'scan.x', name: 'Scan', capabilities: ['port_scan'], activityClass: 'active', disclosureClass: 'active', requiresScope: true }),
  ]);

  it('offers exactly the selected provider\'s declared capabilities', () => {
    expect(capabilityOptionsFor('rdap.x', providers)).toEqual(['asn_mapping', 'rdap']);
    expect(capabilityOptionsFor('rdap.x', providers)).not.toContain('port_scan');
  });

  it('returns [] for an unknown provider id', () => {
    expect(capabilityOptionsFor('nope', providers)).toEqual([]);
    expect(capabilityOptionsFor('', providers)).toEqual([]);
  });
});

describe('prepared descriptors are complete', () => {
  it('covers every activity and disclosure class with a label, summary and tag', () => {
    for (const key of ['passive', 'active', 'unknown'] as const) {
      const d = ACTIVITY_DESCRIPTORS[key];
      expect(d.labelKey && d.summaryKey && d.tagClass).toBeTruthy();
    }
    for (const key of ['local', 'passive', 'active', 'unknown'] as const) {
      const d = DISCLOSURE_DESCRIPTORS[key];
      expect(d.labelKey && d.summaryKey && d.tagClass).toBeTruthy();
    }
  });

  it('passive activity descriptor does NOT claim the operation is necessarily external', () => {
    const passiveDesc = ACTIVITY_DESCRIPTORS.passive.summaryKey;
    expect(passiveDesc).not.toMatch(/consulta.*extern|external.*lookup/i);
    expect(passiveDesc).toMatch(/interacci[oó]n.*activ|active.*interaction/i);
  });

  it('valid combination: activityClass=passive + disclosureClass=local + requiresScope=false', () => {
    const p = normalizeProvider(raw({
      activityClass: 'passive',
      disclosureClass: 'local',
      requiresScope: false,
    }));
    expect(p.activityClass).toBe('passive');
    expect(p.disclosureClass).toBe('local');
    expect(requiresAuthorizedScope(p)).toBe(false);
  });

  it('enumerates the nine result states the area is prepared for', () => {
    expect([...RESULT_STATES]).toEqual([
      'idle',
      'loading',
      'success',
      'empty',
      'error',
      'canceled',
      'rate_limited',
      'unavailable',
      'scope_denied',
    ]);
  });

  it('mirrors every typed OSINT error from the Go layer', () => {
    expect(OSINT_ERROR_KINDS.map((k) => k.id)).toEqual([
      'invalid_config',
      'unsupported_capability',
      'scope_denied',
      'rate_limited',
      'provider_unavailable',
      'external_lookup_failed',
      'canceled',
      'deadline_exceeded',
      'provider_not_found',
      'activity_violation',
      'invalid_provenance',
    ]);
    for (const k of OSINT_ERROR_KINDS) expect(k.titleKey && k.bodyKey).toBeTruthy();
  });

  it('lists provenance fields in display order with no secret-shaped field', () => {
    expect(PROVENANCE_FIELDS.map((f) => f.id)).toEqual([
      'source',
      'provider',
      'capability',
      'activity',
      'disclosure',
      'retrievedAt',
      'endpoint',
      'confidence',
    ]);
    const joined = PROVENANCE_FIELDS.map((f) => f.id.toLowerCase()).join(' ');
    expect(joined).not.toMatch(/token|secret|key|credential|password/);
  });
});
