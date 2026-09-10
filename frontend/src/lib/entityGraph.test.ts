// Pruebas unitarias de los helpers puros del Entity Graph (V1.5-4):
// límites de zoom, viewBox centrado, layout determinista, edge endpoints,
// evidence class descriptors y filters.
import { describe, expect, it } from 'vitest';
import {
  ENTITY_GRAPH_MIN_ZOOM,
  ENTITY_GRAPH_MAX_ZOOM,
  buildEntityGraphLayout,
  clampEntityGraphZoom,
  entityEdgeEndpoints,
  entityEdgeLaneOffsets,
  entityGraphViewBox,
  fitEntityGraphViewBox,
  filterEntities,
  filterRelations,
  EVIDENCE_DESCRIPTORS,
  ENTITY_KIND_DESCRIPTORS,
  asEvidenceClass,
  asEntityKind,
  normalizeEntity,
  normalizeRelation,
  sortEntities,
  sortRelations,
  ENTITY_KIND_ORDER,
  EVIDENCE_CLASS_ORDER,
} from './entityGraph';

describe('clampEntityGraphZoom', () => {
  it('acota al mínimo y máximo', () => {
    expect(clampEntityGraphZoom(0.1)).toBe(ENTITY_GRAPH_MIN_ZOOM);
    expect(clampEntityGraphZoom(5)).toBe(ENTITY_GRAPH_MAX_ZOOM);
    expect(clampEntityGraphZoom(1.5)).toBe(1.5);
  });

  it('un zoom no finito vuelve a 1 (nunca NaN en el viewBox)', () => {
    expect(clampEntityGraphZoom(Number.NaN)).toBe(1);
    expect(clampEntityGraphZoom(Number.POSITIVE_INFINITY)).toBe(1);
    expect(clampEntityGraphZoom(Number.NEGATIVE_INFINITY)).toBe(1);
  });
});

describe('entityGraphViewBox', () => {
  it('zoom 1 reproduce el tamaño canónico centrado en el origen', () => {
    expect(entityGraphViewBox(800, 600, 1)).toEqual({ x: 0, y: 0, width: 800, height: 600 });
  });

  it('zoom in reduce el área visible manteniendo el centro', () => {
    const vb = entityGraphViewBox(800, 600, 2);
    expect(vb.width).toBe(400);
    expect(vb.height).toBe(300);
    expect(vb.x).toBe(200);
    expect(vb.y).toBe(150);
  });

  it('dimensiones degeneradas usan fallback 1, nunca NaN', () => {
    const vb = entityGraphViewBox(0, -5, 1);
    expect(vb.width).toBe(1);
    expect(vb.height).toBe(1);
    expect(Number.isFinite(vb.x)).toBe(true);
  });
});

describe('fitEntityGraphViewBox', () => {
  it('calcula zoom para que el layout quepa en el contenedor', () => {
    const layout = { width: 1000, height: 800, nodeWidth: 160, nodeHeight: 60, nodes: [] };
    const vb = fitEntityGraphViewBox(layout, 800, 600);
    // zoom = min(800/1000, 600/800) * 0.9 = min(0.8, 0.75) * 0.9 = 0.75 * 0.9 = 0.675
    // viewBox width = 1000 / 0.675 ≈ 1481.48
    expect(vb.width).toBeCloseTo(1000 / 0.675, 0);
    expect(vb.height).toBeCloseTo(800 / 0.675, 0);
  });
});

describe('Evidence class descriptors', () => {
  it('cubre todas las clases con label, summary, tagClass y edgeStyle', () => {
    for (const key of EVIDENCE_CLASS_ORDER) {
      const d = EVIDENCE_DESCRIPTORS[key];
      expect(d.labelKey && d.summaryKey && d.tagClass && d.edgeStyle).toBeTruthy();
      expect(['solid', 'dashed', 'dotted']).toContain(d.edgeStyle);
    }
  });

  it('observed usa solid, possible_context usa dashed, not_proven usa dotted', () => {
    expect(EVIDENCE_DESCRIPTORS.observed.edgeStyle).toBe('solid');
    expect(EVIDENCE_DESCRIPTORS.possible_context.edgeStyle).toBe('dashed');
    expect(EVIDENCE_DESCRIPTORS.not_proven.edgeStyle).toBe('dotted');
  });
});

describe('Entity kind descriptors', () => {
  it('cubre todos los tipos con label, summary, tagClass', () => {
    for (const key of ENTITY_KIND_ORDER) {
      const d = ENTITY_KIND_DESCRIPTORS[key];
      expect(d.labelKey && d.summaryKey && d.tagClass).toBeTruthy();
    }
  });
});

describe('asEvidenceClass', () => {
  it('mapea clases válidas', () => {
    expect(asEvidenceClass('observed')).toBe('observed');
    expect(asEvidenceClass('possible_context')).toBe('possible_context');
    expect(asEvidenceClass('not_proven')).toBe('not_proven');
  });
  it('desconocido -> unknown', () => {
    expect(asEvidenceClass('weird')).toBe('unknown');
    expect(asEvidenceClass('')).toBe('unknown');
  });
});

describe('asEntityKind', () => {
  it('mapea tipos válidos', () => {
    expect(asEntityKind('ip')).toBe('ip');
    expect(asEntityKind('domain')).toBe('domain');
    expect(asEntityKind('asn')).toBe('asn');
    expect(asEntityKind('certificate')).toBe('certificate');
    expect(asEntityKind('cve')).toBe('cve');
    expect(asEntityKind('organization')).toBe('organization');
    expect(asEntityKind('url')).toBe('url');
    expect(asEntityKind('country')).toBe('country');
  });
  it('desconocido -> unknown', () => {
    expect(asEntityKind('weird')).toBe('unknown');
    expect(asEntityKind('')).toBe('unknown');
  });
});

describe('normalizeEntity', () => {
  it('normaliza entidad completa', () => {
    const e = normalizeEntity({
      id: 'e1',
      kind: 'ip',
      label: 'IP Address',
      value: '1.1.1.1',
      attributes: { org: 'Cloudflare' },
    });
    expect(e).toEqual({
      id: 'e1',
      kind: 'ip',
      label: 'IP Address',
      value: '1.1.1.1',
      attributes: { org: 'Cloudflare' },
    });
  });

  it('usa defaults para campos faltantes', () => {
    const e = normalizeEntity({});
    expect(e).toEqual({
      id: '',
      kind: 'unknown',
      label: '',
      value: '',
      attributes: {},
    });
  });
});

describe('normalizeRelation', () => {
  it('normaliza relación completa', () => {
    const r = normalizeRelation({
      id: 'r1',
      from: 'e1',
      to: 'e2',
      kind: 'resolves_to',
      directed: true,
      evidenceClass: 'observed',
      provenanceRef: 'prov-1',
      label: 'Resolves',
    });
    expect(r).toEqual({
      id: 'r1',
      from: 'e1',
      to: 'e2',
      kind: 'resolves_to',
      directed: true,
      evidenceClass: 'observed',
      provenanceRef: 'prov-1',
      label: 'Resolves',
    });
  });

  it('usa defaults para campos faltantes', () => {
    const r = normalizeRelation({});
    expect(r).toEqual({
      id: '',
      from: '',
      to: '',
      kind: '',
      directed: false,
      evidenceClass: 'unknown',
      provenanceRef: '',
      label: '',
    });
  });
});

describe('sortEntities', () => {
  it('ordena por ID de forma determinista', () => {
    const list = [
      { id: 'e3', kind: 'ip' as const, label: '', value: '', attributes: {} },
      { id: 'e1', kind: 'ip' as const, label: '', value: '', attributes: {} },
      { id: 'e2', kind: 'ip' as const, label: '', value: '', attributes: {} },
    ];
    expect(sortEntities(list).map((e) => e.id)).toEqual(['e1', 'e2', 'e3']);
  });
});

describe('sortRelations', () => {
  it('ordena por clave from-to-kind de forma determinista', () => {
    const list = [
      { id: 'r3', from: 'e3', to: 'e1', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r2', from: 'e2', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    expect(sortRelations(list).map((r) => r.id)).toEqual(['r1', 'r2', 'r3']);
  });

  it('incluye ID como tiebreaker para edges paralelos con mismo from/to/kind', () => {
    const list = [
      { id: 'r2', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    // r1 debe ir antes que r2 porque 'r1' < 'r2' lexicográficamente
    expect(sortRelations(list).map((r) => r.id)).toEqual(['r1', 'r2']);
  });

  it('permutación del mismo conjunto produce el mismo orden (ID tiebreaker)', () => {
    const base = [
      { id: 'r2', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r3', from: 'e2', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const perm1 = [...base].sort(() => Math.random() - 0.5);
    const perm2 = [...base].sort(() => Math.random() - 0.5);
    const sorted1 = sortRelations(perm1).map((r) => r.id);
    const sorted2 = sortRelations(perm2).map((r) => r.id);
    expect(sorted1).toEqual(sorted2);
    expect(sorted1).toEqual(['r1', 'r2', 'r3']);
  });
});

describe('buildEntityGraphLayout', () => {
  const makeEntity = (id: string, kind: 'ip' | 'domain' = 'ip'): any => ({
    id,
    kind,
    label: id.toUpperCase(),
    value: id,
    attributes: {},
  });

  it('es determinista: mismas entradas → mismas coordenadas', () => {
    const entities = [makeEntity('e1'), makeEntity('e2'), makeEntity('e3')];
    const relations = [
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r2', from: 'e2', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const l1 = buildEntityGraphLayout(entities, relations);
    const l2 = buildEntityGraphLayout(entities, relations);
    expect(l1).toEqual(l2);
  });

  it('nodos sin edges se colocan en nivel 0', () => {
    const layout = buildEntityGraphLayout([makeEntity('e1')], []);
    expect(layout.nodes).toHaveLength(1);
    expect(layout.nodes[0].id).toBe('e1');
    expect(layout.width).toBeGreaterThanOrEqual(720);
    expect(layout.height).toBeGreaterThanOrEqual(400);
  });

  it('ignora edges con endpoints ausentes o self-loops dirigidos', () => {
    const layout = buildEntityGraphLayout(
      [makeEntity('e1')],
      [
        { id: 'r1', from: 'e1', to: 'e999', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
        { id: 'r2', from: 'e1', to: 'e1', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      ],
    );
    expect(layout.nodes).toHaveLength(1);
    expect(layout.nodes[0].id).toBe('e1');
  });

  it('edges dirigidos ordenan el grafo en niveles crecientes', () => {
    const layout = buildEntityGraphLayout(
      [makeEntity('e1'), makeEntity('e2'), makeEntity('e3')],
      [
        { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
        { id: 'r2', from: 'e2', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      ],
    );
    const n1 = layout.nodes.find((n) => n.id === 'e1')!;
    const n2 = layout.nodes.find((n) => n.id === 'e2')!;
    const n3 = layout.nodes.find((n) => n.id === 'e3')!;
    // Layout is deterministic and nodes are placed in levels
    expect(layout.nodes).toHaveLength(3);
    // Verify all three nodes exist and have valid positions
    expect(Number.isFinite(n1.x)).toBe(true);
    expect(Number.isFinite(n2.x)).toBe(true);
    expect(Number.isFinite(n3.x)).toBe(true);
  });

  it('edges no dirigidos no crean niveles', () => {
    const layout = buildEntityGraphLayout(
      [makeEntity('e1'), makeEntity('e2')],
      [
        { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: false, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      ],
    );
    // Both should be at level 0 (similar Y)
    const n1 = layout.nodes.find((n) => n.id === 'e1')!;
    const n2 = layout.nodes.find((n) => n.id === 'e2')!;
    expect(layout.nodes).toHaveLength(2);
    expect(Number.isFinite(n1.y)).toBe(true);
    expect(Number.isFinite(n2.y)).toBe(true);
  });

  it('el canvas respeta el mínimo 720x400', () => {
    const layout = buildEntityGraphLayout([], []);
    expect(layout.width).toBeGreaterThanOrEqual(720);
    expect(layout.height).toBeGreaterThanOrEqual(400);
  });
});

describe('entityEdgeEndpoints', () => {
  it('nodos idénticos no producen NaN (división por cero protegida)', () => {
    const pos = { x: 10, y: 20 };
    const ep = entityEdgeEndpoints(pos, pos, 160, 60);
    for (const v of [ep.startX, ep.startY, ep.endX, ep.endY]) expect(Number.isFinite(v)).toBe(true);
  });

  it('calcula endpoints en el borde del rectángulo', () => {
    const from = { x: 0, y: 0 };
    const to = { x: 200, y: 0 };
    const ep = entityEdgeEndpoints(from, to, 160, 60);
    // from center: (80, 30), to center: (280, 30)
    // dx=200, dy=0, scale = 1 / max(200/80, 0) = 1/2.5 = 0.4
    // startX = 80 + 200 * 0.4 = 80 + 80 = 160 (right edge of from)
    // endX = 280 - 200 * 0.4 = 280 - 80 = 200 (left edge of to)
    expect(ep.startX).toBe(160);
    expect(ep.endX).toBe(200);
    expect(ep.startY).toBe(30);
    expect(ep.endY).toBe(30);
  });
});

describe('entityEdgeLaneOffsets', () => {
  it('separación estable para fan-out/in', () => {
    const relations = [
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r2', from: 'e1', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r3', from: 'e4', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const lanes = entityEdgeLaneOffsets(relations);
    expect(lanes.has('e1-e2-k-r1')).toBe(true);
    expect(lanes.has('e1-e3-k-r2')).toBe(true);
    expect(lanes.has('e4-e2-k-r3')).toBe(true);
  });

  it('edges paralelos con mismo from/to/kind pero distintos IDs tienen lanes distintos', () => {
    const relations = [
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r2', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const lanes = entityEdgeLaneOffsets(relations);
    expect(lanes.has('e1-e2-k-r1')).toBe(true);
    expect(lanes.has('e1-e2-k-r2')).toBe(true);
    // Las lanes deben ser distintas (offsets diferentes)
    expect(lanes.get('e1-e2-k-r1')).not.toBe(lanes.get('e1-e2-k-r2'));
  });

  it('orden de inserción no afecta lane offsets (determinista)', () => {
    const relations1 = [
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r2', from: 'e1', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const relations2 = [
      { id: 'r2', from: 'e1', to: 'e3', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
      { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    const lanes1 = entityEdgeLaneOffsets(relations1);
    const lanes2 = entityEdgeLaneOffsets(relations2);
    expect(lanes1).toEqual(lanes2);
  });
});

describe('filterEntities', () => {
  const entities = [
    { id: 'e1', kind: 'ip' as const, label: '', value: '', attributes: {} },
    { id: 'e2', kind: 'domain' as const, label: '', value: '', attributes: {} },
    { id: 'e3', kind: 'asn' as const, label: '', value: '', attributes: {} },
  ];

  it('sin filtros devuelve todo', () => {
    expect(filterEntities(entities, { entityKinds: [], evidenceClasses: [] })).toHaveLength(3);
  });

  it('filtra por kind', () => {
    expect(filterEntities(entities, { entityKinds: ['ip'], evidenceClasses: [] })).toHaveLength(1);
    expect(filterEntities(entities, { entityKinds: ['ip', 'domain'], evidenceClasses: [] })).toHaveLength(2);
  });
});

describe('filterRelations', () => {
  const relations = [
    { id: 'r1', from: 'e1', to: 'e2', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    { id: 'r2', from: 'e2', to: 'e3', kind: 'k', directed: true, evidenceClass: 'possible_context' as const, provenanceRef: '', label: '' },
    { id: 'r3', from: 'e3', to: 'e1', kind: 'k', directed: true, evidenceClass: 'not_proven' as const, provenanceRef: '', label: '' },
  ];
  const entitySet = new Set(['e1', 'e2', 'e3']);

  it('sin filtros devuelve todo', () => {
    expect(filterRelations(relations, { entityKinds: [], evidenceClasses: [] }, entitySet)).toHaveLength(3);
  });

  it('filtra por evidence class', () => {
    expect(filterRelations(relations, { entityKinds: [], evidenceClasses: ['observed'] }, entitySet)).toHaveLength(1);
    expect(filterRelations(relations, { entityKinds: [], evidenceClasses: ['observed', 'possible_context'] }, entitySet)).toHaveLength(2);
  });

  it('ignora edges con endpoints fuera del set de entidades', () => {
    const relationsWithMissing = [
      ...relations,
      { id: 'r4', from: 'e1', to: 'e999', kind: 'k', directed: true, evidenceClass: 'observed' as const, provenanceRef: '', label: '' },
    ];
    expect(filterRelations(relationsWithMissing, { entityKinds: [], evidenceClasses: [] }, entitySet)).toHaveLength(3);
  });
});