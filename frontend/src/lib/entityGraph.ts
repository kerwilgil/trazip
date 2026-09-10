// OSINT Entity Graph — pure view-model logic (V1.5-4).
//
// The React view stays thin: every rule that decides *what* to show lives here
// so it can be unit-tested the same way osint.ts / topologyGraph.ts are.
// This module holds NO runtime data — no providers, no results, no intelligence.
// It only shapes the entity graph for presentation.

// ---- Evidence Class ---------------------------------------------------------

/** Evidence class for relationships — mirrors backend osint.EvidenceClass. */
export type OsintEvidenceClass = 'observed' | 'possible_context' | 'not_proven' | 'unknown';

export const EVIDENCE_CLASS_ORDER: readonly OsintEvidenceClass[] = [
  'observed',
  'possible_context',
  'not_proven',
  'unknown',
] as const;

export interface EvidenceClassDescriptor {
  labelKey: string;
  summaryKey: string;
  /** CSS tag modifier — never the only signal (text + aria-label carry meaning). */
  tagClass: string;
  /** Shape modifier for edge rendering. */
  edgeStyle: 'solid' | 'dashed' | 'dotted';
}

export const EVIDENCE_DESCRIPTORS: Record<OsintEvidenceClass, EvidenceClassDescriptor> = {
  observed: {
    labelKey: 'Observado',
    summaryKey: 'Relación respaldada directamente por evidencia/provenance.',
    tagClass: 'ok',
    edgeStyle: 'solid',
  },
  possible_context: {
    labelKey: 'Contexto posible',
    summaryKey: 'Contexto plausible útil para investigación, pero NO demostrado.',
    tagClass: 'info',
    edgeStyle: 'dashed',
  },
  not_proven: {
    labelKey: 'No demostrado',
    summaryKey: 'Relación mostrada únicamente como no demostrada.',
    tagClass: 'warn',
    edgeStyle: 'dotted',
  },
  unknown: {
    labelKey: 'Sin clasificar',
    summaryKey: 'La relación no declaró una clase de evidencia válida.',
    tagClass: 'error',
    edgeStyle: 'dotted',
  },
};

export function asEvidenceClass(raw: string): OsintEvidenceClass {
  return raw === 'observed' || raw === 'possible_context' || raw === 'not_proven'
    ? raw
    : 'unknown';
}

// ---- Entity Kind ------------------------------------------------------------

/** Extensible entity kind identifier. */
export type OsintEntityKind =
  | 'ip'
  | 'domain'
  | 'asn'
  | 'certificate'
  | 'cve'
  | 'organization'
  | 'url'
  | 'country'
  | 'unknown';

export const ENTITY_KIND_ORDER: readonly OsintEntityKind[] = [
  'ip',
  'domain',
  'asn',
  'certificate',
  'cve',
  'organization',
  'url',
  'country',
  'unknown',
] as const;

export interface EntityKindDescriptor {
  labelKey: string;
  summaryKey: string;
  tagClass: string;
}

export const ENTITY_KIND_DESCRIPTORS: Record<OsintEntityKind, EntityKindDescriptor> = {
  ip: {
    labelKey: 'IP',
    summaryKey: 'Dirección IP.',
    tagClass: 'ok',
  },
  domain: {
    labelKey: 'Dominio',
    summaryKey: 'Nombre de dominio.',
    tagClass: 'info',
  },
  asn: {
    labelKey: 'ASN',
    summaryKey: 'Número de sistema autónomo.',
    tagClass: 'info',
  },
  certificate: {
    labelKey: 'Certificado',
    summaryKey: 'Certificado TLS/X.509.',
    tagClass: 'info',
  },
  cve: {
    labelKey: 'CVE',
    summaryKey: 'Vulnerabilidad CVE.',
    tagClass: 'warn',
  },
  organization: {
    labelKey: 'Organización',
    summaryKey: 'Organización / entidad.',
    tagClass: 'info',
  },
  url: {
    labelKey: 'URL',
    summaryKey: 'URL / recurso web.',
    tagClass: 'info',
  },
  country: {
    labelKey: 'País',
    summaryKey: 'Código de país ISO.',
    tagClass: 'info',
  },
  unknown: {
    labelKey: 'Sin clasificar',
    summaryKey: 'La entidad no declaró un tipo válido.',
    tagClass: 'error',
  },
};

export function asEntityKind(raw: string): OsintEntityKind {
  const known: OsintEntityKind[] = [
    'ip',
    'domain',
    'asn',
    'certificate',
    'cve',
    'organization',
    'url',
    'country',
  ];
  return known.includes(raw as OsintEntityKind) ? (raw as OsintEntityKind) : 'unknown';
}

// ---- Entity -----------------------------------------------------------------

/** One OSINT entity as shown in the UI — normalized from backend. */
export interface OsintEntity {
  id: string;
  kind: OsintEntityKind;
  label: string;
  value: string;
  attributes: Record<string, string>;
}

/** Normalizes a raw entity from the backend into an OsintEntity. */
export function normalizeEntity(raw: {
  id?: string;
  kind?: string;
  label?: string;
  value?: string;
  attributes?: Record<string, string>;
}): OsintEntity {
  return {
    id: raw.id ?? '',
    kind: asEntityKind(raw.kind ?? ''),
    label: raw.label ?? '',
    value: raw.value ?? '',
    attributes: raw.attributes ?? {},
  };
}

/** Sorted, de-duplicated entity list. */
export function sortEntities(list: OsintEntity[]): OsintEntity[] {
  return [...list].sort((a, b) => a.id.localeCompare(b.id));
}

// ---- Relation ---------------------------------------------------------------

/** One OSINT relation as shown in the UI — normalized from backend. */
export interface OsintRelation {
  id: string;
  from: string;
  to: string;
  kind: string;
  directed: boolean;
  evidenceClass: OsintEvidenceClass;
  provenanceRef: string;
  label: string;
}

/** Normalizes a raw relation from the backend into an OsintRelation. */
export function normalizeRelation(raw: {
  id?: string;
  from?: string;
  to?: string;
  kind?: string;
  directed?: boolean;
  evidenceClass?: string;
  provenanceRef?: string;
  label?: string;
}): OsintRelation {
  return {
    id: raw.id ?? '',
    from: raw.from ?? '',
    to: raw.to ?? '',
    kind: raw.kind ?? '',
    directed: Boolean(raw.directed),
    evidenceClass: asEvidenceClass(raw.evidenceClass ?? ''),
    provenanceRef: raw.provenanceRef ?? '',
    label: raw.label ?? '',
  };
}

/** Sorted, de-duplicated relation list. */
export function sortRelations(list: OsintRelation[]): OsintRelation[] {
  return [...list].sort((a, b) => {
    const ka = a.from + '\0' + a.to + '\0' + a.kind;
    const kb = b.from + '\0' + b.to + '\0' + b.kind;
    return ka.localeCompare(kb);
  });
}

// ---- Graph Layout -----------------------------------------------------------

/** Layout node with computed position. */
export interface EntityLayoutNode {
  id: string;
  x: number;
  y: number;
}

/** Complete graph layout. */
export interface EntityGraphLayout {
  width: number;
  height: number;
  nodeWidth: number;
  nodeHeight: number;
  nodes: EntityLayoutNode[];
}

// Layout constants (tuned for readability).
const ENTITY_NODE_WIDTH = 160;
const ENTITY_NODE_HEIGHT = 60;
const LEVEL_GAP = 120;
const NODE_GAP_X = 24;
const NODE_GAP_Y = 20;
const PADDING_X = 40;
const PADDING_Y = 40;
const MIN_CANVAS_WIDTH = 720;
const MIN_CANVAS_HEIGHT = 400;

export const ENTITY_GRAPH_MIN_ZOOM = 0.3;
export const ENTITY_GRAPH_MAX_ZOOM = 3;
export const ENTITY_GRAPH_ZOOM_STEP = 0.25;

export interface EntityGraphViewBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export function clampEntityGraphZoom(zoom: number): number {
  if (!Number.isFinite(zoom)) return 1;
  return Math.min(ENTITY_GRAPH_MAX_ZOOM, Math.max(ENTITY_GRAPH_MIN_ZOOM, zoom));
}

export function entityGraphViewBox(
  width: number,
  height: number,
  zoom: number,
): EntityGraphViewBox {
  const safeWidth = Number.isFinite(width) && width > 0 ? width : 1;
  const safeHeight = Number.isFinite(height) && height > 0 ? height : 1;
  const safeZoom = clampEntityGraphZoom(zoom);
  const visibleWidth = safeWidth / safeZoom;
  const visibleHeight = safeHeight / safeZoom;
  return {
    x: (safeWidth - visibleWidth) / 2,
    y: (safeHeight - visibleHeight) / 2,
    width: visibleWidth,
    height: visibleHeight,
  };
}

// ---- Deterministic Layout Algorithm ----------------------------------------

/**
 * Builds a deterministic layered layout for the entity graph.
 * Uses only explicit relations for structure — no force-directed randomness.
 */
export function buildEntityGraphLayout(
  entities: OsintEntity[],
  relations: OsintRelation[],
): EntityGraphLayout {
  // Build adjacency and indegree from directed relations only
  const entityIds = entities.map((e) => e.id).sort();
  const byId = new Map(entities.map((e) => [e.id, e]));

  const outgoing = new Map<string, string[]>();
  const indegree = new Map<string, number>();
  for (const id of entityIds) {
    indegree.set(id, 0);
  }

  for (const rel of relations) {
    if (!rel.directed) continue;
    if (!byId.has(rel.from) || !byId.has(rel.to) || rel.from === rel.to) continue;
    const targets = outgoing.get(rel.from) ?? [];
    if (!targets.includes(rel.to)) {
      targets.push(rel.to);
      outgoing.set(rel.from, targets);
      indegree.set(rel.to, (indegree.get(rel.to) ?? 0) + 1);
    }
  }
  // Sort targets for determinism
  for (const targets of outgoing.values()) targets.sort();

  // Topological level assignment (BFS from sources)
  const levelById = new Map<string, number>();
  const queue = [...entityIds].filter((id) => (indegree.get(id) ?? 0) === 0);
  for (const id of queue) levelById.set(id, 0);

  const visit = () => {
    while (queue.length > 0) {
      const id = queue.shift()!;
      const level = levelById.get(id) ?? 0;
      for (const target of outgoing.get(id) ?? []) {
        levelById.set(target, Math.max(levelById.get(target) ?? 0, level + 1));
        const remaining = (indegree.get(target) ?? 1) - 1;
        indegree.set(target, remaining);
        if (remaining === 0) queue.push(target);
      }
      queue.sort(); // deterministic
    }
  };
  visit();

  // Remaining nodes (cycles) get level 0
  for (const id of entityIds) {
    if (levelById.has(id)) continue;
    levelById.set(id, 0);
    queue.push(id);
    visit();
  }

  // Group by level
  const maxLevel = Math.max(0, ...levelById.values());
  const levels = new Map<number, string[]>();
  for (const id of entityIds) {
    const level = levelById.get(id) ?? 0;
    const group = levels.get(level) ?? [];
    group.push(id);
    levels.set(level, group);
  }

  // Compute dimensions per level
  const levelDimensions = new Map<number, { width: number; height: number }>();
  let maxLevelHeight = 0;
  for (let level = 0; level <= maxLevel; level++) {
    const count = (levels.get(level) ?? []).length;
    const { width, height } = levelBlockDimensions(count);
    levelDimensions.set(level, { width, height });
    maxLevelHeight = Math.max(maxLevelHeight, height);
  }

  const height = Math.max(MIN_CANVAS_HEIGHT, PADDING_Y * 2 + maxLevelHeight);
  const levelX = new Map<number, number>();
  let nextX = PADDING_X;
  for (let level = 0; level <= maxLevel; level++) {
    levelX.set(level, nextX);
    nextX += (levelDimensions.get(level)?.width ?? ENTITY_NODE_WIDTH) + LEVEL_GAP;
  }
  const width = Math.max(MIN_CANVAS_WIDTH, nextX - LEVEL_GAP + PADDING_X);

  // Position nodes within each level
  const laidOut: EntityLayoutNode[] = [];
  for (let level = 0; level <= maxLevel; level++) {
    const group = levels.get(level) ?? [];
    const dim = levelDimensions.get(level)!;
    // Sort by degree for readability (higher degree first)
    const ordered = [...group].sort((a, b) => {
      const degA = (outgoing.get(a)?.length ?? 0) + (indegree.get(a) ?? 0);
      const degB = (outgoing.get(b)?.length ?? 0) + (indegree.get(b) ?? 0);
      return degB - degA || a.localeCompare(b);
    });
    const cells = centerFirstCells(
      Math.ceil(dim.height / (ENTITY_NODE_HEIGHT + NODE_GAP_Y)),
      Math.ceil(dim.width / (ENTITY_NODE_WIDTH + NODE_GAP_X)),
    );
    ordered.forEach((id, index) => {
      const cell = cells[index];
      laidOut.push({
        id,
        x: (levelX.get(level) ?? PADDING_X) + cell.column * (ENTITY_NODE_WIDTH + NODE_GAP_X),
        y: (height - dim.height) / 2 + cell.row * (ENTITY_NODE_HEIGHT + NODE_GAP_Y),
      });
    });
  }

  return {
    width,
    height,
    nodeWidth: ENTITY_NODE_WIDTH,
    nodeHeight: ENTITY_NODE_HEIGHT,
    nodes: laidOut,
  };
}

function levelBlockDimensions(count: number): { width: number; height: number } {
  if (count <= 1) return { width: ENTITY_NODE_WIDTH, height: ENTITY_NODE_HEIGHT };
  const rows = Math.min(6, Math.max(1, Math.ceil(Math.sqrt(count))));
  const cols = Math.max(1, Math.ceil(count / rows));
  return {
    width: cols * ENTITY_NODE_WIDTH + Math.max(0, cols - 1) * NODE_GAP_X,
    height: rows * ENTITY_NODE_HEIGHT + Math.max(0, rows - 1) * NODE_GAP_Y,
  };
}

function centerFirstCells(rows: number, cols: number): Array<{ row: number; column: number }> {
  const centreRow = (rows - 1) / 2;
  const centreCol = (cols - 1) / 2;
  const cells: Array<{ row: number; column: number }> = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      cells.push({ row: r, column: c });
    }
  }
  return cells.sort((a, b) => {
    const da = Math.abs(a.row - centreRow) + Math.abs(a.column - centreCol);
    const db = Math.abs(b.row - centreRow) + Math.abs(b.column - centreCol);
    return da - db || a.column - b.column || a.row - b.row;
  });
}

// ---- Edge Endpoints & Curves ------------------------------------------------

export interface EntityEdgeEndpoints {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

export function entityEdgeEndpoints(
  from: Pick<EntityLayoutNode, 'x' | 'y'>,
  to: Pick<EntityLayoutNode, 'x' | 'y'>,
  nodeWidth: number,
  nodeHeight: number,
): EntityEdgeEndpoints {
  const halfW = nodeWidth / 2;
  const halfH = nodeHeight / 2;
  const fx = from.x + halfW;
  const fy = from.y + halfH;
  const tx = to.x + halfW;
  const ty = to.y + halfH;
  const dx = tx - fx;
  const dy = ty - fy;
  if (dx === 0 && dy === 0) return { startX: fx, startY: fy, endX: tx, endY: ty };
  const scale = 1 / Math.max(Math.abs(dx) / halfW, Math.abs(dy) / halfH);
  return {
    startX: fx + dx * scale,
    startY: fy + dy * scale,
    endX: tx - dx * scale,
    endY: ty - dy * scale,
  };
}

export function entityEdgeCurve(
  endpoints: EntityEdgeEndpoints,
  laneOffset: number,
): string {
  const dx = endpoints.endX - endpoints.startX;
  const bend = Math.max(-24, Math.min(24, laneOffset));
  const cx1 = endpoints.startX + dx * 0.34;
  const cx2 = endpoints.endX - dx * 0.34;
  return `M ${endpoints.startX} ${endpoints.startY} C ${cx1} ${endpoints.startY + bend}, ${cx2} ${endpoints.endY + bend}, ${endpoints.endX} ${endpoints.endY}`;
}

export function entityEdgeLaneOffsets(relations: OsintRelation[]): Map<string, number> {
  const outgoing = new Map<string, OsintRelation[]>();
  const incoming = new Map<string, OsintRelation[]>();
  for (const rel of relations) {
    outgoing.set(rel.from, [...(outgoing.get(rel.from) ?? []), rel]);
    incoming.set(rel.to, [...(incoming.get(rel.to) ?? []), rel]);
  }
  const sortRels = (items: OsintRelation[]) =>
    items.sort((a, b) => a.to.localeCompare(b.to) || a.from.localeCompare(b.from));
  for (const items of outgoing.values()) sortRels(items);
  for (const items of incoming.values()) sortRels(items);

  const lane = new Map<string, number>();
  const centred = (items: OsintRelation[], rel: OsintRelation) =>
    items.indexOf(rel) - (items.length - 1) / 2;
  for (const rel of relations) {
    const out = centred(outgoing.get(rel.from) ?? [], rel);
    const inw = centred(incoming.get(rel.to) ?? [], rel);
    lane.set(`${rel.from}-${rel.to}-${rel.kind}`, (out + inw) * 6);
  }
  return lane;
}

// ---- Filters & Helpers ------------------------------------------------------

export interface EntityGraphFilters {
  entityKinds: OsintEntityKind[];
  evidenceClasses: OsintEvidenceClass[];
}

export const DEFAULT_FILTERS: EntityGraphFilters = {
  entityKinds: [],
  evidenceClasses: [],
};

export function filterEntities(
  entities: OsintEntity[],
  filters: EntityGraphFilters,
): OsintEntity[] {
  if (filters.entityKinds.length === 0 && filters.evidenceClasses.length === 0) {
    return entities;
  }
  return entities.filter((e) => {
    if (filters.entityKinds.length > 0 && !filters.entityKinds.includes(e.kind)) {
      return false;
    }
    return true;
  });
}

export function filterRelations(
  relations: OsintRelation[],
  filters: EntityGraphFilters,
  entitySet: Set<string>,
): OsintRelation[] {
  return relations.filter((r) => {
    if (!entitySet.has(r.from) || !entitySet.has(r.to)) return false;
    if (filters.evidenceClasses.length > 0 && !filters.evidenceClasses.includes(r.evidenceClass)) {
      return false;
    }
    return true;
  });
}

// ---- Selection Helpers ------------------------------------------------------

export interface EntityGraphSelection {
  entityId: string | null;
  relationId: string | null;
}

export const EMPTY_SELECTION: EntityGraphSelection = { entityId: null, relationId: null };

// ---- Zoom/Fit Helpers -------------------------------------------------------

export function fitEntityGraphViewBox(
  layout: EntityGraphLayout,
  containerWidth: number,
  containerHeight: number,
): EntityGraphViewBox {
  const safeWidth = Math.max(1, containerWidth);
  const safeHeight = Math.max(1, containerHeight);
  const scaleX = safeWidth / layout.width;
  const scaleY = safeHeight / layout.height;
  const zoom = Math.min(scaleX, scaleY) * 0.9; // 90% to leave padding
  return entityGraphViewBox(layout.width, layout.height, clampEntityGraphZoom(zoom));
}