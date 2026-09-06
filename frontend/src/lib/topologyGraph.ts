export interface TopologyNodeLike {
  asn: number;
  pathCount: number;
}

export interface TopologyEdgeLike {
  from: number;
  to: number;
  observationCount: number;
}

export interface TopologyDegree {
  incoming: number;
  outgoing: number;
  total: number;
}

export interface TopologyLayoutNode {
  asn: number;
  level: number;
  x: number;
  y: number;
}

export interface TopologyLayout {
  width: number;
  height: number;
  nodeWidth: number;
  nodeHeight: number;
  nodes: TopologyLayoutNode[];
}

export interface TopologyEdgeEndpoints {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

const NODE_WIDTH = 192;
const NODE_HEIGHT = 78;
const LEVEL_GAP = 82;
const BLOCK_GAP = 26;
const ROW_GAP = 24;
const PADDING_X = 48;
const PADDING_Y = 40;
const DENSE_LEVEL_ROWS = 8;

export const TOPOLOGY_MIN_ZOOM = 0.5;
export const TOPOLOGY_MAX_ZOOM = 2;
export const TOPOLOGY_ZOOM_STEP = 0.25;

export interface TopologyViewBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

// clampTopologyZoom keeps presentation-only zoom bounded without changing the
// canonical layout coordinates.
export function clampTopologyZoom(zoom: number): number {
  if (!Number.isFinite(zoom)) return 1;
  return Math.min(TOPOLOGY_MAX_ZOOM, Math.max(TOPOLOGY_MIN_ZOOM, zoom));
}

// topologyViewBox zooms around the canonical layout centre. The caller keeps
// the layout itself untouched, so it can always export the whole topology.
export function topologyViewBox(width: number, height: number, zoom: number): TopologyViewBox {
  const safeWidth = Number.isFinite(width) && width > 0 ? width : 1;
  const safeHeight = Number.isFinite(height) && height > 0 ? height : 1;
  const safeZoom = clampTopologyZoom(zoom);
  const visibleWidth = safeWidth / safeZoom;
  const visibleHeight = safeHeight / safeZoom;
  return {
    x: (safeWidth - visibleWidth) / 2,
    y: (safeHeight - visibleHeight) / 2,
    width: visibleWidth,
    height: visibleHeight,
  };
}

export function calculateTopologyDegrees(nodes: TopologyNodeLike[], edges: TopologyEdgeLike[]): Map<number, TopologyDegree> {
  const degrees = new Map(nodes.map((node) => [node.asn, { incoming: 0, outgoing: 0, total: 0 }]));
  for (const edge of edges) {
    if (edge.from === edge.to) continue;
    const from = degrees.get(edge.from);
    const to = degrees.get(edge.to);
    if (!from || !to) continue;
    from.outgoing++;
    from.total++;
    to.incoming++;
    to.total++;
  }
  return degrees;
}

// groupTopologyLevels uses only directed, consecutively observed AS-path
// edges. Equal choices are ASN-sorted, and cycles receive a deterministic
// seed level rather than inventing a relationship or using a force layout.
export function groupTopologyLevels(nodes: TopologyNodeLike[], edges: TopologyEdgeLike[]): Map<number, number[]> {
  const byASN = new Map(nodes.map((node) => [node.asn, node]));
  const outgoing = new Map<number, number[]>();
  const indegree = new Map<number, number>();
  for (const node of nodes) indegree.set(node.asn, 0);
  for (const edge of edges) {
    if (!byASN.has(edge.from) || !byASN.has(edge.to) || edge.from === edge.to) continue;
    const targets = outgoing.get(edge.from) ?? [];
    if (!targets.includes(edge.to)) {
      targets.push(edge.to);
      outgoing.set(edge.from, targets);
      indegree.set(edge.to, (indegree.get(edge.to) ?? 0) + 1);
    }
  }
  for (const targets of outgoing.values()) targets.sort((a, b) => a - b);

  const ordered = [...byASN.keys()].sort((a, b) => a - b);
  const levelByASN = new Map<number, number>();
  const queue = ordered.filter((asn) => indegree.get(asn) === 0);
  for (const asn of queue) levelByASN.set(asn, 0);
  const visit = () => {
    while (queue.length > 0) {
      const asn = queue.shift()!;
      const level = levelByASN.get(asn) ?? 0;
      for (const target of outgoing.get(asn) ?? []) {
        levelByASN.set(target, Math.max(levelByASN.get(target) ?? 0, level + 1));
        const remaining = (indegree.get(target) ?? 1) - 1;
        indegree.set(target, remaining);
        if (remaining === 0) queue.push(target);
      }
      queue.sort((a, b) => a - b);
    }
  };
  visit();
  for (const asn of ordered) {
    if (levelByASN.has(asn)) continue;
    levelByASN.set(asn, 0);
    queue.push(asn);
    visit();
  }

  const levels = new Map<number, number[]>();
  for (const asn of ordered) {
    const level = levelByASN.get(asn) ?? 0;
    const group = levels.get(level) ?? [];
    group.push(asn);
    levels.set(level, group);
  }
  return levels;
}

function blockDimensions(count: number): { rows: number; columns: number; width: number; height: number } {
  const rows = count > 10 ? Math.min(DENSE_LEVEL_ROWS, count) : Math.max(1, count);
  const columns = Math.max(1, Math.ceil(count / rows));
  return {
    rows,
    columns,
    width: columns * NODE_WIDTH + Math.max(0, columns - 1) * BLOCK_GAP,
    height: rows * NODE_HEIGHT + Math.max(0, rows - 1) * ROW_GAP,
  };
}

function centerFirstCells(rows: number, columns: number): Array<{ row: number; column: number }> {
  const centreRow = (rows - 1) / 2;
  const centreColumn = (columns - 1) / 2;
  const cells: Array<{ row: number; column: number }> = [];
  for (let row = 0; row < rows; row++) for (let column = 0; column < columns; column++) cells.push({ row, column });
  return cells.sort((a, b) => {
    const distanceA = Math.abs(a.row - centreRow) + Math.abs(a.column - centreColumn);
    const distanceB = Math.abs(b.row - centreRow) + Math.abs(b.column - centreColumn);
    return distanceA - distanceB || a.column - b.column || a.row - b.row;
  });
}

// buildTopologyLayout uses degree only to place already-observed ASNs more
// readably within a level. It does not infer provider, customer, or transit.
export function buildTopologyLayout(nodes: TopologyNodeLike[], edges: TopologyEdgeLike[]): TopologyLayout {
  const levels = groupTopologyLevels(nodes, edges);
  const degrees = calculateTopologyDegrees(nodes, edges);
  const maxLevel = Math.max(0, ...levels.keys());
  const dimensions = new Map<number, ReturnType<typeof blockDimensions>>();
  let maxBlockHeight = 0;
  for (let level = 0; level <= maxLevel; level++) {
    const dimension = blockDimensions((levels.get(level) ?? []).length);
    dimensions.set(level, dimension);
    maxBlockHeight = Math.max(maxBlockHeight, dimension.height);
  }
  const height = Math.max(300, PADDING_Y * 2 + maxBlockHeight);
  const levelX = new Map<number, number>();
  let nextX = PADDING_X;
  for (let level = 0; level <= maxLevel; level++) {
    levelX.set(level, nextX);
    nextX += (dimensions.get(level)?.width ?? NODE_WIDTH) + LEVEL_GAP;
  }
  const width = Math.max(720, nextX - LEVEL_GAP + PADDING_X);

  const laidOut: TopologyLayoutNode[] = [];
  for (let level = 0; level <= maxLevel; level++) {
    const group = levels.get(level) ?? [];
    const dimension = dimensions.get(level)!;
    const ordered = [...group].sort((a, b) => {
      const degreeA = degrees.get(a)?.total ?? 0;
      const degreeB = degrees.get(b)?.total ?? 0;
      return degreeB - degreeA || a - b;
    });
    const cells = centerFirstCells(dimension.rows, dimension.columns);
    ordered.forEach((asn, index) => {
      const cell = cells[index];
      laidOut.push({
        asn,
        level,
        x: (levelX.get(level) ?? PADDING_X) + cell.column * (NODE_WIDTH + BLOCK_GAP),
        y: (height - dimension.height) / 2 + cell.row * (NODE_HEIGHT + ROW_GAP),
      });
    });
  }
  return { width, height, nodeWidth: NODE_WIDTH, nodeHeight: NODE_HEIGHT, nodes: laidOut };
}

export function topologyEdgeWidth(observationCount: number, maximum: number): number {
  if (maximum <= 0 || observationCount <= 0) return 1.25;
  return Math.min(5.5, 1.25 + Math.sqrt(observationCount / maximum) * 4.25);
}

export function topologyEdgeEndpoints(from: Pick<TopologyLayoutNode, 'x' | 'y'>, to: Pick<TopologyLayoutNode, 'x' | 'y'>, nodeWidth: number, nodeHeight: number): TopologyEdgeEndpoints {
  const halfWidth = nodeWidth / 2;
  const halfHeight = nodeHeight / 2;
  const fromCenterX = from.x + halfWidth;
  const fromCenterY = from.y + halfHeight;
  const toCenterX = to.x + halfWidth;
  const toCenterY = to.y + halfHeight;
  const deltaX = toCenterX - fromCenterX;
  const deltaY = toCenterY - fromCenterY;
  if (deltaX === 0 && deltaY === 0) return { startX: fromCenterX, startY: fromCenterY, endX: toCenterX, endY: toCenterY };
  const scale = 1 / Math.max(Math.abs(deltaX) / halfWidth, Math.abs(deltaY) / halfHeight);
  return { startX: fromCenterX + deltaX * scale, startY: fromCenterY + deltaY * scale, endX: toCenterX - deltaX * scale, endY: toCenterY - deltaY * scale };
}

// topologyEdgeCurve produces a light, deterministic Bézier lane. laneOffset
// is derived from shared endpoints by the caller and only separates strokes.
export function topologyEdgeCurve(endpoints: TopologyEdgeEndpoints, laneOffset: number): string {
  const dx = endpoints.endX - endpoints.startX;
  const bend = Math.max(-34, Math.min(34, laneOffset));
  const controlX1 = endpoints.startX + dx * 0.34;
  const controlX2 = endpoints.endX - dx * 0.34;
  return `M ${endpoints.startX} ${endpoints.startY} C ${controlX1} ${endpoints.startY + bend}, ${controlX2} ${endpoints.endY + bend}, ${endpoints.endX} ${endpoints.endY}`;
}

// topologyEdgeLaneOffsets spreads fan-in/fan-out in stable ASN order.
export function topologyEdgeLaneOffsets(edges: TopologyEdgeLike[]): Map<string, number> {
  const outgoing = new Map<number, TopologyEdgeLike[]>();
  const incoming = new Map<number, TopologyEdgeLike[]>();
  for (const edge of edges) {
    outgoing.set(edge.from, [...(outgoing.get(edge.from) ?? []), edge]);
    incoming.set(edge.to, [...(incoming.get(edge.to) ?? []), edge]);
  }
  const sortEdges = (items: TopologyEdgeLike[]) => items.sort((a, b) => a.to - b.to || a.from - b.from);
  for (const items of outgoing.values()) sortEdges(items);
  for (const items of incoming.values()) sortEdges(items);
  const lane = new Map<string, number>();
  const centred = (items: TopologyEdgeLike[], edge: TopologyEdgeLike) => items.indexOf(edge) - (items.length - 1) / 2;
  for (const edge of edges) {
    const out = centred(outgoing.get(edge.from) ?? [], edge);
    const inwards = centred(incoming.get(edge.to) ?? [], edge);
    lane.set(`${edge.from}-${edge.to}`, (out + inwards) * 8);
  }
  return lane;
}

export function sanitizeTopologyFilename(resource: string): string {
  const normalized = resource.trim().replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized || 'resource';
}
