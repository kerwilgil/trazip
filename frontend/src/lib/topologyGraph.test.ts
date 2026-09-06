// Pruebas unitarias de los helpers puros de la topología BGP (FASE N):
// límites de zoom, viewBox centrado, sanitización de filenames de export
// y determinismo del layout basado solo en edges observados.
import { describe, expect, it } from 'vitest';
import {
  TOPOLOGY_MIN_ZOOM,
  TOPOLOGY_MAX_ZOOM,
  buildTopologyLayout,
  clampTopologyZoom,
  sanitizeTopologyFilename,
  topologyEdgeEndpoints,
  topologyViewBox,
} from './topologyGraph';

describe('clampTopologyZoom', () => {
  it('acota al mínimo y máximo', () => {
    expect(clampTopologyZoom(0.1)).toBe(TOPOLOGY_MIN_ZOOM);
    expect(clampTopologyZoom(10)).toBe(TOPOLOGY_MAX_ZOOM);
    expect(clampTopologyZoom(1.25)).toBe(1.25);
  });

  it('un zoom no finito vuelve a 1 (nunca NaN en el viewBox)', () => {
    expect(clampTopologyZoom(Number.NaN)).toBe(1);
    expect(clampTopologyZoom(Number.POSITIVE_INFINITY)).toBe(1);
  });
});

describe('topologyViewBox', () => {
  it('zoom 1 reproduce el tamaño canónico centrado en el origen', () => {
    expect(topologyViewBox(800, 600, 1)).toEqual({ x: 0, y: 0, width: 800, height: 600 });
  });

  it('zoom in reduce el área visible manteniendo el centro', () => {
    const vb = topologyViewBox(800, 600, 2);
    expect(vb.width).toBe(400);
    expect(vb.height).toBe(300);
    expect(vb.x).toBe(200);
    expect(vb.y).toBe(150);
  });

  it('dimensiones degeneradas usan fallback 1, nunca NaN', () => {
    const vb = topologyViewBox(0, -5, 1);
    expect(vb.width).toBe(1);
    expect(vb.height).toBe(1);
    expect(Number.isFinite(vb.x)).toBe(true);
  });
});

describe('sanitizeTopologyFilename', () => {
  it('permite solo [a-zA-Z0-9._-]', () => {
    expect(sanitizeTopologyFilename('AS13335')).toBe('AS13335');
    expect(sanitizeTopologyFilename('1.1.1.0/24')).toBe('1.1.1.0-24');
    expect(sanitizeTopologyFilename('2606:4700::/32')).toBe('2606-4700-32');
    // Los separadores de ruta se convierten en '-' — traversal imposible;
    // los puntos están explícitamente permitidos por el contrato.
    expect(sanitizeTopologyFilename('../../etc/passwd')).toBe('..-..-etc-passwd');
    expect(sanitizeTopologyFilename('../../etc/passwd')).not.toContain('/');
  });

  it('un recurso vacío o solo símbolos cae al fallback', () => {
    expect(sanitizeTopologyFilename('')).toBe('resource');
    expect(sanitizeTopologyFilename('///***')).toBe('resource');
  });
});

describe('buildTopologyLayout', () => {
  it('es determinista: mismas entradas → mismas coordenadas', () => {
    const nodes = [{ asn: 1, pathCount: 9 }, { asn: 2, pathCount: 3 }, { asn: 3, pathCount: 7 }];
    const edges = [
      { from: 1, to: 2, observationCount: 4 },
      { from: 2, to: 3, observationCount: 2 },
    ];
    expect(buildTopologyLayout(nodes, edges)).toEqual(buildTopologyLayout(nodes, edges));
  });

  it('ignora edges con endpoints ausentes o self-loops (sin nodos inventados)', () => {
    const layout = buildTopologyLayout(
      [{ asn: 1, pathCount: 1 }],
      [
        { from: 1, to: 999, observationCount: 5 },
        { from: 1, to: 1, observationCount: 7 },
      ],
    );
    expect(layout.nodes).toHaveLength(1);
    expect(layout.nodes[0].asn).toBe(1);
  });

  it('el canvas respeta el mínimo 720 de ancho (siempre navegable)', () => {
    const layout = buildTopologyLayout([], []);
    expect(layout.width).toBeGreaterThanOrEqual(720);
    expect(layout.height).toBeGreaterThanOrEqual(300);
  });

  it('edges dirigidos ordenan el grafo en niveles crecientes', () => {
    const layout = buildTopologyLayout(
      [{ asn: 10, pathCount: 1 }, { asn: 20, pathCount: 1 }, { asn: 30, pathCount: 1 }],
      [
        { from: 10, to: 20, observationCount: 1 },
        { from: 20, to: 30, observationCount: 1 },
      ],
    );
    const level = new Map(layout.nodes.map((n) => [n.asn, n.level]));
    expect(level.get(10)).toBeLessThan(level.get(20)!);
    expect(level.get(20)).toBeLessThan(level.get(30)!);
  });
});

describe('topologyEdgeEndpoints', () => {
  it('nodos idénticos no producen NaN (división por cero protegida)', () => {
    const pos = { x: 10, y: 20 };
    const ep = topologyEdgeEndpoints(pos, pos, 192, 78);
    for (const v of [ep.startX, ep.startY, ep.endX, ep.endY]) expect(Number.isFinite(v)).toBe(true);
  });
});
