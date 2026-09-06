// Tests del patrón WAI-ARIA Tabs: navegación roving (wrap-around,
// Home/End) e ids estables tab ↔ panel usados por aria-controls y
// aria-labelledby en BGP Intelligence.
import { describe, expect, it } from 'vitest';
import { ariaTabIds, nextTabIndex } from './tabs';

describe('nextTabIndex', () => {
  it('ArrowRight avanza con wrap-around al final', () => {
    expect(nextTabIndex('ArrowRight', 0, 9)).toBe(1);
    expect(nextTabIndex('ArrowRight', 8, 9)).toBe(0);
  });

  it('ArrowLeft retrocede con wrap-around al inicio', () => {
    expect(nextTabIndex('ArrowLeft', 3, 9)).toBe(2);
    expect(nextTabIndex('ArrowLeft', 0, 9)).toBe(8);
  });

  it('Home/End saltan a los extremos', () => {
    expect(nextTabIndex('Home', 5, 9)).toBe(0);
    expect(nextTabIndex('End', 0, 9)).toBe(8);
  });

  it('teclas no reconocidas no alteran la selección (null)', () => {
    expect(nextTabIndex('ArrowUp', 1, 9)).toBeNull();
    expect(nextTabIndex('Enter', 1, 9)).toBeNull();
    expect(nextTabIndex(' ', 1, 9)).toBeNull();
  });

  it('estados degenerados no navegan (nunca -1 ni NaN como destino)', () => {
    expect(nextTabIndex('ArrowRight', 0, 0)).toBeNull();
    expect(nextTabIndex('ArrowRight', -1, 5)).toBeNull();
    expect(nextTabIndex('ArrowRight', 5, 5)).toBeNull();
  });

  it('un solo tab: las flechas quedan fijas', () => {
    expect(nextTabIndex('ArrowRight', 0, 1)).toBe(0);
    expect(nextTabIndex('ArrowLeft', 0, 1)).toBe(0);
  });
});

describe('ariaTabIds', () => {
  it('genera pares estables y únicos por prefijo', () => {
    expect(ariaTabIds('bgp', 'resumen')).toEqual({ tab: 'bgp-tab-resumen', panel: 'bgp-panel-resumen' });
    expect(ariaTabIds('obs', 'pais')).toEqual({ tab: 'obs-tab-pais', panel: 'obs-panel-pais' });
  });

  it('ids distintos entre tab y panel y entre prefijos (sin colisiones)', () => {
    const a = ariaTabIds('bgp', 'bgplay');
    const b = ariaTabIds('obs', 'bgplay');
    const all = [a.tab, a.panel, b.tab, b.panel];
    expect(new Set(all).size).toBe(4);
  });
});
