// Helpers puros del patrón WAI-ARIA Tabs (navegación roving + ids).
// Sin React, sin DOM, sin efectos — la vista solo traduce el resultado
// a foco real. Esto hace la navegación de teclado mecánicamente testeable.

/**
 * Índice del tab destino para ArrowLeft/ArrowRight/Home/End (wrap-around
 * en las flechas, extremos absolutos en Home/End). null si la tecla no
 * es de navegación — el caller no debe hacer nada entonces.
 */
export function nextTabIndex(key: string, current: number, count: number): number | null {
  if (count <= 0 || current < 0 || current >= count) return null;
  switch (key) {
    case 'ArrowRight': return (current + 1) % count;
    case 'ArrowLeft': return (current - 1 + count) % count;
    case 'Home': return 0;
    case 'End': return count - 1;
    default: return null;
  }
}

/**
 * Ids estables y emparejados tab ↔ tabpanel para OR checkear
 * aria-controls / aria-labelledby sin strings mágicos duplicados.
 */
export function ariaTabIds(prefix: string, id: string): { tab: string; panel: string } {
  return { tab: `${prefix}-tab-${id}`, panel: `${prefix}-panel-${id}` };
}
