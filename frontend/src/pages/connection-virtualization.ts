import { defaultRangeExtractor, type Range, type VirtualItem } from '@tanstack/react-virtual'

export interface ConnectionScrollAnchor { id: string; index: number; offset: number }

// Keep keyboard focus mounted even if live sorting moves that connection away
// from the visible range. This adds at most one row to the bounded window.
export function connectionVirtualRange(range: Range, focusedIndex: number) {
  const indices = defaultRangeExtractor(range)
  if (focusedIndex >= 0 && focusedIndex < range.count && !indices.includes(focusedIndex)) {
    indices.push(focusedIndex)
    indices.sort((left, right) => left - right)
  }
  return indices
}

export function resolveConnectionAnchor(ids: readonly string[], anchor: ConnectionScrollAnchor): number {
  const index = ids.indexOf(anchor.id)
  // If a connection disappears, keep its former position reachable rather
  // than retaining an offset beyond the now shorter table.
  return index >= 0 ? index : Math.min(anchor.index, ids.length - 1)
}

// A focused row can be outside the visible window, so use a spacer for every
// gap, not just before/after the window. The header is real table content.
export function connectionVirtualSpacers(items: readonly VirtualItem[], total: number, headerHeight: number) {
  return items.map((item, index) => Math.max(0, item.start - (items[index - 1]?.end ?? headerHeight)))
    .concat(Math.max(0, total - (items.at(-1)?.end ?? headerHeight)))
}
