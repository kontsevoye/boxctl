import { Virtualizer, type VirtualItem } from '@tanstack/react-virtual'
import { describe, expect, it } from 'vitest'
import { connectionVirtualRange, connectionVirtualSpacers, resolveConnectionAnchor } from './connection-virtualization'

function virtualTable(ids: string[], offset = 0, height = 640) {
  return new Virtualizer<HTMLDivElement, HTMLTableSectionElement>({
    count: ids.length,
    getScrollElement: () => null,
    getItemKey: (index) => ids[index]!,
    estimateSize: () => 88,
    overscan: 6,
    paddingStart: 40,
    initialRect: { width: 1440, height },
    initialOffset: offset,
    observeElementRect: () => undefined,
    observeElementOffset: () => undefined,
    scrollToFn: () => undefined,
  })
}

describe('Connections virtual table', () => {
  const ids = Array.from({ length: 5000 }, (_, index) => `connection-${index}`)

  it('bounds mounted rows for thousands of connections at the start, middle and end', () => {
    for (const offset of [0, 200000, 439000]) {
      const table = virtualTable(ids, offset)
      const items = table.getVirtualItems()
      expect(items.length).toBeGreaterThan(0)
      expect(items.length).toBeLessThan(24)
      expect(items.every((item) => item.key === ids[item.index])).toBe(true)
      const spacers = connectionVirtualSpacers(items, table.getTotalSize(), 40)
      expect(spacers.reduce((total, gap) => total + gap, 0) + items.reduce((total, item) => total + item.size, 0) + 40).toBe(table.getTotalSize())
    }
    expect(virtualTable(ids, 439900).getVirtualItems().at(-1)?.key).toBe('connection-4999')
  })

  it('measures expansion and keeps a connection size associated with its ID after live sorting', () => {
    const table = virtualTable(ids)
    table.getVirtualItems()
    const before = table.getTotalSize()
    table.resizeItem(3, 300)
    expect(table.getTotalSize()).toBe(before + 212)
    const reordered = [...ids]
    reordered.splice(3, 1)
    reordered.splice(100, 0, 'connection-3')
    table.setOptions({ ...table.options, getItemKey: (index) => reordered[index]! })
    table.getVirtualItems()
    expect(table.measurementsCache[100]).toMatchObject({ key: 'connection-3', size: 300 })
    expect(table.measurementsCache[3]?.size).toBe(88)
  })

  it('preserves the reading anchor when a stream reorder moves it, with a reachable fallback on deletion', () => {
    const anchor = { id: 'connection-2000', index: 2000, offset: 17 }
    expect(resolveConnectionAnchor([...ids].reverse(), anchor)).toBe(2999)
    expect(resolveConnectionAnchor(ids.filter((id) => id !== anchor.id), anchor)).toBe(2000)
    expect(resolveConnectionAnchor(ids.slice(0, 4), anchor)).toBe(3)
    expect(resolveConnectionAnchor([], anchor)).toBe(-1)
  })

  it('keeps keyboard focus mounted without rendering every intervening connection', () => {
    const range = { startIndex: 100, endIndex: 106, overscan: 6, count: ids.length }
    const indices = connectionVirtualRange(range, 4000)
    expect(indices).toHaveLength(20)
    expect(indices.at(-1)).toBe(4000)
    expect(connectionVirtualRange(range, 103)).toHaveLength(19)
    expect(connectionVirtualRange(range, -1)).toHaveLength(19)
    const items = indices.map((index): VirtualItem => ({ key: ids[index]!, index, start: 40 + index * 88, end: 40 + (index + 1) * 88, size: 88, lane: 0 }))
    const gaps = connectionVirtualSpacers(items, 440040, 40)
    expect(gaps.at(-2)).toBeGreaterThan(300000)
    expect(gaps.reduce((sum, gap) => sum + gap, 0) + items.length * 88 + 40).toBe(440040)
  })

  it('handles the larger variable mobile-card sizes without losing the last connection', () => {
    const table = virtualTable(ids, 500000, 600)
    table.setOptions({ ...table.options, estimateSize: () => 380, paddingStart: 0 })
    table.getVirtualItems()
    table.resizeItem(1300, 680)
    expect(table.getTotalSize()).toBe(1900300)
    table.scrollOffset = table.getTotalSize() - 600
    const items = table.getVirtualItems()
    expect(items.length).toBeLessThan(16)
    expect(items.at(-1)?.key).toBe('connection-4999')
  })
})
