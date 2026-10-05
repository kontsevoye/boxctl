import { useVirtualizer, type Virtualizer } from '@tanstack/react-virtual'
import { Fragment, useCallback, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { connectionVirtualRange, connectionVirtualSpacers, resolveConnectionAnchor, type ConnectionScrollAnchor } from './connection-virtualization'

interface Props {
  ids: string[]
  label: string
  columnCount: number
  detailIndex: number
  header: ReactNode
  renderRow: (index: number, measure: (element: HTMLTableSectionElement | null) => void) => ReactNode
}

export function VirtualConnectionTable({ ids, label, columnCount, detailIndex, header, renderRow }: Props) {
  const viewport = useRef<HTMLDivElement>(null)
  const head = useRef<HTMLTableSectionElement>(null)
  const previousIDs = useRef(ids)
  const collapsedSizes = useRef(new Map<string, number>())
  const previousDetailID = useRef<string | undefined>(undefined)
  const anchor = useRef<ConnectionScrollAnchor | null>(null)
  const [headerHeight, setHeaderHeight] = useState(0)
  const [mobile, setMobile] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 1280px)').matches)
  const [focusedID, setFocusedID] = useState('')
  const focusedIndex = ids.indexOf(focusedID)
  const keyForIndex = useCallback((index: number) => ids[index]!, [ids])
  const rangeExtractor = useCallback((range: Parameters<typeof connectionVirtualRange>[0]) => connectionVirtualRange(range, focusedIndex), [focusedIndex])
  const captureAnchor = (instance: Virtualizer<HTMLDivElement, HTMLTableSectionElement>) => {
    // Measurement callbacks can fire during a new snapshot's commit. Preserve
    // the previous snapshot's anchor until the layout effect restores it.
    if (previousIDs.current !== ids) return
    // scrollToOffset writes the DOM before its asynchronous scroll event
    // updates the virtualizer's cached offset.
    const offset = viewport.current?.scrollTop ?? instance.scrollOffset ?? 0
    const item = instance.getVirtualItemForOffset(offset + headerHeight)
    anchor.current = offset > 0 && item ? { id: String(item.key), index: item.index, offset: offset + headerHeight - item.start } : null
  }
  const virtualizer = useVirtualizer<HTMLDivElement, HTMLTableSectionElement>({
    count: ids.length,
    getScrollElement: () => viewport.current,
    getItemKey: keyForIndex,
    estimateSize: () => mobile ? 380 : 88,
    overscan: 6,
    paddingStart: headerHeight,
    scrollPaddingStart: headerHeight,
    rangeExtractor,
    onChange: captureAnchor,
    // Mobile cards have a margin outside their measured box. Count it as part
    // of the item, including expanded details and wrapped text.
    measureElement: (element) => {
      const margin = parseFloat(window.getComputedStyle(element).marginBottom) || 0
      const row = element.querySelector<HTMLTableRowElement>('.connections-card-row')
      if (row && element.dataset.connectionId) collapsedSizes.current.set(element.dataset.connectionId, row.getBoundingClientRect().height + margin)
      return element.getBoundingClientRect().height + margin
    },
  })

  useLayoutEffect(() => {
    const media = window.matchMedia('(max-width: 1280px)')
    const update = () => setMobile(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])

  useLayoutEffect(() => {
    const element = head.current
    if (!element) return
    const observer = new ResizeObserver(() => setHeaderHeight(element.getBoundingClientRect().height))
    setHeaderHeight(element.getBoundingClientRect().height)
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  useLayoutEffect(() => {
    virtualizer.measure()
  }, [mobile, virtualizer])

  useLayoutEffect(() => {
    const nextID = ids[detailIndex]
    const previousID = previousDetailID.current
    // Collapsing a row outside the mounted window must also discard its
    // expanded height; ResizeObserver cannot see that unmounted row.
    if (previousID && previousID !== nextID && !virtualizer.elementsCache.has(previousID)) {
      const index = ids.indexOf(previousID)
      const size = collapsedSizes.current.get(previousID)
      if (index >= 0 && size !== undefined) virtualizer.resizeItem(index, size)
    }
    previousDetailID.current = nextID
  }, [detailIndex, ids, virtualizer])

  useLayoutEffect(() => {
    const current = new Set(ids)
    for (const id of collapsedSizes.current.keys()) if (!current.has(id)) collapsedSizes.current.delete(id)
    // A long-lived stream can see an unbounded sequence of distinct IDs even
    // though its active/history lists are bounded. Retire measurements too.
    for (const key of virtualizer.itemSizeCache.keys()) if (!current.has(String(key))) virtualizer.itemSizeCache.delete(key)
  }, [ids, virtualizer])

  useLayoutEffect(() => {
    if (previousIDs.current !== ids && anchor.current) {
      const index = resolveConnectionAnchor(ids, anchor.current)
      // getTotalSize populates the keyed measurement cache before lookup.
      virtualizer.getTotalSize()
      const target = virtualizer.measurementsCache[index]
      if (target) virtualizer.scrollToOffset(Math.max(0, target.start + Math.min(anchor.current.offset, target.size - 1) - headerHeight))
      else virtualizer.scrollToOffset(0)
    }
    previousIDs.current = ids
    captureAnchor(virtualizer)
  })

  const items = virtualizer.getVirtualItems()
  const spacers = connectionVirtualSpacers(items, virtualizer.getTotalSize(), headerHeight)
  const spacer = (height: number, key: string) => height > 0 && <tbody key={key} className="connections-virtual-spacer" aria-hidden="true"><tr><td colSpan={columnCount} style={{ height, padding: 0, border: 0 }} /></tr></tbody>
  // aria-rowcount/index describe the complete data set to assistive technology;
  // browser find only sees mounted rows, so search remains the full-data filter.
  return <div ref={viewport} className="table-wrap connections-table-wrap" role="region" aria-label={label} tabIndex={0}
    onFocusCapture={(event) => setFocusedID((event.target as HTMLElement).closest<HTMLTableSectionElement>('tbody[data-connection-id]')?.dataset.connectionId ?? '')}
    onBlurCapture={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocusedID('') }}
    onKeyDown={(event) => {
      if (event.target !== event.currentTarget) return
      if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault()
        virtualizer.scrollToIndex(event.key === 'Home' ? 0 : ids.length - 1, { align: event.key === 'Home' ? 'start' : 'end' })
      }
    }}>
    <table className="du-table du-table-sm connections-table" aria-rowcount={ids.length + 1 + (detailIndex >= 0 ? 1 : 0)}>
      <thead ref={head}>{header}</thead>
      {items.map((item, index) => <Fragment key={item.key}>{spacer(spacers[index]!, `gap-${item.key}`)}{renderRow(item.index, virtualizer.measureElement)}</Fragment>)}
      {spacer(spacers.at(-1)!, 'tail')}
    </table>
  </div>
}
