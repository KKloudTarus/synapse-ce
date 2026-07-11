import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef, type ReactNode } from 'react'
import { cn } from './ui'

export interface Column<T> {
  header: string
  /** Width/grow/alignment classes, applied to both the header and the cells. */
  className?: string
  cell: (item: T) => ReactNode
}

/** A windowed table that renders only the visible rows – for SBOMs / vuln lists
 *  that can run to thousands of rows (docs/04-ui-ux.md: virtualize > 50 rows). */
export function VirtualTable<T>({
  columns,
  items,
  rowKey,
  rowHeight = 46,
  maxHeightClass = 'max-h-[60vh]',
  tableMinWidthClass = 'min-w-full',
  headerClassName,
  rowClassName,
  totalItems,
}: {
  columns: Column<T>[]
  items: T[]
  rowKey: (item: T, index: number) => string
  rowHeight?: number | ((item: T) => number)
  maxHeightClass?: string
  tableMinWidthClass?: string
  headerClassName?: string
  rowClassName?: string | ((item: T) => string)
  totalItems?: number
}) {
  const parentRef = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => (typeof rowHeight === 'function' ? rowHeight(items[index]) : rowHeight),
    overscan: 12,
  })

  return (
    <div ref={parentRef} role="table" aria-rowcount={items.length + 1} className={cn('overflow-auto', maxHeightClass)}>
      <div className={tableMinWidthClass}>
        <div
          role="row"
          aria-rowindex={1}
          className={cn(
            'sticky top-0 z-20 flex items-center gap-3 border-y border-borderstrong bg-elevated/95 px-4 py-3 text-[11px] uppercase tracking-[0.14em] text-foreground shadow-sm backdrop-blur',
            headerClassName,
          )}
        >
          {columns.map((c, i) => (
            <div key={i} role="columnheader" className={cn('font-semibold', c.className)}>
              {c.header}
            </div>
          ))}
        </div>
        <div style={{ height: `${v.getTotalSize()}px`, position: 'relative' }}>
          {v.getVirtualItems().map((vi) => {
            const item = items[vi.index]
            return (
              <div
                key={rowKey(item, vi.index)}
                role="row"
                aria-rowindex={vi.index + 2}
                className={cn(
                  'absolute left-0 top-0 flex w-full items-center gap-3 border-b border-border/60 px-4 text-sm hover:bg-elevated/40',
                    typeof rowClassName === 'function' ? rowClassName(item) : rowClassName,
                )}
                style={{ height: `${vi.size}px`, transform: `translateY(${vi.start}px)` }}
              >
                {columns.map((c, i) => (
                  <div key={i} role="cell" className={cn('min-w-0 truncate', c.className)}>
                    {c.cell(item)}
                  </div>
                ))}
              </div>
            )
          })}
        </div>
        <div className="border-t border-border px-4 py-2 text-xs text-mutedfg tabular-nums">
          {totalItems === undefined
            ? `${items.length.toLocaleString()} rows`
            : `${items.length.toLocaleString()} rows shown · ${totalItems.toLocaleString()} total after current filters`}
        </div>
      </div>
    </div>
  )
}
