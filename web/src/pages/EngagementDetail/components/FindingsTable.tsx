import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, SwitchVertical01 } from '@untitledui/icons'
import { Fragment } from 'react'
import { AITriageBadges } from '../../../components/synapse/AITriageBadges'
import { KevBadge, Select, SevBadge, cn } from '../../../components/ui'
import { sevRank } from '../../../lib/severity'
import { statusLabel } from '../../../lib/format'
import type { Finding, ScanResult, Vulnerability } from '../../../lib/types'
import { KindBadge, PriorityBadge, ScopeBadge, shortPkg } from '../VulnsTab'
import { FindingDetail } from './FindingDetail'
import { FindingStatusControl } from './FindingStatus'

export const DEFAULT_PAGE_SIZE = 25
export const PAGE_SIZE_OPTIONS = [25, 50, 100] as const

export type FindingSortKey = 'priority' | 'severity' | 'title' | 'scope' | 'status'
export type SortDirection = 'asc' | 'desc'

/** Ascending comparators; the direction flag reverses them. */
const COMPARATORS: Record<FindingSortKey, (a: Finding, b: Finding) => number> = {
  priority: (a, b) => a.priority - b.priority,
  severity: (a, b) => sevRank(a.severity) - sevRank(b.severity),
  title: (a, b) => a.title.localeCompare(b.title),
  scope: (a, b) => (a.scope || '').localeCompare(b.scope || ''),
  status: (a, b) => statusLabel(a.status).localeCompare(statusLabel(b.status)),
}

/** First click on a column picks the direction an analyst actually wants. */
export const INITIAL_DIRECTION: Record<FindingSortKey, SortDirection> = {
  priority: 'asc',
  severity: 'desc',
  title: 'asc',
  scope: 'asc',
  status: 'asc',
}

export function isFindingSortKey(value: string | null | undefined): value is FindingSortKey {
  return value === 'priority' || value === 'severity' || value === 'title' || value === 'scope' || value === 'status'
}

/**
 * Sorts a copy; the caller's array order is the API's and stays the tiebreak so
 * equal keys keep a stable, deterministic order across renders.
 */
export function sortFindings(rows: Finding[], key: FindingSortKey | null, direction: SortDirection): Finding[] {
  if (!key) return rows
  const compare = COMPARATORS[key]
  const sign = direction === 'asc' ? 1 : -1
  return rows
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => sign * compare(a.finding, b.finding) || a.index - b.index)
    .map((entry) => entry.finding)
}

function SortableHeader({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
  className,
}: {
  label: string
  sortKey: FindingSortKey
  activeKey: FindingSortKey | null
  direction: SortDirection
  onSort: (key: FindingSortKey) => void
  className?: string
}) {
  const active = activeKey === sortKey
  const Icon = !active ? SwitchVertical01 : direction === 'asc' ? ArrowUp : ArrowDown
  return (
    <th
      scope="col"
      className={className}
      aria-sort={active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 font-bold uppercase tracking-wider text-secondary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
      >
        {label}
        <Icon className={cn('size-3', active ? 'text-primary' : 'text-quaternary')} aria-hidden="true" />
      </button>
    </th>
  )
}

export function findingAnchor(id: string) {
  return `finding-${id}`
}

export function TablePagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: {
  page: number
  totalPages: number
  total: number
  pageSize: number
  onPageChange: (p: number) => void
  /** Omit to keep a fixed page size (the SLA table still does). */
  onPageSizeChange?: (size: number) => void
}) {
  if (totalPages <= 1 && !onPageSizeChange) return null
  const start = (page - 1) * pageSize
  const end = Math.min(start + pageSize, total)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-secondary px-4 py-3">
      <span className="text-xs text-tertiary">
        Showing <span className="font-semibold text-primary">{total === 0 ? 0 : start + 1}</span> to{' '}
        <span className="font-semibold text-primary">{end}</span> of{' '}
        <span className="font-semibold text-primary">{total}</span> findings
      </span>
      <div className="flex items-center gap-2">
        {onPageSizeChange && (
          <Select
            value={String(pageSize)}
            onValueChange={(v) => onPageSizeChange(Number(v))}
            size="sm"
            ariaLabel="Findings per page"
            className="w-28"
            options={PAGE_SIZE_OPTIONS.map((n) => ({ value: String(n), label: `${n} / page` }))}
          />
        )}
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          aria-label="Previous page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"
        >
          <ChevronLeft className="size-4" aria-hidden="true" />
        </button>
        <span className="text-xs tabular-nums text-tertiary">
          Page <span className="font-semibold text-primary">{page}</span> of{' '}
          <span className="font-semibold text-primary">{totalPages}</span>
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages}
          aria-label="Next page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"
        >
          <ChevronRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}

export function FindingsTable({
  rows,
  page,
  expanded,
  focusedFindingId,
  vulnByKey,
  triageByKey,
  engagementId,
  onToggle,
  onUpdated,
  onReload,
  readOnly = false,
  readOnlyReason,
  pageSize = DEFAULT_PAGE_SIZE,
  sortKey = null,
  sortDirection = 'asc',
  onSort,
}: {
  rows: Finding[]
  page: number
  expanded: Set<string>
  focusedFindingId: string
  vulnByKey: Map<string, Vulnerability>
  triageByKey: Map<string, NonNullable<ScanResult['aiTriage']>[number]>
  engagementId: string
  onToggle: (id: string) => void
  onUpdated: (f: Finding) => void
  onReload: () => void
  readOnly?: boolean
  readOnlyReason?: string
  pageSize?: number
  sortKey?: FindingSortKey | null
  sortDirection?: SortDirection
  onSort?: (key: FindingSortKey) => void
}) {
  const header = (label: string, key: FindingSortKey, className: string) =>
    onSort ? (
      <SortableHeader
        label={label}
        sortKey={key}
        activeKey={sortKey}
        direction={sortDirection}
        onSort={onSort}
        className={className}
      />
    ) : (
      <th scope="col" className={className}>
        {label}
      </th>
    )

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-secondary bg-secondary text-[11px] font-bold uppercase tracking-wider text-secondary">
            <th className="w-8 pl-3 py-2.5" />
            {header('Pri', 'priority', 'px-2 py-2.5')}
            {header('Severity', 'severity', 'px-2 py-2.5')}
            {header('Finding & Details', 'title', 'px-4 py-2.5')}
            {header('Scope', 'scope', 'px-4 py-2.5')}
            {header('Status', 'status', 'px-4 py-2.5')}
          </tr>
        </thead>
        <tbody className="divide-y divide-secondary">
          {rows.slice((page - 1) * pageSize, page * pageSize).map((f) => {
            const v = vulnByKey.get(f.dedupKey)
            const triage = triageByKey.get(f.id) ?? triageByKey.get(f.dedupKey)
            const isOpen = expanded.has(f.id)
            return (
              <Fragment key={f.id}>
                <tr
                  id={findingAnchor(f.id)}
                  onClick={() => onToggle(f.id)}
                  className={cn(
                    'cursor-pointer transition-colors hover:bg-secondary',
                    isOpen && 'bg-secondary',
                    focusedFindingId === f.id && 'bg-brand-primary ring-1 ring-inset ring-brand-solid',
                  )}
                >
                  <td className="pl-3 py-3 align-top">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      aria-label={`Toggle details for ${f.title}`}
                      onClick={(e) => {
                        e.stopPropagation()
                        onToggle(f.id)
                      }}
                      className="rounded p-1 text-quaternary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
                    >
                      <ChevronRight className={cn('size-4 transition-transform', isOpen && 'rotate-90')} />
                    </button>
                  </td>
                  <td className="px-2 py-3 align-top">
                    <PriorityBadge priority={f.priority} />
                  </td>
                  <td className="px-2 py-3 align-top">
                    <SevBadge sev={f.severity} />
                  </td>
                  <td className="px-4 py-3 align-top">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-primary">{f.title}</span>
                      {f.kev && <KevBadge />}
                      {f.kind && f.kind !== 'sca' && <KindBadge kind={f.kind} />}
                      {f.cwe && (
                        <span className="rounded bg-secondary px-1.5 py-0.2 font-mono text-[11px] font-bold tabular-nums text-secondary">
                          {f.cwe}
                        </span>
                      )}
                      {triage && <AITriageBadges triage={triage} />}
                      {v && !v.direct && v.path.length >= 2 && (
                        <span
                          className="text-xs text-tertiary"
                          title={v.path.map(shortPkg).join(' › ')}
                        >
                          via <span className="font-mono font-medium text-secondary">{shortPkg(v.path[v.path.length - 2])}</span>
                        </span>
                      )}
                    </div>
                    {f.description && !isOpen && (
                      <div className="mt-1 line-clamp-1 text-xs text-tertiary">{f.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 align-top">
                    <ScopeBadge scope={f.scope} />
                  </td>
                  <td className="px-4 py-3 align-top" onClick={(e) => e.stopPropagation()}>
                    <FindingStatusControl
                      finding={f}
                      engagementId={engagementId}
                      onUpdated={onUpdated}
                      onReload={onReload}
                      readOnly={readOnly}
                      readOnlyReason={readOnlyReason}
                    />
                  </td>
                </tr>
                {isOpen && (
                  <tr className="bg-secondary border-t border-secondary">
                    <td />
                    <td colSpan={5} className="p-4">
                      <FindingDetail
                        finding={f}
                        vuln={v}
                        engagementId={engagementId}
                        onUpdated={onUpdated}
                        onReload={onReload}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
