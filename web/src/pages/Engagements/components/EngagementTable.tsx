import { useState, type FC } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ChevronUp,
  ChevronDown,
  ArrowLeft,
  ArrowRight,
  Copy01,
  Check,
  Target01,
} from '@untitledui/icons'
import { StatusPill } from './StatusPill'
import { EngagementRowActions } from './EngagementRowActions'
import { SeverityBadge } from '../../../components/synapse/SeverityBadge'
import type { Engagement } from '../../../lib/types'
import type { SortField, SortDirection } from '../types'

export interface EngagementTableProps {
  engagements: Engagement[]
  assetNames: Record<string, string>
  loading?: boolean
  isFiltered?: boolean
  sortField: SortField
  sortDirection: SortDirection
  onSort: (field: SortField) => void
  page: number
  pageSize: number
  totalItems: number
  onPageChange: (newPage: number) => void
  onPageSizeChange: (newPageSize: number) => void
  onStatusChange?: (id: string, newStatus: string) => Promise<void>
  onDelete?: (id: string) => Promise<void>
}

function formatRelativeTime(dateString: string | null | undefined): string {
  if (!dateString) return '—'
  const date = new Date(dateString)
  if (isNaN(date.getTime())) return '—'
  const now = Date.now()
  const diffSec = Math.floor((now - date.getTime()) / 1000)
  if (diffSec < 60) return 'Just now'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHours = Math.floor(diffMin / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 30) return `${diffDays}d ago`
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

export const EngagementTable: FC<EngagementTableProps> = ({
  engagements,
  assetNames,
  loading = false,
  isFiltered = false,
  sortField,
  sortDirection,
  onSort,
  page,
  pageSize,
  totalItems,
  onPageChange,
  onPageSizeChange,
  onStatusChange,
  onDelete,
}) => {
  const navigate = useNavigate()
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const copyToClipboard = (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(id)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize))
  const startIndex = (page - 1) * pageSize + 1
  const endIndex = Math.min(totalItems, page * pageSize)

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return null
    }
    return sortDirection === 'asc' ? (
      <ChevronUp className="size-3.5 text-primary" />
    ) : (
      <ChevronDown className="size-3.5 text-primary" />
    )
  }

  return (
    <div className="flex flex-col overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
      {/* Table Container */}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-sm" role="table" aria-rowcount={totalItems + 1}>
          <thead>
            <tr className="border-b border-secondary bg-secondary/50 text-xs font-semibold text-tertiary">
              {/* Column 1: Name */}
              <th scope="col" className="px-5 py-3">
                <button
                  type="button"
                  onClick={() => onSort('name')}
                  className="flex items-center gap-1.5 font-semibold text-secondary hover:text-primary focus:outline-none"
                >
                  Name
                  {renderSortIcon('name')}
                </button>
              </th>

              {/* Column 2: In Scope */}
              <th scope="col" className="w-[200px] px-4 py-3">
                <button
                  type="button"
                  onClick={() => onSort('repository')}
                  className="flex items-center gap-1.5 font-semibold text-secondary hover:text-primary focus:outline-none"
                >
                  In Scope
                  {renderSortIcon('repository')}
                </button>
              </th>

              {/* Column 3: Status */}
              <th scope="col" className="w-[120px] px-4 py-3">
                <button
                  type="button"
                  onClick={() => onSort('status')}
                  className="flex items-center gap-1.5 font-semibold text-secondary hover:text-primary focus:outline-none"
                >
                  Status
                  {renderSortIcon('status')}
                </button>
              </th>

              {/* Column 4: Findings */}
              <th scope="col" className="w-[180px] px-4 py-3">
                <button
                  type="button"
                  onClick={() => onSort('findings')}
                  className="flex items-center gap-1.5 font-semibold text-secondary hover:text-primary focus:outline-none"
                >
                  Findings
                  {renderSortIcon('findings')}
                </button>
              </th>

              {/* Column 5: Last Scan */}
              <th scope="col" className="w-[150px] px-4 py-3">
                <button
                  type="button"
                  onClick={() => onSort('lastScanDate')}
                  className="flex items-center gap-1.5 font-semibold text-secondary hover:text-primary focus:outline-none"
                >
                  Last Scan
                  {renderSortIcon('lastScanDate')}
                </button>
              </th>

              {/* Column 6: Actions */}
              <th scope="col" className="w-[60px] px-4 py-3 text-right">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>

          <tbody className="divide-y divide-secondary">
            {loading ? (
              // Loading skeleton rows
              Array.from({ length: 6 }).map((_, idx) => (
                <tr key={`skeleton-${idx}`} className="animate-pulse">
                  <td className="px-5 py-4">
                    <div className="h-4 w-36 rounded bg-secondary" />
                    <div className="mt-1.5 h-3 w-24 rounded bg-secondary/60" />
                  </td>
                  <td className="px-4 py-4">
                    <div className="h-4 w-28 rounded bg-secondary" />
                  </td>
                  <td className="px-4 py-4">
                    <div className="h-5 w-16 rounded-full bg-secondary" />
                  </td>
                  <td className="px-4 py-4">
                    <div className="h-4 w-20 rounded bg-secondary" />
                  </td>
                  <td className="px-4 py-4">
                    <div className="h-4 w-20 rounded bg-secondary" />
                  </td>
                  <td className="px-4 py-4 text-right">
                    <div className="ml-auto size-6 rounded bg-secondary" />
                  </td>
                </tr>
              ))
            ) : engagements.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-5 py-12 text-center">
                  <div className="mx-auto flex max-w-sm flex-col items-center">
                    <div className="flex size-10 items-center justify-center rounded-full bg-secondary text-quaternary">
                      <Target01 className="size-5" />
                    </div>
                    <h3 className="mt-3 text-sm font-semibold text-primary">
                      {isFiltered ? 'No engagements found' : 'No engagements yet'}
                    </h3>
                    <p className="mt-1 text-xs text-tertiary">
                      {isFiltered
                        ? 'Try adjusting your search query or filter parameters.'
                        : 'Create one to define an authorized testing scope and connect the assessment to an Asset.'}
                    </p>
                    {!isFiltered && (
                      <Link
                        to="/engagements/new"
                        className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-brand-solid px-3.5 py-2 text-xs font-semibold text-white shadow-xs transition hover:bg-brand-solid_hover"
                      >
                        New Engagement
                      </Link>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              engagements.map((engagement) => {
                const targetRepo =
                  engagement.inScope.find((s) => s.kind === 'repo')?.value ||
                  engagement.inScope[0]?.value ||
                  (engagement.businessAssetId ? assetNames[engagement.businessAssetId] : '—')

                const anyEngagement = engagement as any
                const findingsCount = anyEngagement.findingsCount ?? null
                const totalFindings = findingsCount?.total ?? 0

                return (
                  <tr
                    key={engagement.id}
                    onClick={() => navigate(`/engagements/${engagement.id}`)}
                    className="group cursor-pointer transition-colors hover:bg-secondary/40"
                  >
                    {/* Column 1: Name + ID */}
                    <td className="px-5 py-3.5">
                      <div className="min-w-0">
                        <Link
                          to={`/engagements/${engagement.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="font-semibold text-primary transition-colors group-hover:text-brand-secondary"
                        >
                          {engagement.name || 'Untitled'}
                        </Link>
                        <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-tertiary">
                          <span className="truncate" title={engagement.id}>
                            {engagement.id.slice(0, 16)}
                            {engagement.id.length > 16 ? '…' : ''}
                          </span>
                          <button
                            type="button"
                            onClick={(e) => copyToClipboard(engagement.id, e)}
                            title="Copy ID"
                            aria-label={`Copy ID ${engagement.id}`}
                            className="rounded p-0.5 text-quaternary hover:text-primary focus:outline-none"
                          >
                            {copiedId === engagement.id ? (
                              <Check className="size-3 text-utility-green-600 dark:text-utility-green-400" />
                            ) : (
                              <Copy01 className="size-3" />
                            )}
                          </button>
                          {engagement.client && (
                            <span className="text-quaternary">· {engagement.client}</span>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Column 2: Repository / Scope */}
                    <td className="px-4 py-3.5">
                      <div className="truncate font-mono text-xs text-secondary" title={targetRepo}>
                        {targetRepo}
                      </div>
                      {engagement.businessAssetId && assetNames[engagement.businessAssetId] && (
                        <div className="truncate text-[11px] text-tertiary">
                          Asset: {assetNames[engagement.businessAssetId]}
                        </div>
                      )}
                    </td>

                    {/* Column 3: Status */}
                    <td className="px-4 py-3.5">
                      <StatusPill status={engagement.status} />
                    </td>

                    {/* Column 4: Findings breakdown */}
                    <td className="px-4 py-3.5">
                      {totalFindings > 0 ? (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-xs font-semibold tabular-nums text-primary">
                            {totalFindings}
                          </span>
                          {findingsCount.critical > 0 && (
                            <SeverityBadge
                              severity="critical"
                              size="sm"
                              showIcon={false}
                              className="font-mono text-[10px] tabular-nums"
                            />
                          )}
                          {findingsCount.high > 0 && (
                            <SeverityBadge
                              severity="high"
                              size="sm"
                              showIcon={false}
                              className="font-mono text-[10px] tabular-nums"
                            />
                          )}
                          {findingsCount.medium > 0 && (
                            <SeverityBadge
                              severity="medium"
                              size="sm"
                              showIcon={false}
                              className="font-mono text-[10px] tabular-nums"
                            />
                          )}
                        </div>
                      ) : (
                        <span className="font-mono text-xs text-tertiary">—</span>
                      )}
                    </td>

                    {/* Column 5: Last Scan */}
                    <td className="px-4 py-3.5">
                      <span
                        className="font-mono text-xs text-secondary"
                        title={anyEngagement.lastScanDate || engagement.createdAt || undefined}
                      >
                        {formatRelativeTime(anyEngagement.lastScanDate || engagement.createdAt)}
                      </span>
                    </td>

                    {/* Column 6: Actions menu */}
                    <td className="px-4 py-3.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <EngagementRowActions
                        engagement={engagement}
                        onStatusChange={onStatusChange}
                        onDelete={onDelete}
                      />
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <footer className="flex flex-col gap-3 border-t border-secondary px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3 text-xs text-tertiary">
          <span>
            Showing <strong className="font-semibold text-secondary">{totalItems === 0 ? 0 : startIndex}</strong>–
            <strong className="font-semibold text-secondary">{endIndex}</strong> of{' '}
            <strong className="font-semibold text-secondary">{totalItems}</strong> engagements
          </span>

          <div className="flex items-center gap-1.5 pl-3 border-l border-secondary">
            <label htmlFor="page-size-select" className="text-xs text-tertiary">
              Rows:
            </label>
            <select
              id="page-size-select"
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              aria-label="Rows per page"
              className="rounded border border-secondary bg-primary px-2 py-0.5 text-xs font-medium text-secondary shadow-xs outline-none focus:border-brand"
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>

        {/* Page navigation */}
        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            aria-label="Previous page"
            className="inline-flex items-center gap-1 rounded-lg border border-secondary bg-primary px-2.5 py-1.5 text-xs font-semibold text-secondary shadow-xs transition hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowLeft className="size-3.5" />
          </button>

          <div className="px-2 text-xs font-medium text-secondary">
            Page {page} of {totalPages}
          </div>

          <button
            type="button"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            aria-label="Next page"
            className="inline-flex items-center gap-1 rounded-lg border border-secondary bg-primary px-2.5 py-1.5 text-xs font-semibold text-secondary shadow-xs transition hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowRight className="size-3.5" />
          </button>
        </div>
      </footer>
    </div>
  )
}
