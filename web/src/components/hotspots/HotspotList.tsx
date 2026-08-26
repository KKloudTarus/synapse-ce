import {
  AlertTriangle,
  CheckCircle as CheckCircle2,
  SearchLg as Search,
  Shield01 as Shield,
  ShieldZap as ShieldAlert,
  ShieldTick as ShieldCheck,
  XClose as X,
} from '@untitledui/icons'
import { useEffect, useState } from 'react'
import type { HotspotListFilter, HotspotPage, HotspotStatus, Severity } from '../../lib/types'
import { FacetFilter } from '../rules/FacetFilter'
import { Button, EmptyState, ErrorState, Spinner, cn } from '../ui'

export function formatHotspotStatus(status: HotspotStatus) {
  switch (status) {
    case 'to_review': return 'To review'
    case 'acknowledged': return 'Acknowledged'
    case 'fixed': return 'Fixed'
    case 'safe': return 'Safe'
    default: return status
  }
}

function statusBadgeStyle(status: HotspotStatus) {
  switch (status) {
    case 'to_review':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'acknowledged':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'fixed':
      return 'bg-utility-purple-50 text-utility-purple-700 dark:bg-utility-purple-950/40 dark:text-utility-purple-300 border-utility-purple-200'
    case 'safe':
      return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

function severityBadgeStyle(severity: Severity | 'blocker' | 'major' | 'minor') {
  switch (severity) {
    case 'blocker':
    case 'critical':
      return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    case 'major':
    case 'high':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'medium':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'low':
    case 'minor':
    case 'info':
      return 'bg-secondary text-secondary border-secondary'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

function StatusIcon({ status, className }: { status: HotspotStatus; className?: string }) {
  switch (status) {
    case 'to_review': return <ShieldAlert className={cn('text-warning-primary', className)} />
    case 'acknowledged': return <AlertTriangle className={cn('text-utility-blue-600 dark:text-utility-blue-400', className)} />
    case 'fixed': return <CheckCircle2 className={cn('text-utility-purple-600 dark:text-utility-purple-400', className)} />
    case 'safe': return <ShieldCheck className={cn('text-success-primary', className)} />
    default: return <Shield className={className} />
  }
}

export function HotspotList({
  page,
  loading,
  error,
  filter,
  onFilterChange,
  onLoadMore,
  selectedId,
  onSelect,
}: {
  page: HotspotPage | null
  loading: boolean
  error: string | null
  filter: HotspotListFilter
  onFilterChange: (f: Partial<HotspotListFilter>) => void
  onLoadMore: () => void
  selectedId: string | null
  onSelect: (id: string | null) => void
}) {
  const [query, setQuery] = useState(filter.search || '')

  useEffect(() => {
    setQuery(filter.search || '')
  }, [filter.search])

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (query !== (filter.search || '')) {
        onFilterChange({ search: query })
      }
    }, 250)
    return () => clearTimeout(timeout)
  }, [query, filter.search, onFilterChange])

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 flex-col gap-2.5 border-b border-secondary bg-primary p-3.5">
        <div className="relative w-full">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-tertiary" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hotspots..."
            className="w-full rounded-lg border border-secondary bg-primary py-2 pl-9 pr-8 text-xs text-primary shadow-xs transition-colors placeholder:text-tertiary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
            maxLength={256}
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-tertiary hover:bg-secondary hover:text-primary"
              aria-label="Clear search"
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>
        {page?.facets && (
          <div className="flex items-center gap-2">
            <FacetFilter
              label="Status"
              values={Object.keys(page.facets.statuses)}
              selected={filter.status ? [filter.status] : []}
              formatValue={(v) => formatHotspotStatus(v as HotspotStatus)}
              onChange={(v) => onFilterChange({ status: v.length ? (v[v.length - 1] as HotspotStatus) : undefined })}
            />
            <FacetFilter
              label="Severity"
              values={Object.keys(page.facets.severities)}
              selected={filter.severity ? [filter.severity] : []}
              onChange={(v) => onFilterChange({ severity: v.length ? (v[v.length - 1] as Severity) : undefined })}
            />
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {error ? (
          <div className="p-6"><ErrorState message={error} /></div>
        ) : !page && loading ? (
          <div className="flex justify-center p-12"><Spinner className="size-6 text-brand" /></div>
        ) : page?.items.length === 0 ? (
          <div className="p-12">
            <EmptyState icon={ShieldCheck} title="No hotspots found" hint="Try adjusting your filters or search." />
          </div>
        ) : (
          <div className="divide-y divide-secondary">
            {page?.items.map((h) => {
              const isSelected = selectedId === h.id
              return (
                <button
                  key={h.id}
                  type="button"
                  onClick={() => onSelect(isSelected ? null : h.id)}
                  className={cn(
                    'flex w-full items-start gap-3 p-3.5 text-left transition-all',
                    isSelected
                      ? 'bg-brand-primary/10 border-l-3 border-l-brand-solid shadow-2xs'
                      : 'border-l-3 border-l-transparent hover:bg-secondary/40',
                  )}
                >
                  <StatusIcon status={h.status} className="mt-0.5 size-4 shrink-0" />
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <div className="font-semibold text-primary text-xs line-clamp-2 leading-snug break-words">
                      {h.title}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 text-xs">
                      <span className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10.5px] font-semibold border', statusBadgeStyle(h.status))}>
                        {formatHotspotStatus(h.status)}
                      </span>
                      <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10.5px] font-bold uppercase border', severityBadgeStyle(h.severity))}>
                        {h.severity}
                      </span>
                      <span className="font-mono text-[11px] text-tertiary truncate max-w-[140px]" title={h.ruleKey}>
                        {h.ruleKey}
                      </span>
                    </div>
                  </div>
                </button>
              )
            })}
            {loading && (
              <div className="flex justify-center p-6"><Spinner className="size-5 text-brand" /></div>
            )}
            {page?.next && !loading && (
              <div className="p-4 text-center">
                <Button variant="secondary" onClick={onLoadMore}>Load more</Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
