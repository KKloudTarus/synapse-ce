import { Search, X, ShieldAlert, CheckCircle2, ShieldCheck, Shield, AlertTriangle } from 'lucide-react'
import { useState, useEffect } from 'react'
import type { HotspotListFilter, HotspotPage, HotspotStatus, Severity } from '../../lib/types'
import { Button, EmptyState, ErrorState, Spinner, cn } from '../ui'
import { FacetFilter } from '../rules/FacetFilter'

export function formatHotspotStatus(status: HotspotStatus) {
  switch (status) {
    case 'to_review': return 'To review'
    case 'acknowledged': return 'Acknowledged'
    case 'fixed': return 'Fixed'
    case 'safe': return 'Safe'
    default: return status
  }
}

function StatusIcon({ status, className }: { status: HotspotStatus; className?: string }) {
  switch (status) {
    case 'to_review': return <ShieldAlert className={cn('text-high', className)} />
    case 'acknowledged': return <AlertTriangle className={cn('text-medium', className)} />
    case 'fixed': return <CheckCircle2 className={cn('text-accent', className)} />
    case 'safe': return <ShieldCheck className={cn('text-brand', className)} />
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
      <div className="flex shrink-0 flex-col gap-3 border-b border-border bg-surface p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-mutedfg" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search hotspots..."
              className="w-full rounded-lg border border-border bg-card py-1.5 pl-9 pr-8 text-sm text-foreground transition-colors placeholder:text-mutedfg focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand shadow-sm"
              maxLength={256}
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-mutedfg hover:bg-surface hover:text-foreground"
              >
                <X className="size-3.5" />
              </button>
            )}
          </div>
          {page?.facets && (
            <>
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
            </>
          )}
        </div>
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
          <div className="divide-y divide-border">
            {page?.items.map((h) => (
              <button
                key={h.id}
                onClick={() => onSelect(selectedId === h.id ? null : h.id)}
                className={cn(
                  'flex w-full items-start gap-4 p-4 text-left transition-colors hover:bg-surface/50 focus:outline-none focus:ring-2 focus:ring-brand/60 focus:ring-inset',
                  selectedId === h.id ? 'bg-brand/10 border-l-2 border-l-brand' : 'border-l-2 border-l-transparent'
                )}
              >
                <StatusIcon status={h.status} className="mt-1 size-5 shrink-0" />
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="font-medium text-foreground line-clamp-2">{h.title}</div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-mutedfg">
                    <span className="font-mono">{h.ruleKey}</span>
                    <span>&bull;</span>
                    <span className="capitalize">{h.severity}</span>
                  </div>
                </div>
              </button>
            ))}
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
