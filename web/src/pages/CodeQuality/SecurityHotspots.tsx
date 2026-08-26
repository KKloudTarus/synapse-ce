import { CheckCircle, ShieldTick, Target04 } from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { HotspotList } from '../../components/hotspots/HotspotList'
import { HotspotSidePanel } from '../../components/hotspots/HotspotSidePanel'
import { EmptyState, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import type { HotspotListFilter, HotspotPage } from '../../lib/types'
import { useProjectRouteContext } from './CodeQualityProject'

function getGradeColor(grade: string) {
  switch (grade) {
    case 'A': return 'text-success-primary'
    case 'B': return 'text-utility-blue-600 dark:text-utility-blue-400'
    case 'C': return 'text-warning-primary'
    case 'D': return 'text-utility-orange-600 dark:text-utility-orange-400'
    case 'E': return 'text-error-primary'
    default: return 'text-primary'
  }
}

function getGradePillStyle(grade: string) {
  switch (grade) {
    case 'A': return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    case 'B': return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'C': return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'D': return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'E': return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    default: return 'bg-secondary text-secondary border-secondary'
  }
}

export function SecurityHotspotsPage() {
  const { projectKey } = useProjectRouteContext()
  const [params, setParams] = useSearchParams()

  const lens = (params.get('lens') === 'new-code' ? 'new-code' : 'overall') as 'overall' | 'new-code'
  const status = params.get('status') as any || undefined
  const rule = params.get('rule') || undefined
  const severity = params.get('severity') as any || undefined
  const search = params.get('search') || undefined

  const filter = useMemo<HotspotListFilter>(() => ({
    status,
    rule,
    severity,
    search,
    limit: 50,
  }), [status, rule, severity, search])

  const [page, setPage] = useState<HotspotPage | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refreshCount, setRefreshCount] = useState(0)

  const selectedId = params.get('id')

  const { data: initialPage, error: fetchError } = useFetch(
    () => api.listProjectHotspots(projectKey, lens, filter),
    { deps: [projectKey, lens, filter, refreshCount] },
  )

  useEffect(() => {
    if (initialPage) {
      setPage(initialPage)
      // Auto-select first hotspot if none selected
      if (initialPage.items.length > 0 && !params.get('id')) {
        const next = new URLSearchParams(params)
        next.set('id', initialPage.items[0].id)
        setParams(next, { replace: true })
      }
    }
  }, [initialPage, params, setParams])

  useEffect(() => {
    if (fetchError) setError(fetchError)
    else setError(null)
  }, [fetchError])

  const loadMore = () => {
    if (!page?.next || loading) return
    setLoading(true)
    api.listProjectHotspots(projectKey, lens, { ...filter, before_last_seen_at: page.next.beforeLastSeenAt, before_id: page.next.beforeId })
      .then((res) => {
        setPage((prev) => prev ? { ...res, items: [...prev.items, ...res.items] } : res)
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        setLoading(false)
      })
  }

  return (
    <div className="flex h-[calc(100vh-16rem)] flex-col gap-4 overflow-hidden">
      {page?.summary && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex flex-wrap items-center gap-6">
            {/* KPI 1: Total */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <Target04 className="size-5 text-primary" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Total Hotspots</div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-primary">{page.summary.total}</div>
              </div>
            </div>

            <div className="h-8 w-px bg-secondary hidden sm:block" />

            {/* KPI 2: Reviewed */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <CheckCircle className="size-5 text-success-primary" aria-hidden="true" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-tertiary">Reviewed</span>
                  <span className="font-mono text-xs font-bold text-success-primary">
                    {formatOverviewPercentage(page.summary.reviewedPct)}
                  </span>
                </div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-primary">
                  {page.summary.reviewed} <span className="text-sm font-normal text-tertiary">/ {page.summary.total}</span>
                </div>
              </div>
            </div>

            <div className="h-8 w-px bg-secondary hidden sm:block" />

            {/* KPI 3: Security Review Grade */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <ShieldTick className="size-5 text-brand-secondary" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Review Grade</div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className={cn('text-2xl font-mono font-extrabold tabular-nums', getGradeColor(page.summary.grade))}>
                    {page.summary.grade}
                  </span>
                  <span className={cn('text-xs font-semibold px-2 py-0.5 rounded-md border', getGradePillStyle(page.summary.grade))}>
                    Rating {page.summary.grade}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div role="group" aria-label="Hotspots code lens" className="flex items-center gap-1 rounded-lg border border-secondary bg-secondary p-1">
            <button
              type="button"
              aria-pressed={lens === 'overall'}
              onClick={() => { const next = new URLSearchParams(params); next.set('lens', 'overall'); setParams(next) }}
              className={cn(
                'rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
                lens === 'overall'
                  ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                  : 'text-tertiary hover:text-primary',
              )}
            >
              Overall Code
            </button>
            <button
              type="button"
              aria-pressed={lens === 'new-code'}
              onClick={() => { const next = new URLSearchParams(params); next.set('lens', 'new-code'); setParams(next) }}
              className={cn(
                'rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
                lens === 'new-code'
                  ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                  : 'text-tertiary hover:text-primary',
              )}
            >
              New Code
            </button>
          </div>
        </div>
      )}

      {/* 2-Pane Master-Detail Inspector Layout */}
      <div className="flex flex-1 gap-4 overflow-hidden min-h-0">
        {/* Left Column: Master Hotspots List */}
        <div className="w-full lg:w-[400px] xl:w-[440px] shrink-0 flex flex-col overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
          <HotspotList
            page={page}
            loading={loading}
            error={error}
            filter={filter}
            onLoadMore={loadMore}
            onFilterChange={(newFilter) => {
              const next = new URLSearchParams(params)
              if (newFilter.status) next.set('status', newFilter.status)
              else next.delete('status')

              if (newFilter.rule) next.set('rule', newFilter.rule)
              else next.delete('rule')

              if (newFilter.severity) next.set('severity', newFilter.severity)
              else next.delete('severity')

              if (newFilter.search) next.set('search', newFilter.search)
              else next.delete('search')

              setParams(next, { replace: true })
            }}
            selectedId={selectedId}
            onSelect={(id) => {
              const next = new URLSearchParams(params)
              if (id) next.set('id', id)
              else next.delete('id')
              setParams(next)
            }}
          />
        </div>

        {/* Right Column: Full-Width Tabbed Inspector */}
        <div className="hidden lg:flex flex-1 min-w-0 flex-col overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
          {selectedId ? (
            <HotspotSidePanel
              projectKey={projectKey}
              hotspotId={selectedId}
              onClose={() => {
                const next = new URLSearchParams(params)
                next.delete('id')
                setParams(next)
              }}
              onTransition={() => {
                setRefreshCount((c) => c + 1)
              }}
            />
          ) : (
            <div className="flex h-full items-center justify-center p-8">
              <EmptyState
                icon={ShieldTick}
                title="Select a security hotspot"
                hint="Choose a hotspot from the list to inspect risk evidence, analyze code location, and submit review decisions."
              />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
