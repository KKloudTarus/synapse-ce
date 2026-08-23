import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useProjectRouteContext } from './CodeQualityProject'
import { api, ApiError } from '../../lib/api'
import { useFetch } from '../../hooks'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import type { HotspotListFilter, HotspotPage } from '../../lib/types'
import { HotspotList } from '../../components/hotspots/HotspotList'
import { HotspotSidePanel } from '../../components/hotspots/HotspotSidePanel'

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
    if (initialPage) setPage(initialPage)
  }, [initialPage])

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
        <div className="flex items-center gap-6 rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div>
            <div className="text-sm font-medium text-tertiary">Total Hotspots</div>
            <div className="text-2xl font-bold text-primary">{page.summary.total}</div>
          </div>
          <div>
            <div className="text-sm font-medium text-tertiary">Reviewed</div>
            <div className="text-2xl font-bold text-primary">{page.summary.reviewed} ({formatOverviewPercentage(page.summary.reviewedPct)})</div>
          </div>
          <div>
            <div className="text-sm font-medium text-tertiary">Security Review Grade</div>
            <div className="text-2xl font-bold text-primary">{page.summary.grade}</div>
          </div>
          <div className="ml-auto flex items-center rounded-lg border border-secondary bg-secondary p-1">
            <button
              aria-pressed={lens === 'overall'}
              onClick={() => { const next = new URLSearchParams(params); next.set('lens', 'overall'); setParams(next) }}
              className={`rounded-md px-3 py-1 text-sm font-semibold transition-colors ${lens === 'overall' ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary'}`}
            >
              Overall
            </button>
            <button
              aria-pressed={lens === 'new-code'}
              onClick={() => { const next = new URLSearchParams(params); next.set('lens', 'new-code'); setParams(next) }}
              className={`rounded-md px-3 py-1 text-sm font-semibold transition-colors ${lens === 'new-code' ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary'}`}
            >
              New Code
            </button>
          </div>
        </div>
      )}
      <div className="flex flex-1 gap-4 overflow-hidden">
        <div className="flex flex-1 flex-col overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
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
      {selectedId && (
        <div className="w-[400px] shrink-0 overflow-y-auto rounded-xl border border-secondary bg-primary shadow-xs">
          <HotspotSidePanel
            projectKey={projectKey}
            hotspotId={selectedId}
            onClose={() => {
              const next = new URLSearchParams(params)
              next.delete('id')
              setParams(next)
            }}
            onTransition={() => {
              setRefreshCount(c => c + 1)
            }}
          />
        </div>
      )}
      </div>
    </div>
  )
}
