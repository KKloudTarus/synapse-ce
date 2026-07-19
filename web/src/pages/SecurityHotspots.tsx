import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useProjectRouteContext } from './CodeQualityProject'
import { api, ApiError } from '../lib/api'
import type { HotspotListFilter, HotspotPage } from '../lib/types'
import { HotspotList } from '../components/hotspots/HotspotList'
import { HotspotSidePanel } from '../components/hotspots/HotspotSidePanel'

export function SecurityHotspotsPage() {
  const { projectKey } = useProjectRouteContext()
  const [params, setParams] = useSearchParams()

  const lens = (params.get('lens') === 'new_code' ? 'new_code' : 'overall') as 'overall' | 'new_code'
  const status = params.get('status') as any || undefined
  const ruleKey = params.get('ruleKey') || undefined
  const severity = params.get('severity') as any || undefined
  const search = params.get('q') || undefined

  const filter = useMemo<HotspotListFilter>(() => ({
    status,
    ruleKey,
    severity,
    search,
    limit: 50,
  }), [status, ruleKey, severity, search])

  const [page, setPage] = useState<HotspotPage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const selectedId = params.get('id')

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    api.listProjectHotspots(projectKey, lens, filter)
      .then((res) => {
        if (!active) return
        setPage(res)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => { active = false }
  }, [projectKey, lens, filter])

  const loadMore = () => {
    if (!page?.next || loading) return
    setLoading(true)
    api.listProjectHotspots(projectKey, lens, { ...filter, beforeLastSeenAt: page.next.beforeLastSeenAt, beforeId: page.next.beforeId })
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
    <div className="flex h-[calc(100vh-16rem)] gap-4 overflow-hidden">
      <div className="flex flex-1 flex-col overflow-hidden rounded-xl border border-border bg-card shadow-sm">
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
            
            if (newFilter.ruleKey) next.set('ruleKey', newFilter.ruleKey)
            else next.delete('ruleKey')

            if (newFilter.severity) next.set('severity', newFilter.severity)
            else next.delete('severity')

            if (newFilter.search) next.set('q', newFilter.search)
            else next.delete('q')

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
        <div className="w-[400px] shrink-0 overflow-y-auto rounded-xl border border-border bg-card shadow-sm">
          <HotspotSidePanel
            projectKey={projectKey}
            hotspotId={selectedId}
            onClose={() => {
              const next = new URLSearchParams(params)
              next.delete('id')
              setParams(next)
            }}
          />
        </div>
      )}
    </div>
  )
}
