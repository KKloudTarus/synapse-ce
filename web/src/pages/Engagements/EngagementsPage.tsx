import { useMemo, useRef, useState, type FC } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Plus,
  Upload01,
  Target01,
  Activity,
  CheckCircle,
  LayersThree01,
} from '@untitledui/icons'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import { EngagementStatCard } from './components/EngagementStatCard'
import { EngagementFilterBar } from './components/EngagementFilterBar'
import { EngagementTable } from './components/EngagementTable'
import { PageError } from '../../components/synapse/PageError'
import type { Engagement } from '../../lib/types'
import type { EngagementStatusFilter, SortDirection, SortField } from './types'

export const EngagementsPage: FC = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const fileRef = useRef<HTMLInputElement>(null)

  // URL state sync
  const queryParam = searchParams.get('q') || ''
  const statusParam = (searchParams.get('status') as EngagementStatusFilter) || 'All'
  const scopeParam = searchParams.get('scope') || 'All'
  const pageParam = parseInt(searchParams.get('page') || '1', 10)
  const pageSizeParam = parseInt(searchParams.get('pageSize') || '20', 10)
  const sortParam = (searchParams.get('sort') as SortField) || 'lastScanDate'
  const dirParam = (searchParams.get('dir') as SortDirection) || 'desc'

  const [search, setSearch] = useState(queryParam)
  const [status, setStatus] = useState<EngagementStatusFilter>(statusParam)
  const [scope, setScope] = useState<string>(scopeParam)
  const [page, setPage] = useState(isNaN(pageParam) || pageParam < 1 ? 1 : pageParam)
  const [pageSize, setPageSize] = useState(isNaN(pageSizeParam) ? 20 : pageSizeParam)
  const [sortField, setSortField] = useState<SortField>(sortParam)
  const [sortDirection, setSortDirection] = useState<SortDirection>(dirParam)

  const [importing, setImporting] = useState(false)
  const [importErr, setImportErr] = useState<string | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)

  if (searchParams.get('create') === '1') {
    const assetId = searchParams.get('assetId')
    return (
      <Navigate
        replace
        to={assetId ? `/engagements/new?${new URLSearchParams({ assetId }).toString()}` : '/engagements/new'}
      />
    )
  }

  // Fetch engagements + assets
  const { data, error, loading } = useFetch<{ list: Engagement[]; assetNames: Record<string, string> }>(
    async () => {
      const engagements = await api.listEngagements()
      let assetNames: Record<string, string> = {}
      try {
        const pageResult = await api.listBusinessAssets('limit=200')
        assetNames = Object.fromEntries(pageResult.items.map((asset) => [asset.id, asset.name]))
      } catch {
        /* ignore asset name failures */
      }
      return { list: engagements, assetNames }
    },
    { deps: [refreshKey] },
  )

  const rawList = data?.list ?? []
  const assetNames = data?.assetNames ?? {}

  // Stat metrics (unfiltered)
  const totalCount = rawList.length
  const activeCount = rawList.filter((e) => e.status.toLowerCase() === 'active').length
  const completedCount = rawList.filter((e) => e.status.toLowerCase() === 'completed').length
  const unassignedCount = rawList.filter((e) => !e.businessAssetId).length

  // Filter & Search
  const filteredList = useMemo(() => {
    return rawList.filter((engagement) => {
      // Status filter
      if (status !== 'All' && engagement.status.toLowerCase() !== status.toLowerCase()) {
        return false
      }
      // Scope filter
      if (scope !== 'All') {
        const hasScope = engagement.inScope?.some((s) => {
          const k = s.kind.toLowerCase()
          if (scope === 'repo') return k === 'repo' || k === 'git_repo' || k === 'git'
          return k === scope.toLowerCase()
        })
        if (!hasScope) return false
      }
      // Query filter
      if (search.trim()) {
        const q = search.trim().toLowerCase()
        const nameMatch = engagement.name?.toLowerCase().includes(q)
        const idMatch = engagement.id?.toLowerCase().includes(q)
        const clientMatch = engagement.client?.toLowerCase().includes(q)
        const assetMatch = engagement.businessAssetId && assetNames[engagement.businessAssetId]?.toLowerCase().includes(q)
        const scopeMatch = engagement.inScope?.some((s) => s.value.toLowerCase().includes(q))
        if (!nameMatch && !idMatch && !clientMatch && !assetMatch && !scopeMatch) {
          return false
        }
      }
      return true
    })
  }, [rawList, status, scope, search, assetNames])

  // Sorting
  const sortedList = useMemo(() => {
    return [...filteredList].sort((a, b) => {
      let valA: any = ''
      let valB: any = ''

      if (sortField === 'name') {
        valA = (a.name || '').toLowerCase()
        valB = (b.name || '').toLowerCase()
      } else if (sortField === 'repository') {
        valA = (a.inScope[0]?.value || '').toLowerCase()
        valB = (b.inScope[0]?.value || '').toLowerCase()
      } else if (sortField === 'status') {
        valA = (a.status || '').toLowerCase()
        valB = (b.status || '').toLowerCase()
      } else if (sortField === 'findings') {
        const anyA = a as any
        const anyB = b as any
        valA = anyA.findingsCount?.total ?? 0
        valB = anyB.findingsCount?.total ?? 0
      } else {
        // lastScanDate or createdAt
        const anyA = a as any
        const anyB = b as any
        valA = new Date(anyA.lastScanDate || a.createdAt || 0).getTime()
        valB = new Date(anyB.lastScanDate || b.createdAt || 0).getTime()
      }

      if (valA < valB) return sortDirection === 'asc' ? -1 : 1
      if (valA > valB) return sortDirection === 'asc' ? 1 : -1
      return 0
    })
  }, [filteredList, sortField, sortDirection])

  // Pagination slice
  const paginatedList = useMemo(() => {
    const start = (page - 1) * pageSize
    return sortedList.slice(start, start + pageSize)
  }, [sortedList, page, pageSize])

  // Helper to update URL params
  const updateQueryParams = (newParams: Record<string, string | number | undefined>) => {
    setSearchParams(
      (prev) => {
        const updated = new URLSearchParams(prev)
        Object.entries(newParams).forEach(([key, val]) => {
          if (val === undefined || val === '' || val === 'All') {
            updated.delete(key)
          } else {
            updated.set(key, String(val))
          }
        })
        return updated
      },
      { replace: true },
    )
  }

  const handleSearchChange = (newSearch: string) => {
    setSearch(newSearch)
    setPage(1)
    updateQueryParams({ q: newSearch, page: 1 })
  }

  const handleStatusChange = (newStatus: EngagementStatusFilter) => {
    setStatus(newStatus)
    setPage(1)
    updateQueryParams({ status: newStatus, page: 1 })
  }

  const handleScopeChange = (newScope: string) => {
    setScope(newScope)
    setPage(1)
    updateQueryParams({ scope: newScope, page: 1 })
  }

  const handleClearFilters = () => {
    setSearch('')
    setStatus('All')
    setScope('All')
    setPage(1)
    updateQueryParams({ q: undefined, status: undefined, scope: undefined, page: 1 })
  }

  const handleSort = (field: SortField) => {
    let nextDir: SortDirection = 'asc'
    if (sortField === field) {
      nextDir = sortDirection === 'asc' ? 'desc' : 'asc'
    } else {
      nextDir = field === 'lastScanDate' || field === 'findings' ? 'desc' : 'asc'
    }
    setSortField(field)
    setSortDirection(nextDir)
    updateQueryParams({ sort: field, dir: nextDir })
  }

  const handlePageChange = (newPage: number) => {
    setPage(newPage)
    updateQueryParams({ page: newPage })
  }

  const handlePageSizeChange = (newPageSize: number) => {
    setPageSize(newPageSize)
    setPage(1)
    updateQueryParams({ pageSize: newPageSize, page: 1 })
  }

  const handleTransitionStatus = async (id: string, newStatus: string) => {
    try {
      await api.transitionEngagement(id, newStatus)
      setRefreshKey((k) => k + 1)
    } catch (err) {
      setImportErr(err instanceof Error ? err.message : 'Status transition failed')
    }
  }

  const handleImportFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setImporting(true)
    setImportErr(null)
    try {
      const engagement = await api.importBundle(await file.text())
      navigate(`/engagements/${engagement.id}`)
    } catch (nextError) {
      setImportErr(nextError instanceof Error ? nextError.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      {/* Page Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            Engagements
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Define scopes, link Assets, and track execution to completion
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={handleImportFile}
          />
          <button
            type="button"
            disabled={importing}
            onClick={() => fileRef.current?.click()}
            className="inline-flex items-center gap-2 rounded-lg border border-secondary bg-primary px-3.5 py-2 text-sm font-semibold text-secondary shadow-xs transition hover:bg-secondary hover:text-primary focus:outline-none focus:ring-2 focus:ring-brand/30 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Upload01 className="size-4 text-tertiary" />
            {importing ? 'Importing…' : 'Import bundle'}
          </button>

          <Link
            to="/engagements/new"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand-solid px-3.5 py-2 text-sm font-semibold text-white shadow-xs transition hover:bg-brand-solid_hover focus:outline-none focus:ring-2 focus:ring-brand/30"
          >
            <Plus className="size-4" />
            New Engagement
          </Link>
        </div>
      </header>

      {/* Import Error Banner */}
      {importErr && (
        <div className="rounded-xl border border-utility-red-200 bg-utility-red-50 p-4 text-xs font-medium text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
          {importErr}
        </div>
      )}

      {/* KPI Stat Cards Row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <EngagementStatCard
          label="Total"
          value={data ? totalCount : '—'}
          icon={Target01}
          tone="info"
          hint="All recorded scopes"
        />
        <EngagementStatCard
          label="Active"
          value={data ? activeCount : '—'}
          icon={Activity}
          tone="accent"
          hint="Currently undergoing test"
        />
        <EngagementStatCard
          label="Completed"
          value={data ? completedCount : '—'}
          icon={CheckCircle}
          tone="brand"
          hint="Closed assessments"
        />
        <EngagementStatCard
          label="Unassigned"
          value={data ? unassignedCount : '—'}
          icon={LayersThree01}
          tone={unassignedCount > 0 ? 'warning' : 'default'}
          hint="No connected business asset"
        />
      </div>

      {/* Error state */}
      {error && <PageError error={error} />}

      {/* Filter Bar */}
      <EngagementFilterBar
        search={search}
        onSearchChange={handleSearchChange}
        status={status}
        onStatusChange={handleStatusChange}
        scope={scope}
        onScopeChange={handleScopeChange}
        onClear={handleClearFilters}
        totalResults={filteredList.length}
      />

      {/* DataTable */}
      <EngagementTable
        engagements={paginatedList}
        assetNames={assetNames}
        loading={loading}
        isFiltered={Boolean(search.trim() || status !== 'All' || scope !== 'All')}
        sortField={sortField}
        sortDirection={sortDirection}
        onSort={handleSort}
        page={page}
        pageSize={pageSize}
        totalItems={filteredList.length}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        onStatusChange={handleTransitionStatus}
      />
    </div>
  )
}
