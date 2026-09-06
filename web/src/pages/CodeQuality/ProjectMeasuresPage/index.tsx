import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  ChevronRight,
  Clock,
  Copy01,
  CpuChip01,
  File01,
  FileCode01,
  Folder,
  FolderClosed,
  SearchLg as Search,
  ShieldTick,
  Star01,
  Virus,
  XClose,
} from '@untitledui/icons'
import { api } from '../../../lib/api'
import { useFetch } from '../../../hooks'
import { Button, EmptyState, ErrorState, cn } from '../../../components/ui'
import { VirtualTable } from '../../../components/synapse/VirtualTable'
import { useProjectRouteContext, ProjectRouteEmpty } from '../CodeQualityProject'
import type { ProjectMeasureResponse } from '../../../lib/projectMeasures'
import { getDomainColumns, CurrentNodeMeasures } from './measureColumns'

const DOMAINS = [
  { key: 'size', label: 'Size', icon: FileCode01 },
  { key: 'complexity', label: 'Complexity', icon: CpuChip01 },
  { key: 'coverage', label: 'Coverage', icon: ShieldTick },
  { key: 'duplication', label: 'Duplications', icon: Copy01 },
  { key: 'issues', label: 'Issues', icon: Virus },
  { key: 'debt', label: 'Technical Debt', icon: Clock },
  { key: 'ratings', label: 'Ratings', icon: Star01 },
]

export function ProjectMeasuresPage() {
  const { projectKey, job } = useProjectRouteContext()
  const [searchParams, setSearchParams] = useSearchParams()
  const path = searchParams.get('path') ?? ''
  const domain = searchParams.get('domain') ?? 'size'

  const [searchQuery, setSearchQuery] = useState('')
  const [kindFilter, setKindFilter] = useState<'all' | 'directory' | 'file'>('all')

  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ProjectMeasureResponse | null>(null)

  const requestGenerationRef = useRef(0)

  const { data: fetchedData, loading, error: fetchError } = useFetch(
    (signal) => api.projectMeasures(projectKey, { path, domain: [domain], limit: 100 }, signal),
    { deps: [projectKey, path, domain] },
  )

  // Sync fetched data to local state
  useEffect(() => {
    if (fetchedData) {
      setData(fetchedData)
      requestGenerationRef.current += 1
    }
  }, [fetchedData])

  useEffect(() => {
    if (fetchError) setError(fetchError)
    else setError(null)
  }, [fetchError])

  async function loadMore() {
    if (!data?.children.nextCursor || loadingMore) return
    setLoadingMore(true)
    setError(null)

    const generation = requestGenerationRef.current
    const requestedPath = path
    const requestedDomain = domain

    try {
      const res = await api.projectMeasures(projectKey, {
        path,
        domain: [domain],
        limit: 100,
        cursor: data.children.nextCursor,
      })

      if (
        generation !== requestGenerationRef.current ||
        requestedPath !== path ||
        requestedDomain !== domain
      ) {
        return
      }
      setData((prev) => {
        if (!prev) return res
        const existing = new Set(prev.children.items.map((x) => x.path))
        const newItems = res.children.items.filter((x) => !existing.has(x.path))
        return {
          ...prev,
          children: {
            items: [...prev.children.items, ...newItems],
            nextCursor: res.children.nextCursor,
          },
        }
      })
    } catch (error) {
      if (generation !== requestGenerationRef.current) return
      if (error instanceof DOMException && error.name === 'AbortError') return

      setError(error instanceof Error ? error.message : 'Failed to load more')
    } finally {
      setLoadingMore(false)
    }
  }

  function setPath(newPath: string) {
    const sp = new URLSearchParams(searchParams)
    if (newPath) sp.set('path', newPath)
    else sp.delete('path')
    setSearchParams(sp)
    setSearchQuery('')
  }

  function setDomain(newDomain: string) {
    const sp = new URLSearchParams(searchParams)
    sp.set('domain', newDomain)
    setSearchParams(sp)
  }

  // Breadcrumbs processing
  const parts = path ? path.split('/') : []
  const breadcrumbs: { label: string; path: string }[] = []
  let currentPath = ''
  for (let i = 0; i < parts.length; i++) {
    currentPath += (i === 0 ? '' : '/') + parts[i]
    breadcrumbs.push({ label: parts[i], path: currentPath })
  }

  // Filter and sort items
  const sortedAndFilteredItems = useMemo(() => {
    if (!data) return []
    const query = searchQuery.trim().toLowerCase()

    return [...data.children.items]
      .filter((item) => {
        if (query && !item.name.toLowerCase().includes(query)) return false
        if (kindFilter === 'directory' && item.kind !== 'directory') return false
        if (kindFilter === 'file' && item.kind !== 'file') return false
        return true
      })
      .sort((a, b) => {
        if (a.kind === 'directory' && b.kind !== 'directory') return -1
        if (a.kind !== 'directory' && b.kind === 'directory') return 1
        return a.name.localeCompare(b.name)
      })
  }, [data, kindFilter, searchQuery])

  const totalFolders = useMemo(() => {
    return data?.children.items.filter((x) => x.kind === 'directory').length ?? 0
  }, [data])

  const totalFiles = useMemo(() => {
    return data?.children.items.filter((x) => x.kind === 'file').length ?? 0
  }, [data])

  const totalLinesInNode = data?.node?.size?.ncloc?.value ?? 0
  const columns = useMemo(() => getDomainColumns(domain, totalLinesInNode), [domain, totalLinesInNode])
  // Build the resolved column array once: columns(setPath) allocates fresh cell
  // closures, so calling it per row (as before) rebuilt them on every render.
  const cols = columns(setPath)

  // Only blank on the first load. loading is also true while refetching after a
  // path/domain change, and blanking then wiped the breadcrumbs and selector.
  if (loading && !data) return <div className="h-20" />
  if (error && !data) return <ErrorState message={error} />
  if (!data || data.state === 'not_analyzed') return <ProjectRouteEmpty running={job?.status === 'running'} />

  return (
    <div className="space-y-5">
      {/* Top Bar: Breadcrumbs & Domain Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Breadcrumb Navigation */}
        <nav className="flex flex-wrap items-center text-xs font-semibold text-tertiary" aria-label="Breadcrumb">
          <button
            onClick={() => setPath('')}
            aria-current={breadcrumbs.length === 0 ? 'page' : undefined}
            className={cn(
              'inline-flex items-center gap-1.5 rounded px-2 py-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
              breadcrumbs.length === 0
                ? 'bg-secondary text-primary font-bold shadow-2xs'
                : 'hover:bg-secondary/60 hover:text-primary',
            )}
          >
            <FolderClosed className="size-3.5 text-brand-secondary shrink-0" aria-hidden="true" />
            <span>{data.project.name}</span>
          </button>
          {breadcrumbs.map((b, i) => (
            <div key={b.path} className="flex items-center">
              <ChevronRight className="size-3.5 mx-0.5 text-quaternary" aria-hidden="true" />
              <button
                onClick={() => setPath(b.path)}
                aria-current={i === breadcrumbs.length - 1 ? 'page' : undefined}
                className={cn(
                  'rounded px-2 py-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                  i === breadcrumbs.length - 1
                    ? 'bg-secondary text-primary font-bold shadow-2xs'
                    : 'hover:bg-secondary/60 hover:text-primary',
                )}
              >
                {b.label}
              </button>
            </div>
          ))}
        </nav>

        {/* Domain Segmented Control */}
        <div className="flex flex-wrap items-center gap-1 rounded-xl border border-secondary bg-secondary/40 p-1 shadow-2xs" aria-label="Measures domain">
          {DOMAINS.map((d) => {
            const Icon = d.icon
            const isSelected = domain === d.key
            return (
              <button
                key={d.key}
                type="button"
                onClick={() => setDomain(d.key)}
                aria-pressed={isSelected}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                  isSelected
                    ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary hover:bg-secondary/50',
                )}
              >
                <Icon className={cn('size-3.5', isSelected ? 'text-brand-secondary' : 'text-tertiary')} />
                <span>{d.label}</span>
              </button>
            )
          })}
        </div>
      </div>

      {error && <ErrorState message={error} />}

      {/* Current Node KPI Cards */}
      {data.node && <CurrentNodeMeasures node={data.node} domain={domain} />}

      {/* Directory Content Table & Instant Filters */}
      {data.node?.kind !== 'file' && (
        <div className="rounded-xl border border-secondary bg-primary overflow-hidden shadow-xs">
          {/* Table Header Filter Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-secondary bg-secondary/20 p-3">
            {/* Search Box */}
            <div className="relative min-w-[220px] max-w-sm flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter files or directories..."
                className="w-full rounded-lg border border-secondary bg-primary py-1.5 pl-8 pr-7 text-xs text-primary shadow-2xs placeholder:text-tertiary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary hover:bg-secondary hover:text-primary"
                  aria-label="Clear search"
                >
                  <XClose className="size-3" />
                </button>
              )}
            </div>

            {/* Kind Quick Filter Pills */}
            <div className="flex items-center gap-1.5 text-xs">
              <button
                type="button"
                onClick={() => setKindFilter('all')}
                className={cn(
                  'rounded-lg px-2.5 py-1 text-xs font-semibold transition-all border',
                  kindFilter === 'all'
                    ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                    : 'border-secondary bg-primary text-tertiary hover:bg-secondary hover:text-primary',
                )}
              >
                All ({data.children.items.length})
              </button>
              <button
                type="button"
                onClick={() => setKindFilter('directory')}
                className={cn(
                  'inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold transition-all border',
                  kindFilter === 'directory'
                    ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                    : 'border-secondary bg-primary text-tertiary hover:bg-secondary hover:text-primary',
                )}
              >
                <FolderClosed className="size-3 text-brand-secondary" />
                <span>Folders ({totalFolders})</span>
              </button>
              <button
                type="button"
                onClick={() => setKindFilter('file')}
                className={cn(
                  'inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold transition-all border',
                  kindFilter === 'file'
                    ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                    : 'border-secondary bg-primary text-tertiary hover:bg-secondary hover:text-primary',
                )}
              >
                <File01 className="size-3 text-tertiary" />
                <span>Files ({totalFiles})</span>
              </button>
            </div>
          </div>

          {/* Table Body */}
          {sortedAndFilteredItems.length === 0 ? (
            <EmptyState
              icon={Folder}
              title={searchQuery ? 'No matching files or folders' : 'Empty directory'}
              hint={searchQuery ? 'Try adjusting your search query or filter.' : 'This directory has no measurable children.'}
            />
          ) : sortedAndFilteredItems.length > 50 ? (
            <VirtualTable
              columns={cols}
              items={sortedAndFilteredItems}
              rowKey={(item) => item.path}
              totalItems={undefined}
            />
          ) : (
            <div className="overflow-x-auto min-w-full">
              <table className="min-w-full text-left text-sm whitespace-nowrap">
                <thead className="bg-secondary/40 text-[10px] uppercase tracking-wider text-tertiary border-b border-secondary sticky top-0 font-bold font-sans">
                  <tr>
                    {cols.map((c, ci) => (
                      <th key={ci} scope="col" className={cn('px-4 py-2.5 font-bold', c.className)}>
                        {c.header}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-secondary/40 font-sans text-xs">
                  {sortedAndFilteredItems.map((item) => (
                    <tr key={item.path} className="hover:bg-secondary/40 transition-colors group">
                      {cols.map((c, ci) => (
                        <td key={ci} className={cn('px-4 py-2.5 min-w-0 truncate', c.className)}>
                          {c.cell(item)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Load More Button */}
      {data.node?.kind !== 'file' && data.children.nextCursor && (
        <div className="flex justify-center pt-2">
          <Button variant="secondary" onClick={loadMore} loading={loadingMore}>
            Load more
          </Button>
        </div>
      )}
    </div>
  )
}
