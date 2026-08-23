import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Folder, ChevronRight } from 'lucide-react'
import { api } from '../../../lib/api'
import { useFetch } from '../../../hooks'
import { Button, EmptyState, ErrorState, cn } from '../../../components/ui'
import { VirtualTable } from '../../../components/synapse/VirtualTable'
import { useProjectRouteContext, ProjectRouteEmpty } from '../CodeQualityProject'
import type { ProjectMeasureResponse } from '../../../lib/projectMeasures'
import { getDomainColumns, CurrentNodeMeasures } from './measureColumns'

const DOMAINS = [
  { key: 'size', label: 'Size' },
  { key: 'complexity', label: 'Complexity' },
  { key: 'coverage', label: 'Coverage' },
  { key: 'duplication', label: 'Duplications' },
  { key: 'issues', label: 'Issues' },
  { key: 'debt', label: 'Technical Debt' },
  { key: 'ratings', label: 'Ratings' },
]

export function ProjectMeasuresPage() {
  const { projectKey, job } = useProjectRouteContext()
  const [searchParams, setSearchParams] = useSearchParams()
  const path = searchParams.get('path') ?? ''
  const domain = searchParams.get('domain') ?? 'size'

  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ProjectMeasureResponse | null>(null)
  
  const requestGenerationRef = useRef(0)

  const { data: fetchedData, loading, error: fetchError } = useFetch(
    (signal) => api.projectMeasures(projectKey, { path, domain: [domain], limit: 100 }, signal),
    { deps: [projectKey, path, domain] },
  )

  // Sync fetched data to local state (needed for loadMore appending)
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
        cursor: data.children.nextCursor
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
        const existing = new Set(prev.children.items.map(x => x.path))
        const newItems = res.children.items.filter(x => !existing.has(x.path))
        return {
          ...prev,
          children: {
            items: [...prev.children.items, ...newItems],
            nextCursor: res.children.nextCursor,
          }
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
  }

  function setDomain(newDomain: string) {
    const sp = new URLSearchParams(searchParams)
    sp.set('domain', newDomain)
    setSearchParams(sp)
  }

  if (loading) return <div className="h-20" />
  if (error && !data) return <ErrorState message={error} />
  if (!data || data.state === 'not_analyzed') return <ProjectRouteEmpty running={job?.status === 'running'} />

  // Breadcrumbs processing
  const parts = path ? path.split('/') : []
  const breadcrumbs: { label: string; path: string }[] = []
  let currentPath = ''
  for (let i = 0; i < parts.length; i++) {
    currentPath += (i === 0 ? '' : '/') + parts[i]
    breadcrumbs.push({ label: parts[i], path: currentPath })
  }

  // Sort children: directories first
  const sortedItems = [...data.children.items].sort((a, b) => {
    if (a.kind === 'directory' && b.kind !== 'directory') return -1
    if (a.kind !== 'directory' && b.kind === 'directory') return 1
    return a.name.localeCompare(b.name)
  })

  const columns = getDomainColumns(domain)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Breadcrumbs */}
        <nav className="flex items-center text-sm font-medium text-tertiary" aria-label="Breadcrumb">
          <button
            onClick={() => setPath('')}
            aria-current={breadcrumbs.length === 0 ? 'page' : undefined}
            className="rounded-sm hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            {data.project.name}
          </button>
          {breadcrumbs.map((b, i) => (
            <div key={b.path} className="flex items-center">
              <ChevronRight className="size-4 mx-1" aria-hidden="true" />
              <button
                onClick={() => setPath(b.path)}
                aria-current={i === breadcrumbs.length - 1 ? 'page' : undefined}
                className={cn("rounded-sm hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60", i === breadcrumbs.length - 1 && "text-primary font-semibold")}
              >
                {b.label}
              </button>
            </div>
          ))}
        </nav>

        {/* Domain Selector */}
        <div className="flex flex-wrap items-center gap-1 rounded-lg border border-secondary bg-secondary p-1">
          {DOMAINS.map(d => (
            <button
              key={d.key}
              type="button"
              onClick={() => setDomain(d.key)}
              aria-pressed={domain === d.key}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60",
                domain === d.key ? "bg-primary text-brand-secondary shadow-xs" : "text-tertiary hover:text-primary"
              )}
            >
              {d.label}
            </button>
          ))}
        </div>
      </div>

      {error && <ErrorState message={error} />}
      
      {data.node && (
        <CurrentNodeMeasures node={data.node} domain={domain} />
      )}

      {data.node?.kind !== 'file' && (
        <div className="bg-primary border border-secondary rounded-xl overflow-hidden shadow-xs">
          {sortedItems.length === 0 ? (
            <EmptyState
              icon={Folder}
              title="Empty directory"
              hint="This directory has no measurable children."
            />
        ) : sortedItems.length > 50 ? (
          <VirtualTable
            columns={columns(setPath)}
            items={sortedItems}
            rowKey={(item) => item.path}
            totalItems={undefined}
          />
        ) : (
          <div className="overflow-x-auto min-w-full">
            <table className="min-w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-secondary/95 text-[11px] uppercase tracking-[0.14em] text-primary border-b border-secondary sticky top-0">
                <tr>
                  {columns(setPath).map((c) => (
                    <th key={c.header} scope="col" className={cn("px-4 py-3 font-semibold", c.className)}>{c.header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-secondary">
                {sortedItems.map(item => (
                  <tr key={item.path} className="hover:bg-secondary/50 transition-colors">
                    {columns(setPath).map((c) => (
                      <td key={c.header} className={cn("px-4 py-3 min-w-0 truncate", c.className)}>
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

      {data.node?.kind !== 'file' && data.children.nextCursor && (
        <div className="flex justify-center pt-4">
          <Button variant="secondary" onClick={loadMore} loading={loadingMore}>
            Load more
          </Button>
        </div>
      )}
    </div>
  )
}
