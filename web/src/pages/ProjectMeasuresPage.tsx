import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Folder, File, ChevronRight, AlertCircle } from 'lucide-react'
import { api } from '../lib/api'
import { Button, EmptyState, ErrorState, Spinner, Pill, cn } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { useProjectRouteContext, ProjectRouteEmpty } from './CodeQualityProject'
import type { 
  ProjectMeasureResponse, 
  MeasureNode, 
  MeasureCountMetric, 
  MeasureDecimalMetric, 
  MeasureGradeMetric 
} from '../lib/projectMeasures'

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

  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ProjectMeasureResponse | null>(null)
  
  const abortController = useRef<AbortController | null>(null)
  const requestGenerationRef = useRef(0)

  useEffect(() => {
    let live = true
    setLoading(true)
    setError(null)
    setData(null)
    
    requestGenerationRef.current += 1

    if (abortController.current) {
      abortController.current.abort()
    }
    const ac = new AbortController()
    abortController.current = ac

    api.projectMeasures(projectKey, { path, domain: [domain], limit: 100 }, ac.signal)
      .then((res) => {
        if (!live) return
        setData(res)
      })
      .catch((err) => {
        if (!live || err.name === 'AbortError') return
        setError(err instanceof Error ? err.message : 'Failed to load measures')
      })
      .finally(() => {
        if (live) setLoading(false)
      })

    return () => {
      live = false
      ac.abort()
    }
  }, [projectKey, path, domain])

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
      }, abortController.current?.signal)
      
      if (
        generation !== requestGenerationRef.current ||
        requestedPath !== path ||
        requestedDomain !== domain
      ) {
        return
      }
      setData((prev) => {
        if (!prev) return res
        // Prevent duplicated rows by using a simple Set of paths (though backend handles cursor correctly)
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

  if (loading) return <Spinner label="Loading measures…" />
  if (error && !data) return <ErrorState message={error} />
  if (!data || data.state === 'not_analyzed') return <ProjectRouteEmpty running={job?.status === 'running'} />

  // Breadcrumbs processing
  const parts = path ? path.split('/') : []
  const breadcrumbs = []
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
        <nav className="flex items-center text-sm font-medium text-mutedfg" aria-label="Breadcrumb">
          <button
            onClick={() => setPath('')}
            aria-current={breadcrumbs.length === 0 ? 'page' : undefined}
            className="rounded-sm hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            {data.project.name}
          </button>
          {breadcrumbs.map((b, i) => (
            <div key={b.path} className="flex items-center">
              <ChevronRight className="size-4 mx-1" aria-hidden="true" />
              <button
                onClick={() => setPath(b.path)}
                aria-current={i === breadcrumbs.length - 1 ? 'page' : undefined}
                className={cn("rounded-sm hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60", i === breadcrumbs.length - 1 && "text-foreground")}
              >
                {b.label}
              </button>
            </div>
          ))}
        </nav>

        {/* Domain Selector */}
        <div className="flex gap-1 bg-elevated p-1 rounded-lg border border-border">
          {DOMAINS.map(d => (
            <button
              key={d.key}
              onClick={() => setDomain(d.key)}
              aria-pressed={domain === d.key}
              className={cn(
                "px-3 py-1.5 text-xs font-medium rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60",
                domain === d.key ? "bg-bg text-foreground shadow-sm ring-1 ring-border" : "text-mutedfg hover:text-foreground hover:bg-elevated/50"
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
        <div className="bg-card border border-border rounded-xl overflow-hidden">
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
              <thead className="bg-elevated/95 text-[11px] uppercase tracking-[0.14em] text-foreground border-b border-borderstrong sticky top-0">
                <tr>
                  {columns(setPath).map((c) => (
                    <th key={c.header} scope="col" className={cn("px-4 py-3 font-semibold", c.className)}>{c.header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {sortedItems.map(item => (
                  <tr key={item.path} className="hover:bg-elevated/40 transition-colors">
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

function MetricValue({ m }: { m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined }) {
  if (!m) return <span className="text-mutedfg" title="Omitted">-</span>
  if (m.availability === 'not_applicable') {
    return <span className="text-subtlefg" title="Not applicable">N/A</span>
  }
  if (m.availability === 'unavailable') {
    return (
      <span className="text-mutedfg flex items-center gap-1" title={m.reason ?? 'Unavailable'}>
        -
        {m.reason && <AlertCircle className="size-3 text-branddim" aria-hidden="true" />}
      </span>
    )
  }
  
  if ('grade' in m) {
    return <span className="font-medium font-mono">{m.grade}</span>
  }
  
  if (m.value === null) return <span className="text-mutedfg">-</span>

  // Round decimals (e.g. coverage/density percentages) and group large counts, matching the
  // sibling tabs; small integers render unchanged.
  return <span className="tabular-nums font-mono">{m.value.toLocaleString(undefined, { maximumFractionDigits: 2 })}</span>
}

function CurrentNodeMeasures({ node, domain }: { node: MeasureNode, domain: string }) {
  const metrics: { label: string, m: MeasureCountMetric | MeasureDecimalMetric | MeasureGradeMetric | undefined }[] = []
  
  if (domain === 'size') {
    metrics.push(
      { label: 'Files', m: node.size?.files },
      { label: 'Lines of Code', m: node.size?.ncloc },
      { label: 'Functions', m: node.size?.functions },
      { label: 'Comment Lines', m: node.size?.commentLines },
      { label: 'Blank Lines', m: node.size?.blankLines },
      { label: 'Comment Density', m: node.size?.commentDensity }
    )
  } else if (domain === 'complexity') {
    metrics.push(
      { label: 'Cyclomatic', m: node.complexity?.cyclomatic },
      { label: 'Cognitive', m: node.complexity?.cognitive }
    )
  } else if (domain === 'coverage') {
    metrics.push(
      { label: 'Coverage', m: node.coverage?.coverage },
      { label: 'New Code Coverage', m: node.coverage?.newCodeCoverage },
      { label: 'Covered Lines', m: node.coverage?.coveredLines },
      { label: 'Coverable Lines', m: node.coverage?.coverableLines }
    )
  } else if (domain === 'duplication') {
    metrics.push(
      { label: 'Duplication Density', m: node.duplication?.duplicationDensity },
      { label: 'Duplicated Lines', m: node.duplication?.duplicatedLines },
      { label: 'Duplication Blocks', m: node.duplication?.duplicationBlocks }
    )
  } else if (domain === 'issues') {
    metrics.push(
      { label: 'Bugs', m: node.issues?.byType['bug'] },
      { label: 'Vulnerabilities', m: node.issues?.byType['vulnerability'] },
      { label: 'Code Smells', m: node.issues?.byType['code_smell'] },
      { label: 'Security Hotspots', m: node.issues?.byType['security_hotspot'] },
      { label: 'Critical', m: node.issues?.bySeverity['critical'] },
      { label: 'High', m: node.issues?.bySeverity['high'] },
      { label: 'Medium', m: node.issues?.bySeverity['medium'] },
      { label: 'Low', m: node.issues?.bySeverity['low'] },
      { label: 'Info', m: node.issues?.bySeverity['info'] }
    )
  } else if (domain === 'debt') {
    metrics.push(
      { label: 'Remediation Effort (mins)', m: node.debt?.remediationEffortMinutes }
    )
  } else if (domain === 'ratings') {
    metrics.push(
      { label: 'Security', m: node.ratings?.security },
      { label: 'Reliability', m: node.ratings?.reliability },
      { label: 'Maintainability', m: node.ratings?.maintainability }
    )
  }

  return (
    <div className="bg-card border border-border rounded-xl p-4">
      <h3 className="text-sm font-semibold mb-3">Current Node Metrics</h3>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
        {metrics.map((item) => (
          <div key={item.label} className="flex flex-col gap-1">
            <span className="text-xs font-medium text-mutedfg">{item.label}</span>
            <div className="text-sm"><MetricValue m={item.m} /></div>
          </div>
        ))}
      </div>
    </div>
  )
}

function getDomainColumns(domain: string): (setPath: (p: string) => void) => Column<MeasureNode>[] {
  const baseColumns: (setPath: (p: string) => void) => Column<MeasureNode>[] = (setPath) => [
    {
      header: 'Name',
      className: 'w-[40%]',
      cell: (item) => {
        const navigable = item.kind === 'directory' || item.kind === 'file'
        return (
          <div className="flex items-center gap-2">
            {item.kind === 'directory' ? <Folder className="size-4 text-branddim shrink-0" aria-hidden="true" /> : <File className="size-4 text-mutedfg shrink-0" aria-hidden="true" />}
            {navigable ? (
              <button
                onClick={() => setPath(item.path)}
                className="rounded-sm font-medium hover:underline hover:text-brand text-left truncate focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                title={item.name}
              >
                {item.name}
              </button>
            ) : (
              <span className="font-medium truncate" title={item.name}>{item.name}</span>
            )}
          </div>
        )
      }
    },
    {
      header: 'Kind',
      className: 'w-[15%]',
      cell: (item) => <span className="capitalize">{item.kind}</span>
    },
    {
      header: 'Language',
      className: 'w-[15%]',
      cell: (item) => item.language ? <Pill>{item.language}</Pill> : null
    },
  ]

  return (setPath) => {
    const base = baseColumns(setPath)
    switch (domain) {
      case 'size':
        return [
          ...base,
          { header: 'Files', cell: (i) => <MetricValue m={i.size?.files} /> },
          { header: 'Code Lines', cell: (i) => <MetricValue m={i.size?.ncloc} /> },
          { header: 'Functions', cell: (i) => <MetricValue m={i.size?.functions} /> },
        ]
      case 'complexity':
        return [
          ...base,
          { header: 'Cyclomatic', cell: (i) => <MetricValue m={i.complexity?.cyclomatic} /> },
          { header: 'Cognitive', cell: (i) => <MetricValue m={i.complexity?.cognitive} /> },
        ]
      case 'coverage':
        return [
          ...base,
          { header: 'Coverage %', cell: (i) => <MetricValue m={i.coverage?.coverage} /> },
          { header: 'New Code %', cell: (i) => <MetricValue m={i.coverage?.newCodeCoverage} /> },
          { header: 'Covered Lines', cell: (i) => <MetricValue m={i.coverage?.coveredLines} /> },
        ]
      case 'duplication':
        return [
          ...base,
          { header: 'Duplication %', cell: (i) => <MetricValue m={i.duplication?.duplicationDensity} /> },
          { header: 'Duplicated Lines', cell: (i) => <MetricValue m={i.duplication?.duplicatedLines} /> },
          { header: 'Blocks', cell: (i) => <MetricValue m={i.duplication?.duplicationBlocks} /> },
        ]
      case 'issues':
        return [
          ...base,
          { header: 'Bugs', cell: (i) => <MetricValue m={i.issues?.byType['bug']} /> },
          { header: 'Vulnerabilities', cell: (i) => <MetricValue m={i.issues?.byType['vulnerability']} /> },
          { header: 'Code Smells', cell: (i) => <MetricValue m={i.issues?.byType['code_smell']} /> },
          { header: 'Hotspots', cell: (i) => <MetricValue m={i.issues?.byType['security_hotspot']} /> },
        ]
      case 'debt':
        return [
          ...base,
          { header: 'Remediation Effort', cell: (i) => <MetricValue m={i.debt?.remediationEffortMinutes} /> },
        ]
      case 'ratings':
        return [
          ...base,
          { header: 'Security', cell: (i) => <MetricValue m={i.ratings?.security} /> },
          { header: 'Reliability', cell: (i) => <MetricValue m={i.ratings?.reliability} /> },
          { header: 'Maintainability', cell: (i) => <MetricValue m={i.ratings?.maintainability} /> },
        ]
      default:
        return base
    }
  }
}
