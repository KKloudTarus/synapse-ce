import {
  AlertTriangle,
  ChevronRight,
  Dataflow04,
  Download01,
  GitBranch01,
  Package,
  SearchLg,
  Shield01,
  Scale01,
} from '@untitledui/icons'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Button, Card, EmptyState, ErrorState, Input, Pill, SevBadge, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import {
  allPathsToDependency,
  buildProjectDependencyIndex,
  countDescendants,
  matchesDependencyNode,
  projectDependencyTreeRows,
  visibleDependencyIDs,
  vulnerablePathIDs,
  type DependencyFilter,
  type ProjectDependencyIndex,
} from '../../lib/projectDependencyGraph'
import { CATEGORY_LABEL } from '../../lib/severity'
import type { ProjectDependencyNode } from '../../lib/types'
import { ProjectRouteEmpty, useProjectRouteContext } from './CodeQualityProject'

const FILTERS: Array<{ id: DependencyFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'vulnerable', label: 'Vulnerable' },
  { id: 'license-risk', label: 'License risk' },
  { id: 'direct', label: 'Direct' },
  { id: 'transitive', label: 'Transitive' },
]

export function ProjectDependencyGraphPage() {
  const { project, projectKey, analysisRevision, isRunning } = useProjectRouteContext()
  const { data: graph, loading, error, refetch } = useFetch((signal) => api.projectDependencyGraph(projectKey, signal), {
    deps: [projectKey, analysisRevision],
  })
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<DependencyFilter>('all')
  const [selectedID, setSelectedID] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const index = useMemo(() => graph ? buildProjectDependencyIndex(graph) : null, [graph])
  const visible = useMemo(
    () => index ? visibleDependencyIDs(index, filter, search) : new Set<string>(),
    [filter, index, search],
  )
  const riskyPaths = useMemo(() => index ? vulnerablePathIDs(index) : new Set<string>(), [index])
  const searchMatches = useMemo(() => {
    if (!index || !search.trim()) return []
    return [...index.nodes.values()]
      .filter((node) => matchesDependencyNode(node, 'all', search))
      .sort(compareNodes)
      .slice(0, 100)
  }, [index, search])
  const selected = index?.nodes.get(selectedID) ?? null
  const tree = useMemo(
    () => index ? projectDependencyTreeRows(index, visible, expanded) : { rows: [], truncated: false },
    [expanded, index, visible],
  )

  useEffect(() => {
    if (!index) return
    setExpanded(new Set(index.roots))
    setSelectedID((current) => current && index.nodes.has(current) ? current : index.roots[0] ?? index.nodes.keys().next().value ?? '')
  }, [index])

  useEffect(() => {
    if (!index || (filter === 'all' && !search.trim())) return
    setExpanded((current) => {
      const next = new Set(current)
      for (const id of visible) {
        if (index.children.get(id)?.some((child) => visible.has(child))) next.add(id)
      }
      return next
    })
  }, [filter, index, search, visible])

  if (loading && !graph) {
    return <Card><EmptyState icon={Dataflow04} title="Loading dependency graph" hint="Building a read-only view from the latest project SBOM." /></Card>
  }
  if (!project.latestAnalysis && !graph) return <ProjectRouteEmpty running={isRunning} />
  if (error && !graph) {
    return <div className="space-y-4"><ErrorState message={error} /><Button variant="secondary" onClick={refetch}>Retry dependency graph</Button></div>
  }
  if (!graph || !index) return null
  if (graph.nodes.length === 0) {
    return <Card><EmptyState icon={Package} title="No dependencies found" hint="The latest analysis contains no SBOM components to explore." /></Card>
  }

  async function exportSBOM(root = '') {
    if (exporting) return
    setExporting(true)
    setExportError(null)
    try {
      await api.downloadProjectDependencySubtree(projectKey, root)
    } catch (reason) {
      setExportError(reason instanceof Error ? reason.message : 'Failed to export dependency SBOM')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Metric icon={<Package className="size-4" />} label="Components" value={graph.summary.components} />
        <Metric icon={<GitBranch01 className="size-4" />} label="Direct" value={graph.summary.direct} />
        <Metric icon={<Dataflow04 className="size-4" />} label="Transitive" value={graph.summary.transitive} />
        <Metric icon={<Shield01 className="size-4" />} label="Vulnerable" value={graph.summary.vulnerable} risk={graph.summary.vulnerable > 0} />
        <Metric icon={<Scale01 className="size-4" />} label="License risk" value={graph.summary.licenseRisk} risk={graph.summary.licenseRisk > 0} />
      </div>

      <Card
        title={<span className="inline-flex items-center gap-2"><Dataflow04 className="size-4 text-brand-secondary" /> Dependency explorer</span>}
        actions={<Button variant="secondary" loading={exporting} onClick={() => exportSBOM()}><Download01 className="size-4" /> Export full SBOM</Button>}
        bodyClass="space-y-4"
      >
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
          <label className="relative min-w-0 flex-1">
            <span className="sr-only">Search dependencies</span>
            <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" aria-hidden="true" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Find a package, version, or PURL…"
              className="pl-9"
            />
          </label>
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Dependency filters">
            {FILTERS.map((option) => (
              <button
                key={option.id}
                type="button"
                aria-pressed={filter === option.id}
                onClick={() => setFilter(option.id)}
                className={cn(
                  'rounded-lg px-3 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                  filter === option.id ? 'bg-brand-primary text-brand-secondary ring-1 ring-inset ring-brand/25' : 'bg-secondary text-tertiary hover:text-primary',
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {exportError && <ErrorState message={exportError} />}

        {search.trim() && (
          <div className="rounded-lg border border-secondary bg-secondary-subtle p-3">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-tertiary">
              {searchMatches.length} package match{searchMatches.length === 1 ? '' : 'es'}
            </p>
            {searchMatches.length > 0 ? (
              <div className="flex max-h-28 flex-wrap gap-1.5 overflow-auto">
                {searchMatches.map((node) => (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => setSelectedID(node.id)}
                    className={cn(
                      'rounded-md border px-2 py-1 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                      selectedID === node.id ? 'border-brand bg-brand-primary text-brand-secondary' : 'border-secondary bg-primary text-secondary hover:border-primary',
                    )}
                  >
                    {node.name}<span className="ml-1 text-quaternary">{node.version}</span>
                  </button>
                ))}
              </div>
            ) : <p className="text-sm text-quaternary">No component matches this search.</p>}
          </div>
        )}

        <div className="grid min-h-[34rem] overflow-hidden rounded-xl border border-secondary lg:grid-cols-[minmax(0,1.35fr)_minmax(20rem,0.65fr)]">
          <section className="min-w-0 border-b border-secondary lg:border-b-0 lg:border-r" aria-label="Dependency tree">
            <div className="flex items-center justify-between border-b border-secondary bg-secondary-subtle px-4 py-3">
              <div>
                <h3 className="text-sm font-semibold text-primary">Dependency tree</h3>
                <p className="text-xs text-quaternary">Red branches lead to a vulnerable package.</p>
              </div>
              <span className="text-xs tabular-nums text-tertiary">{visible.size} shown</span>
            </div>
            <div className="max-h-[44rem] overflow-auto p-2">
              {tree.rows.length > 0 ? tree.rows.map((row) => (
                <DependencyTreeRow
                  key={row.id}
                  node={index.nodes.get(row.id)!}
                  level={row.level}
                  index={index}
                  visible={visible}
                  riskyPaths={riskyPaths}
                  open={expanded.has(row.id)}
                  selectedID={selectedID}
                  onSelect={setSelectedID}
                  onToggle={(id) => setExpanded((current) => {
                    const next = new Set(current)
                    if (next.has(id)) next.delete(id)
                    else next.add(id)
                    return next
                  })}
                />
              )) : (
                <EmptyState icon={SearchLg} title="No dependencies match" hint="Change the search or filter to restore the tree." />
              )}
              {tree.truncated && (
                <p className="m-2 flex items-center gap-1.5 rounded-lg border border-medium/25 bg-medium/5 p-3 text-xs text-medium">
                  <AlertTriangle className="size-3.5 shrink-0" /> Tree display is limited to 5,000 packages. Narrow the search or filter to inspect the remainder.
                </p>
              )}
            </div>
          </section>
          <DependencyDetails node={selected} index={index} exporting={exporting} onExport={exportSBOM} />
        </div>
      </Card>
    </div>
  )
}

function Metric({ icon, label, value, risk = false }: { icon: ReactNode; label: string; value: number; risk?: boolean }) {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className={cn('mb-2 inline-flex rounded-lg bg-secondary p-2 text-tertiary', risk && 'bg-critical/10 text-critical')}>{icon}</div>
      <div className={cn('text-2xl font-bold tabular-nums text-primary', risk && 'text-critical')}>{value}</div>
      <div className="text-xs text-tertiary">{label}</div>
    </div>
  )
}

function DependencyTreeRow({
  node,
  level,
  index,
  visible,
  riskyPaths,
  open,
  selectedID,
  onSelect,
  onToggle,
}: {
  node: ProjectDependencyNode
  level: number
  index: ProjectDependencyIndex
  visible: Set<string>
  riskyPaths: Set<string>
  open: boolean
  selectedID: string
  onSelect: (id: string) => void
  onToggle: (id: string) => void
}) {
  const hasChildren = index.children.get(node.id)?.some((child) => visible.has(child)) ?? false

  return (
    <div className="flex items-center" style={{ paddingLeft: `${Math.min(level, 20) * 18}px` }}>
      <button
        type="button"
        aria-label={hasChildren ? `${open ? 'Collapse' : 'Expand'} ${node.name}` : undefined}
        tabIndex={hasChildren ? 0 : -1}
        disabled={!hasChildren}
        onClick={() => onToggle(node.id)}
        className="inline-flex size-7 shrink-0 items-center justify-center rounded text-quaternary hover:bg-secondary hover:text-primary disabled:opacity-30"
      >
        <ChevronRight className={cn('size-3.5 transition-transform', open && 'rotate-90')} aria-hidden="true" />
      </button>
      <button
        type="button"
        onClick={() => onSelect(node.id)}
        className={cn(
          'my-0.5 flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-transparent px-2.5 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
          selectedID === node.id ? 'border-brand/30 bg-brand-primary' : 'hover:bg-secondary',
          riskyPaths.has(node.id) && 'border-l-critical',
        )}
      >
        <Package className={cn('size-4 shrink-0 text-tertiary', node.vulnerabilityCount > 0 && 'text-critical')} aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-primary">{node.name}</span>
        {node.version && <span className="max-w-28 truncate font-mono text-[11px] text-quaternary">{node.version}</span>}
        {node.vulnerabilityCount > 0 && <Pill className="bg-critical/10 text-critical">{node.vulnerabilityCount} vuln</Pill>}
        {node.licenseRisk && <Scale01 className="size-3.5 shrink-0 text-medium" aria-label="License risk" />}
        {node.depth < 0 && <Pill>cycle</Pill>}
      </button>
    </div>
  )
}

function DependencyDetails({
  node,
  index,
  exporting,
  onExport,
}: {
  node: ProjectDependencyNode | null
  index: ProjectDependencyIndex
  exporting: boolean
  onExport: (root: string) => Promise<void>
}) {
  const paths = useMemo(() => node ? allPathsToDependency(index, node.id) : { paths: [], truncated: false }, [index, node])
  const descendants = useMemo(() => node ? countDescendants(index, node.id) : 0, [index, node])

  if (!node) {
    return <aside className="p-4"><EmptyState icon={Package} title="Select a package" hint="Package risk and reverse dependency paths will appear here." /></aside>
  }

  return (
    <aside className="min-w-0 overflow-auto bg-primary p-5" aria-label="Package details">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wide text-tertiary">Package details</p>
          <h3 className="mt-1 break-words text-lg font-semibold text-primary">{node.name}</h3>
          <p className="font-mono text-xs text-quaternary">{node.version || 'Version unknown'}</p>
        </div>
        <Button variant="secondary" loading={exporting} onClick={() => onExport(node.id)} title={`Export ${node.name} and its dependencies`}>
          <Download01 className="size-4" /> Subtree
        </Button>
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-3 text-sm">
        <Detail label="Relationship" value={node.direct ? 'Direct' : 'Transitive'} />
        <Detail label="Depth" value={node.depth >= 0 ? String(node.depth) : 'Cycle / unrooted'} />
        <Detail label="Scope" value={node.scope || 'Unknown'} />
        <Detail label="Reachability" value={node.reachability || 'Unknown'} />
        <Detail label="Dependencies" value={String(descendants)} />
        <Detail label="Used by" value={String(index.parents.get(node.id)?.length ?? 0)} />
      </dl>

      {node.purl && (
        <div className="mt-4 rounded-lg bg-secondary-subtle p-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-quaternary">PURL</div>
          <code className="mt-1 block break-all text-xs text-secondary">{node.purl}</code>
        </div>
      )}

      <section className="mt-6">
        <h4 className="flex items-center gap-2 text-sm font-semibold text-primary"><Shield01 className="size-4" /> Vulnerabilities ({node.vulnerabilityCount})</h4>
        {node.vulnerabilities.length > 0 ? (
          <ul className="mt-2 space-y-2">
            {node.vulnerabilities.map((vulnerability) => (
              <li key={`${vulnerability.source}:${vulnerability.id}`} className="rounded-lg border border-critical/20 bg-critical/5 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-primary">{vulnerability.id}</span>
                  <SevBadge sev={vulnerability.severity} />
                </div>
                <div className="mt-1 text-xs text-tertiary">
                  {vulnerability.source || 'Unknown source'}{vulnerability.fixedVersion ? ` · Fixed in ${vulnerability.fixedVersion}` : ' · No fix recorded'}
                </div>
              </li>
            ))}
          </ul>
        ) : <p className="mt-2 text-sm text-quaternary">No matched vulnerabilities.</p>}
      </section>

      <section className="mt-6">
        <h4 className="flex items-center gap-2 text-sm font-semibold text-primary"><Scale01 className="size-4" /> Licenses</h4>
        {node.licenses.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {node.licenses.map((license) => (
              <Pill key={`${license.id}:${license.name}`} className={node.licenseRisk ? 'bg-medium/10 text-medium' : undefined}>
                {license.id || license.name || 'Unknown'} · {CATEGORY_LABEL[license.category] ?? license.category}
              </Pill>
            ))}
          </div>
        ) : <p className="mt-2 text-sm text-quaternary">No license detected.</p>}
      </section>

      <section className="mt-6">
        <h4 className="flex items-center gap-2 text-sm font-semibold text-primary"><GitBranch01 className="size-4" /> Paths to this package ({paths.paths.length})</h4>
        <p className="mt-1 text-xs text-quaternary">Reverse lookup: every known reason this package is included.</p>
        <ol className="mt-3 space-y-2">
          {paths.paths.map((path, pathIndex) => (
            <li key={`${path.join('>')}:${pathIndex}`} className={cn('rounded-lg border p-3', node.vulnerabilityCount > 0 ? 'border-critical/25 bg-critical/5' : 'border-secondary bg-secondary-subtle')}>
              <div className="flex flex-wrap items-center gap-1 text-xs">
                {path.map((id, indexInPath) => (
                  <span key={`${id}:${indexInPath}`} className="contents">
                    {indexInPath > 0 && <ChevronRight className={cn('size-3', node.vulnerabilityCount > 0 ? 'text-critical' : 'text-quaternary')} aria-hidden="true" />}
                    <span className={cn('font-medium', id === node.id ? 'text-primary' : 'text-secondary')}>{index.nodes.get(id)?.name ?? id}</span>
                  </span>
                ))}
              </div>
            </li>
          ))}
        </ol>
        {paths.truncated && (
          <p className="mt-2 flex items-center gap-1 text-xs text-medium"><AlertTriangle className="size-3.5" /> Showing the first 50 paths.</p>
        )}
      </section>
    </aside>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-[10px] font-semibold uppercase tracking-wide text-quaternary">{label}</dt><dd className="mt-0.5 break-words text-secondary">{value}</dd></div>
}

function compareNodes(left: ProjectDependencyNode, right: ProjectDependencyNode): number {
  return left.name.localeCompare(right.name) || left.version.localeCompare(right.version) || left.id.localeCompare(right.id)
}
