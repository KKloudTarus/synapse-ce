import { Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import {
  findingMatchesRatedDimension,
  ratedFindingDimensionLabel,
  ratedFindingDimensionValues,
  type RatedFindingDimension,
} from '../../lib/ratedFindingDimensions'
import type { Finding } from '../../lib/types'
import { Card, EmptyState, Input, Pill, Select, SevBadge } from '../ui'

const pageSize = 50
const findingKey = (finding: Finding) => JSON.stringify([finding.id ?? '', finding.dedupKey ?? ''])
type FindingKindFilter = 'all' | `dimension:${RatedFindingDimension}` | `kind:${string}`

export function FindingExplorer({
  findings,
  headingId,
  initialDimension = null,
  dimensionNavigationKey,
}: {
  findings: Finding[]
  headingId?: string
  initialDimension?: RatedFindingDimension | null
  dimensionNavigationKey?: string
}) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [kindFilter, setKindFilter] = useState<FindingKindFilter>(() => dimensionFilter(initialDimension))
  const [selected, setSelected] = useState<Finding | null>(null)
  const [shown, setShown] = useState(pageSize)
  const kinds = useMemo(() => [...new Set(findings.map((finding) => finding.kind))].sort(), [findings])
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return findings.filter((finding) => (!needle || `${finding.title} ${finding.description} ${finding.cwe}`.toLowerCase().includes(needle)) && (severity === 'all' || finding.severity === severity) && matchesKindFilter(finding, kindFilter))
  }, [findings, kindFilter, query, severity])
  const rendered = visible.slice(0, shown)

  useEffect(() => {
    setKindFilter(dimensionFilter(initialDimension))
    setSelected(null)
  }, [dimensionNavigationKey, initialDimension])
  useEffect(() => setShown(pageSize), [visible])
  useEffect(() => setSelected((current) => current ? visible.find((finding) => findingKey(finding) === findingKey(current)) ?? null : null), [visible])

  return <Card title="Analysis findings" titleId={headingId} titleTabIndex={headingId ? -1 : undefined} titleClassName={headingId ? 'scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60' : undefined} actions={<Pill className="tabular-nums">{findings.length.toLocaleString()} findings</Pill>} bodyClass="p-0">
    {findings.length === 0 ? <div className="p-5"><EmptyState icon={Search} title="No analysis findings" hint="This analysis did not produce publishable findings." /></div> : <>
      <div className="grid gap-3 border-b border-border p-4 md:grid-cols-[1fr_10rem_12rem]"><label className="relative"><span className="sr-only">Search findings</span><Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtlefg" aria-hidden="true" /><Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search title, description, or CWE…" /></label><Select value={severity} onValueChange={setSeverity} ariaLabel="Filter findings by severity" options={[{ value: 'all', label: 'All severities' }, ...['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((value) => ({ value, label: value }))]} /><Select value={kindFilter} onValueChange={(value) => setKindFilter(value as FindingKindFilter)} ariaLabel="Filter findings by kind" options={[{ value: 'all', label: 'All kinds' }, ...ratedFindingDimensionValues.map((dimension) => ({ value: `dimension:${dimension}`, label: ratedFindingDimensionLabel(dimension) })), ...kinds.map((value) => ({ value: `kind:${value}`, label: value || 'Legacy security kind' }))]} /></div>
      <div className="grid min-h-64 md:grid-cols-[minmax(0,1fr)_22rem]"><div className="max-h-[34rem] overflow-y-auto divide-y divide-border">{visible.length === 0 ? <p className="p-5 text-sm text-mutedfg">No findings match these filters.</p> : <>{rendered.map((finding) => <button key={findingKey(finding)} type="button" onClick={() => setSelected(finding)} aria-pressed={selected !== null && findingKey(selected) === findingKey(finding)} className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-elevated/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/60 aria-pressed:bg-brand/5"><SevBadge sev={finding.severity} /><div className="min-w-0 flex-1"><div className="text-sm font-medium text-foreground">{finding.title}</div><div className="mt-1 flex flex-wrap gap-2 text-xs text-mutedfg"><span>{finding.kind}</span>{finding.cwe && <span>{finding.cwe}</span>}<span className="capitalize">{finding.status}</span></div></div></button>)}{shown < visible.length && <div className="p-3"><button type="button" onClick={() => setShown((count) => Math.min(count + pageSize, visible.length))} className="w-full rounded-md border border-border px-3 py-2 text-sm font-medium text-foreground hover:bg-elevated/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">Load more findings</button></div>}</>}</div><aside className="border-t border-border bg-bg p-5 md:border-l md:border-t-0" aria-label="Finding details">{selected ? <div><div className="flex flex-wrap items-center gap-2"><SevBadge sev={selected.severity} /><Pill>{selected.kind}</Pill>{selected.cwe && <Pill>{selected.cwe}</Pill>}</div><h3 className="mt-4 font-semibold">{selected.title}</h3><p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-mutedfg">{selected.description || 'No additional description was supplied.'}</p><dl className="mt-5 grid grid-cols-2 gap-3 text-xs"><div><dt className="text-subtlefg">Status</dt><dd className="mt-1 capitalize text-foreground">{selected.status}</dd></div><div><dt className="text-subtlefg">Priority</dt><dd className="mt-1 tabular-nums text-foreground">P{selected.priority || '—'}</dd></div><div><dt className="text-subtlefg">Scope</dt><dd className="mt-1 capitalize text-foreground">{selected.scope || 'Unspecified'}</dd></div><div><dt className="text-subtlefg">Reachability</dt><dd className="mt-1 capitalize text-foreground">{selected.reachability || 'Unknown'}</dd></div></dl></div> : <div className="flex h-full min-h-40 items-center justify-center text-center text-sm text-mutedfg">Select a finding to inspect its evidence and status.</div>}</aside></div>
    </>}
  </Card>
}

function dimensionFilter(dimension: RatedFindingDimension | null): FindingKindFilter {
  return dimension === null ? 'all' : `dimension:${dimension}`
}

function matchesKindFilter(finding: Finding, filter: FindingKindFilter): boolean {
  if (filter === 'all') return true
  if (filter.startsWith('dimension:')) {
    return findingMatchesRatedDimension(finding, filter.slice('dimension:'.length) as RatedFindingDimension)
  }
  return finding.kind === filter.slice('kind:'.length)
}
