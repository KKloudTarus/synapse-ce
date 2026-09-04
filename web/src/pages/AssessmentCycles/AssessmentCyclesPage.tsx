import { ChevronDown, GitBranch01, RefreshCw01, SearchLg } from '@untitledui/icons'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type {
  AssessmentCycleBoundaryKind,
  AssessmentCycleMember,
  AssessmentCycleScanStaleness,
  AssessmentCycleStatus,
  AssessmentCycleSummary,
  AssessmentStatus,
} from '../../lib/types'

export function AssessmentCyclesPage() {
  const [params, setParams] = useSearchParams()
  const status = (params.get('status') ?? '') as AssessmentCycleStatus | ''
  const boundaryKind = (params.get('boundary') ?? '') as AssessmentCycleBoundaryKind | ''
  const assessmentStatus = (params.get('assessment_status') ?? '') as AssessmentStatus | ''
  const assessmentType = (params.get('assessment_type') ?? '') as AssessmentCycleMember['assessmentType'] | ''
  const scanStaleness = (params.get('scan') ?? '') as AssessmentCycleScanStaleness | ''
  const selectedHeadAssessmentId = params.get('selected_head') ?? ''
  const cursor = params.get('cursor') ?? ''
  const search = params.get('q') ?? ''
  const expanded = new Set((params.get('expanded') ?? '').split(',').filter(Boolean))
  const filterValues = [status, boundaryKind, assessmentStatus, assessmentType, scanStaleness, selectedHeadAssessmentId, search]
  const cyclesFetch = useFetch(() => api.listAssessmentCycles({
    status: status || undefined,
    boundaryKind: boundaryKind || undefined,
    assessmentStatus: assessmentStatus || undefined,
    selectedHeadAssessmentId: selectedHeadAssessmentId || undefined,
    assessmentType: assessmentType || undefined,
    scanStaleness: scanStaleness || undefined,
    search: search || undefined,
    cursor,
    limit: 50,
  }), { deps: [...filterValues, cursor] })
  const [extraMembers, setExtraMembers] = useState<Record<string, AssessmentCycleMember[]>>({})
  const [memberCursors, setMemberCursors] = useState<Record<string, string>>({})
  const [memberLoading, setMemberLoading] = useState('')
  const [memberErrors, setMemberErrors] = useState<Record<string, string>>({})

  function update(next: Record<string, string>, replace = true) {
    const values = new URLSearchParams(params)
    for (const [key, value] of Object.entries(next)) value ? values.set(key, value) : values.delete(key)
    setParams(values, { replace })
  }

  function toggle(cycleId: string) {
    const next = new Set(expanded)
    next.has(cycleId) ? next.delete(cycleId) : next.add(cycleId)
    update({ expanded: [...next].sort().join(',') })
  }

  async function loadMore(cycle: AssessmentCycleSummary) {
    const nextCursor = memberCursors[cycle.id] ?? cycle.membersNextCursor
    if (!nextCursor) return
    setMemberLoading(cycle.id)
    setMemberErrors((current) => ({ ...current, [cycle.id]: '' }))
    try {
      const page = await api.listAssessmentCycleMembers(cycle.id, nextCursor, 25)
      setExtraMembers((current) => ({ ...current, [cycle.id]: [...(current[cycle.id] ?? []), ...page.items] }))
      setMemberCursors((current) => ({ ...current, [cycle.id]: page.nextCursor }))
    } catch (cause) {
      setMemberErrors((current) => ({ ...current, [cycle.id]: cause instanceof Error ? cause.message : 'Member page failed.' }))
    } finally {
      setMemberLoading('')
    }
  }

  const items = cyclesFetch.data?.items ?? []
  return <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
    <header className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-wider text-brand-secondary">Assessment lifecycle</p><h1 className="mt-1 text-2xl font-bold tracking-tight text-primary">Assessment Cycles</h1><p className="mt-1 text-sm text-tertiary">Root-to-selected/final projections only. Display latest never changes semantic precedence.</p></div><Button variant="secondary" onClick={cyclesFetch.refetch}><RefreshCw01 className="size-4" aria-hidden="true" />Refresh</Button></header>
    <Card bodyClass="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <div className="relative sm:col-span-2"><SearchLg className="pointer-events-none absolute left-3 top-3 size-4 text-quaternary" aria-hidden="true" /><Input aria-label="Search Assessment Cycles" value={search} onChange={(event) => update({ q: event.target.value, cursor: '' })} className="pl-9" placeholder="Search Cycle, root, or selected head" /></div>
      <Select ariaLabel="Cycle status" value={status} onValueChange={(value) => update({ status: value, cursor: '' })} placeholder="All Cycle statuses" options={[{ value: 'open', label: 'Open' }, { value: 'completed', label: 'Completed' }, { value: 'archived', label: 'Archived' }]} className="w-full" />
      <Select ariaLabel="Boundary kind" value={boundaryKind} onValueChange={(value) => update({ boundary: value, cursor: '' })} placeholder="All boundaries" options={[{ value: 'standalone', label: 'Standalone' }, { value: 'asset', label: 'Asset' }, { value: 'project', label: 'Project' }, { value: 'asset_project', label: 'Asset + Project' }]} className="w-full" />
      <Select ariaLabel="Selected-head Assessment status" value={assessmentStatus} onValueChange={(value) => update({ assessment_status: value, cursor: '' })} placeholder="All Assessment statuses" options={[{ value: 'draft', label: 'Draft' }, { value: 'active', label: 'Active' }, { value: 'completed', label: 'Completed' }, { value: 'archived', label: 'Archived' }]} className="w-full" />
      <Select ariaLabel="Assessment member type" value={assessmentType} onValueChange={(value) => update({ assessment_type: value, cursor: '' })} placeholder="Initial or Re-test" options={[{ value: 'initial', label: 'Initial' }, { value: 'retest', label: 'Re-test' }]} className="w-full" />
      <Input aria-label="Selected head Assessment ID" value={selectedHeadAssessmentId} onChange={(event) => update({ selected_head: event.target.value, cursor: '' })} placeholder="Selected head ID" />
      <Select ariaLabel="Selected-head scan staleness" value={scanStaleness} onValueChange={(value) => update({ scan: value, cursor: '' })} placeholder="Any scan freshness" options={[{ value: 'fresh', label: 'Fresh ≤ 24h' }, { value: 'stale', label: 'Stale > 24h' }, { value: 'missing', label: 'No trustworthy scan' }]} className="w-full" />
      {filterValues.some(Boolean) ? <Button variant="secondary" onClick={() => setParams(new URLSearchParams(), { replace: true })}>Clear filters</Button> : null}
    </Card>
    {cyclesFetch.loading && !cyclesFetch.data ? <Spinner label="Loading Assessment Cycles…" /> : null}
    {cyclesFetch.error ? <ErrorState message={cyclesFetch.error} /> : null}
    {!cyclesFetch.loading && !cyclesFetch.error && items.length === 0 && !(cyclesFetch.data?.migrationPendingTotal) ? <EmptyState icon={GitBranch01} title="No Assessment Cycles" hint="No Cycle or migration-pending Assessment matches these filters." /> : null}
    <div className="space-y-3">{items.map((cycle) => <CycleRow key={cycle.id} cycle={cycle} expanded={expanded.has(cycle.id)} extraMembers={extraMembers[cycle.id] ?? []} nextMemberCursor={memberCursors[cycle.id] ?? cycle.membersNextCursor} loading={memberLoading === cycle.id} error={memberErrors[cycle.id] ?? ''} onToggle={() => toggle(cycle.id)} onLoadMore={() => loadMore(cycle)} />)}</div>
    {cyclesFetch.data?.nextCursor ? <div className="flex justify-end"><Button variant="secondary" onClick={() => update({ cursor: cyclesFetch.data?.nextCursor ?? '' }, false)}>Next Cycle page</Button></div> : null}
    {cyclesFetch.data?.migrationPendingTotal ? <Card title={`Migration pending · ${cyclesFetch.data.migrationPendingTotal}`}>{cyclesFetch.data.migrationPending.length ? <div className="space-y-2">{cyclesFetch.data.migrationPending.map((assessment) => <Link key={assessment.assessmentId} to={`/engagements/${encodeURIComponent(assessment.assessmentId)}`} className="flex flex-wrap items-center gap-2 rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"><span className="font-semibold text-primary">{assessment.name}</span><span className="font-mono text-xs text-tertiary">{assessment.assessmentId}</span><Pill className="text-warning">Migration pending</Pill><Pill>{assessment.status} Assessment</Pill><span className="ml-auto text-xs text-tertiary">{formatDate(assessment.updatedAt)}</span></Link>)}</div> : <p className="text-sm text-tertiary">Pending legacy Assessments exist but are excluded by Cycle-only filters. Clear filters to inspect them.</p>}</Card> : null}
  </div>
}

function CycleRow({ cycle, expanded, extraMembers, nextMemberCursor, loading, error, onToggle, onLoadMore }: { cycle: AssessmentCycleSummary; expanded: boolean; extraMembers: AssessmentCycleMember[]; nextMemberCursor: string; loading: boolean; error: string; onToggle: () => void; onLoadMore: () => void }) {
  const members = [...cycle.members, ...extraMembers]
  return <Card bodyClass="p-0"><button type="button" aria-expanded={expanded} aria-controls={`cycle-${cycle.id}`} onClick={onToggle} className="grid w-full gap-3 px-5 py-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand md:grid-cols-[minmax(240px,1.4fr)_repeat(3,minmax(110px,.6fr))_auto] md:items-center"><span><span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-primary">{cycle.name}</strong><Pill>{cycle.status} Cycle</Pill></span><span className="mt-1 block font-mono text-xs text-tertiary">{cycle.id}</span></span><Stat label="Members / branches" value={`${cycle.memberCount} / ${cycle.activeBranchCount}`} /><Stat label="Latest member" value={cycle.latestRetestNumber > 0 ? `Re-test #${cycle.latestRetestNumber}` : 'Initial'} /><Stat label="Selected-head scan" value={cycle.scanStaleness} /><ChevronDown className={cn('size-4 text-tertiary transition-transform', expanded && 'rotate-180')} aria-hidden="true" /></button>{expanded ? <div id={`cycle-${cycle.id}`} className="border-t border-secondary px-5 py-4"><div className="mb-3 grid gap-2 text-xs text-tertiary sm:grid-cols-2 lg:grid-cols-4"><span><strong>Root snapshot:</strong> {cycle.rootSnapshotId || 'N/A'}</span><span><strong>Current snapshot:</strong> {cycle.currentSnapshotId || 'N/A'}</span><span><strong>Display latest:</strong> {cycle.latestAssessmentId || 'N/A'}</span><span><strong>Last trusted scan:</strong> {cycle.selectedHeadLastScanAt ? formatDate(cycle.selectedHeadLastScanAt) : 'N/A'}</span></div><ul aria-label={`${cycle.name} members`} className="space-y-2">{members.map((member) => <li key={member.assessmentId}><Link to={`/engagements/${encodeURIComponent(member.assessmentId)}`} className="flex flex-wrap items-center gap-2 rounded-lg border border-secondary px-3 py-2 text-sm hover:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"><span className="font-semibold text-primary">{member.assessmentType === 'retest' ? `Re-test #${member.retestNumber}` : 'Initial'}</span><span className="font-mono text-xs text-tertiary">{member.assessmentId}</span>{member.assessmentId === cycle.selectedHeadAssessmentId ? <Pill className="text-brand-secondary">Selected head</Pill> : null}{member.assessmentId === cycle.latestAssessmentId ? <Pill className="text-brand-secondary">Display latest</Pill> : null}{member.archivedAt ? <Pill className="text-warning">Archived</Pill> : null}<span className="ml-auto text-xs text-tertiary">{formatDate(member.createdAt)}</span></Link></li>)}</ul>{error ? <ErrorState className="mt-3" message={error} /> : null}{nextMemberCursor ? <Button className="mt-3" variant="secondary" loading={loading} onClick={onLoadMore}>Load more members</Button> : null}</div> : null}</Card>
}

function Stat({ label, value }: { label: string; value: string }) { return <span><span className="block text-[11px] font-semibold uppercase tracking-wide text-quaternary">{label}</span><span className="mt-1 block text-sm font-semibold capitalize text-primary">{value}</span></span> }
function formatDate(value: string) { return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(value)) : 'Unknown' }
