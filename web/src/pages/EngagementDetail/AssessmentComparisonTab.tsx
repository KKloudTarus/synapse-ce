import { AlertCircle, ArrowDown, ArrowNarrowRight, ArrowUp, CheckCircle, ChevronLeft, ChevronRight, FilterLines, GitBranch01, InfoCircle, RefreshCw01, SearchLg, ShieldTick, Sliders04, SwitchVertical01, XClose } from '@untitledui/icons'
import { Fragment, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Dialog, Modal, ModalOverlay } from '../../components/application/modals/modal'
import { SlideoutMenu } from '../../components/application/slideout-menus/slideout-menu'
import { Metric, MetricStrip } from '../../components/synapse/Metric'
import { SeverityBadge } from '../../components/synapse/SeverityBadge'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { sevRank } from '../../lib/severity'
import type { AssessmentComparison, AssessmentComparisonChangeFlag, AssessmentComparisonItem, AssessmentComparisonMode, AssessmentComparisonRatio, AssessmentComparisonScope, AssessmentComparisonSummary, AssessmentLifecycle, AssessmentSnapshot, AssessmentSnapshotListResponse, Severity } from '../../lib/types'
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS, type SortDirection } from './components/FindingsTable'

const ALL = 'all'
const PRESENCE = ['all', 'new', 'still_detected', 'not_detected_under_comparable_coverage', 'not_evaluated', 'reopened', 'needs_review'].map(option)
const NEUTRAL_PRESENCE = ['all', 'only_in_a', 'both', 'only_in_b', 'needs_review'].map(option)
const SEVERITY = ['all', 'critical', 'high', 'medium', 'low', 'info', 'unknown'].map(option)
const REVIEW = ['all', 'needs_review', 'verified', 'clear'].map(option)
const DISPOSITION = ['all', 'current_actionable', 'baseline_only', 'non_actionable'].map(option)
const CHANGES = ['all', 'severity_increased', 'severity_decreased', 'component_version_changed', 'location_changed', 'reachability_changed', 'evidence_changed', 'scanner_changed', 'rule_profile_changed', 'advisory_changed'].map(option)
const SCOPES: Array<{ value: AssessmentComparisonScope; label: string; description: string }> = [
  { value: 'vulnerability', label: 'Vulnerabilities', description: 'Unique SCA vulnerability identities' },
  { value: 'security', label: 'Security findings', description: 'Vulnerabilities, SAST, secrets, and misconfigurations' },
  { value: 'all', label: 'All findings', description: 'Includes quality and reliability findings' },
]
const TERMINAL_STATUSES = ['complete', 'needs_review', 'superseded']
type ComparisonSortKey = 'lifecycle' | 'severity' | 'identity' | 'change' | 'coverage'

const COMPARISON_SORT_KEYS: ComparisonSortKey[] = ['lifecycle', 'severity', 'identity', 'change', 'coverage']

function selectedOption(value: string | null, options: Array<{ value: string }>, fallback = ALL) {
  return value && options.some((option) => option.value === value) ? value : fallback
}

function isComparisonSortKey(value: string | null): value is ComparisonSortKey {
  return value !== null && COMPARISON_SORT_KEYS.includes(value as ComparisonSortKey)
}

export function AssessmentComparisonTab({ assessmentId }: { assessmentId: string }) {
  const [params, setParams] = useSearchParams()
  const mode = (params.get('comparison_mode') === 'neutral_diff' ? 'neutral_diff' : 'lifecycle') as AssessmentComparisonMode
  const baselineAssessmentParam = params.get('comparison_base_assessment') ?? ''
  const baselineSnapshotId = params.get('comparison_baseline') ?? ''
  const currentSnapshotId = params.get('comparison_current') ?? ''
  const comparisonId = params.get('comparison_id') ?? ''
  const requestedScope = params.get('comparison_scope')
  const scope = (SCOPES.some((item) => item.value === requestedScope) ? requestedScope : 'vulnerability') as AssessmentComparisonScope
  const cursor = params.get('comparison_cursor') ?? ''
  const presenceOptions = mode === 'neutral_diff' ? NEUTRAL_PRESENCE : PRESENCE
  const presence = selectedOption(params.get('comparison_presence'), presenceOptions)
  const severity = selectedOption(params.get('comparison_severity'), SEVERITY)
  const changeFlag = selectedOption(params.get('comparison_change'), CHANGES)
  const reviewState = selectedOption(params.get('comparison_review'), REVIEW)
  const disposition = selectedOption(params.get('comparison_disposition'), DISPOSITION)
  const producer = params.get('comparison_producer') ?? ''
  const findingKind = params.get('comparison_kind') ?? ''
  const searchQuery = params.get('comparison_q') ?? ''
  const sortParam = params.get('comparison_sort')
  const sortKey: ComparisonSortKey = isComparisonSortKey(sortParam) ? sortParam : 'severity'
  const sortDirection: SortDirection = params.get('comparison_dir') === 'asc' ? 'asc' : 'desc'
  const sizeParam = Number(params.get('comparison_size'))
  const pageSize = (PAGE_SIZE_OPTIONS as readonly number[]).includes(sizeParam) ? sizeParam : DEFAULT_PAGE_SIZE
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')
  const [selectedItem, setSelectedItem] = useState<AssessmentComparisonItem | null>(null)
  const [configOpen, setConfigOpen] = useState(!comparisonId)
  const [expandedItemId, setExpandedItemId] = useState('')
  const [cursorHistory, setCursorHistory] = useState<string[]>([])

  const context = useFetch(() => Promise.all([api.assessmentLifecycle(assessmentId), api.assessmentSnapshots(assessmentId)]), { deps: [assessmentId] })
  const lifecycle = context.data?.[0] ?? null
  const currentSnapshots = context.data?.[1] ?? null
  const assessmentIds = useMemo(() => comparisonAssessmentIds(lifecycle, assessmentId, mode), [assessmentId, lifecycle, mode])
  const baselineAssessmentId = assessmentIds.includes(baselineAssessmentParam) ? baselineAssessmentParam : (assessmentIds[0] ?? '')
  const baselineFetch = useFetch(() => api.assessmentSnapshots(baselineAssessmentId), { enabled: Boolean(baselineAssessmentId), deps: [baselineAssessmentId] })
  const baselineSnapshots = baselineAssessmentId === assessmentId ? currentSnapshots : baselineFetch.data

  useEffect(() => {
    if (!currentSnapshots || !baselineSnapshots || !baselineAssessmentId) return
    const current = currentSnapshots.items.some((item) => item.id === currentSnapshotId) ? currentSnapshotId : currentSnapshots.defaultSnapshotId || currentSnapshots.items.at(-1)?.id || ''
    const validBaseline = baselineSnapshots.items.some((item) => item.id === baselineSnapshotId) && baselineSnapshotId !== current
    const baseline = validBaseline ? baselineSnapshotId : chooseBaselineSnapshot(baselineSnapshots, baselineAssessmentId === assessmentId, current)
    if (baselineAssessmentParam === baselineAssessmentId && baselineSnapshotId === baseline && currentSnapshotId === current) return
    setParams((next) => {
      next.set('comparison_mode', mode)
      next.set('comparison_base_assessment', baselineAssessmentId)
      setOrDelete(next, 'comparison_baseline', baseline)
      setOrDelete(next, 'comparison_current', current)
      next.delete('comparison_id'); next.delete('comparison_cursor')
      return next
    }, { replace: true })
  }, [assessmentId, baselineAssessmentId, baselineAssessmentParam, baselineSnapshotId, baselineSnapshots, currentSnapshotId, currentSnapshots, mode, setParams])

  const comparisonFetch = useFetch(() => api.assessmentComparison(comparisonId), { enabled: Boolean(comparisonId), deps: [comparisonId] })
  const comparison = comparisonFetch.data
  const terminal = TERMINAL_STATUSES.includes(comparison?.status ?? '')
  useEffect(() => {
    if (!comparison || !['queued', 'generating'].includes(comparison.status)) return
    const timer = window.setInterval(comparisonFetch.refetch, 2000)
    return () => window.clearInterval(timer)
  }, [comparison, comparisonFetch.refetch])

  const summaryFetch = useFetch(async () => ({ scope, summary: await api.assessmentComparisonSummary(comparisonId, scope) }), {
    enabled: Boolean(comparisonId) && terminal,
    deps: [comparisonId, scope, terminal],
  })

  const itemFetch = useFetch(async () => ({ scope, page: await api.assessmentComparisonItems(comparisonId, {
    cursor: cursor || undefined, limit: pageSize, scope,
    presence: presence === ALL ? undefined : presence,
    severity: severity === ALL ? undefined : severity,
    changeFlag: changeFlag === ALL ? undefined : changeFlag as AssessmentComparisonChangeFlag,
    reviewState: reviewState === ALL ? undefined : reviewState,
    disposition: disposition === ALL ? undefined : disposition,
    producer: producer || undefined, findingKind: findingKind || undefined,
  }) }), {
    enabled: Boolean(comparisonId) && terminal,
    deps: [changeFlag, comparisonId, cursor, disposition, findingKind, pageSize, presence, producer, reviewState, scope, severity, terminal],
  })

  const baselineSnapshot = baselineSnapshots?.items.find((item) => item.id === baselineSnapshotId) ?? null
  const currentSnapshot = currentSnapshots?.items.find((item) => item.id === currentSnapshotId) ?? null
  const scopedSummary = summaryFetch.data?.scope === scope ? summaryFetch.data.summary : null
  const scopedItemPage = itemFetch.data?.scope === scope ? itemFetch.data.page : null
  const visibleItems = useMemo(() => sortComparisonItems(filterComparisonItems(scopedItemPage?.items ?? [], searchQuery), sortKey, sortDirection), [scopedItemPage?.items, searchQuery, sortDirection, sortKey])

  function setParam(key: string, value: string, clearComparison = false) {
    setCursorHistory([])
    setParams((next) => {
      setOrDelete(next, key, key === 'comparison_scope' ? value : value === ALL ? '' : value)
      next.delete('comparison_cursor')
      if (clearComparison) next.delete('comparison_id')
      return next
    }, { replace: true })
  }

  async function createComparison() {
    if (!baselineSnapshotId || !currentSnapshotId || baselineSnapshotId === currentSnapshotId) return setCreateError('Baseline and current must be different immutable snapshots.')
    setCreating(true); setCreateError('')
    try {
      const result = await api.createAssessmentComparison({ baselineSnapshotId, currentSnapshotId, mode })
      const returned = result.comparison
      if (returned.mode !== mode || returned.baselineSnapshotId !== baselineSnapshotId || returned.currentSnapshotId !== currentSnapshotId) throw new Error('The server returned a different pair or mode; comparison was rejected locally.')
      setParams((next) => { next.set('comparison_id', returned.id); next.delete('comparison_cursor'); return next })
      setConfigOpen(false)
    } catch (error) { setCreateError(error instanceof Error ? error.message : 'Comparison request failed.') }
    finally { setCreating(false) }
  }

  if (context.loading && !context.data) return <Spinner label="Loading assessment comparison context…" />
  if (context.error) return <ErrorState message={context.error} />
  if (!lifecycle || !currentSnapshots?.items.length) return <EmptyState icon={GitBranch01} title="No immutable snapshots to compare" hint="Finalize at least one assessment snapshot before creating a comparison." />

  const scopeDetails = SCOPES.find((item) => item.value === scope) ?? SCOPES[0]
  const hasAdvancedFilters = Boolean(producer || findingKind || reviewState !== ALL || disposition !== ALL)
  const hasFilters = Boolean(searchQuery || presence !== ALL || severity !== ALL || changeFlag !== ALL || hasAdvancedFilters)

  function clearFilters() {
    setCursorHistory([])
    setExpandedItemId('')
    setParams((next) => {
      for (const key of ['comparison_q', 'comparison_presence', 'comparison_severity', 'comparison_change', 'comparison_review', 'comparison_disposition', 'comparison_producer', 'comparison_kind', 'comparison_cursor']) next.delete(key)
      return next
    }, { replace: true })
  }

  function onSort(key: ComparisonSortKey) {
    const direction: SortDirection = sortKey === key ? (sortDirection === 'asc' ? 'desc' : 'asc') : key === 'severity' ? 'desc' : 'asc'
    setCursorHistory([])
    setParams((next) => {
      next.set('comparison_sort', key)
      next.set('comparison_dir', direction)
      next.delete('comparison_cursor')
      return next
    }, { replace: true })
  }

  function nextPage() {
    if (!scopedItemPage?.nextCursor) return
    setCursorHistory((history) => [...history, cursor])
    setParams((next) => { next.set('comparison_cursor', scopedItemPage.nextCursor); return next }, { replace: true })
    setExpandedItemId('')
  }

  function previousPage() {
    if (!cursorHistory.length) return
    const previousCursor = cursorHistory.at(-1) ?? ''
    setCursorHistory((history) => history.slice(0, -1))
    setParams((next) => { setOrDelete(next, 'comparison_cursor', previousCursor); return next }, { replace: true })
    setExpandedItemId('')
  }

  return <div className="space-y-5">
    {!comparisonId ? <EmptyState icon={GitBranch01} title="Configure a comparison" hint="Choose two immutable snapshots and the finding scope you want to inspect." action={<Button onClick={() => setConfigOpen(true)}><Sliders04 className="size-4" />Configure comparison</Button>} /> : <ComparisonPairBar mode={mode} baseline={baselineSnapshot} current={currentSnapshot} baselineLabel={baselineAssessmentId ? memberLabel(lifecycle, baselineAssessmentId, false) : 'Baseline'} currentLabel={memberLabel(lifecycle, assessmentId, false)} onConfigure={() => setConfigOpen(true)} />}
    {comparisonId ? <CoverageBanner baseline={baselineSnapshot} current={currentSnapshot} /> : null}
    {comparisonId && comparisonFetch.loading && !comparison ? <Spinner label="Loading immutable comparison…" /> : null}
    {comparisonFetch.error ? <ErrorState message={comparisonFetch.error} /> : null}
    {comparison ? <ComparisonState comparison={comparison} onRefresh={comparisonFetch.refetch} /> : null}
    {comparison && terminal ? <>
      <Card title="Comparison overview" bodyClass="space-y-6">
        <ScopeTabs scope={scope} onChange={(value) => setParam('comparison_scope', value)} />
        <p className="-mt-3 text-sm text-tertiary">{scopeDetails.description}. Switch scope to keep vulnerability outcomes separate from code quality noise.</p>
        {summaryFetch.loading && !scopedSummary ? <Spinner label={`Calculating ${scopeDetails.label.toLowerCase()}…`} /> : null}
        {summaryFetch.error ? <ErrorState message={summaryFetch.error} /> : null}
        {scopedSummary ? <Summary comparison={comparison} summary={scopedSummary} scope={scope} coverage={coverageCounts(baselineSnapshot, currentSnapshot)} onPresenceChange={(value) => setParam('comparison_presence', value)} onSeverityChange={(value) => setParam('comparison_severity', value)} /> : null}
      </Card>
      <Card bodyClass="p-3" className="shadow-xs">
        <ComparisonFilterBar searchQuery={searchQuery} presence={presence} severity={severity} changeFlag={changeFlag} presenceOptions={presenceOptions} hasFilters={hasFilters} onSetParam={setParam} onClear={clearFilters} />
        <details className="group mt-3 rounded-lg border border-secondary bg-secondary/20" open={hasAdvancedFilters}>
          <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-semibold text-secondary hover:text-primary"><FilterLines className="size-3.5" />Advanced filters</summary>
          <div className="grid gap-3 border-t border-secondary p-3 md:grid-cols-2 xl:grid-cols-4">
            <Field label="Review state"><Select size="sm" ariaLabel="Review state filter" value={reviewState} onValueChange={(value) => setParam('comparison_review', value)} options={REVIEW} className="w-full" /></Field>
            <Field label="Disposition"><Select size="sm" ariaLabel="Disposition filter" value={disposition} onValueChange={(value) => setParam('comparison_disposition', value)} options={DISPOSITION} className="w-full" /></Field>
            <Field label="Producer"><Input aria-label="Producer filter" placeholder="e.g. trivy" value={producer} onChange={(event) => setParam('comparison_producer', event.target.value)} className="h-8 py-1.5 text-xs" /></Field>
            <Field label="Finding kind"><Input aria-label="Finding kind filter" placeholder="e.g. vulnerability" value={findingKind} onChange={(event) => setParam('comparison_kind', event.target.value)} className="h-8 py-1.5 text-xs" /></Field>
          </div>
        </details>
      </Card>
      <Card title={<span className="flex items-center gap-2"><SearchLg className="size-4 text-quaternary" />Compared findings</span>} actions={<Pill>{scopeDetails.label}</Pill>} bodyClass="p-0" className="overflow-hidden shadow-xs">
        <ItemTable loading={itemFetch.loading} error={itemFetch.error} items={visibleItems} unfilteredCount={scopedItemPage?.items.length ?? 0} searchQuery={searchQuery} sortKey={sortKey} sortDirection={sortDirection} onSort={onSort} expandedItemId={expandedItemId} onToggle={(id) => setExpandedItemId((current) => current === id ? '' : id)} onSelect={setSelectedItem} />
        <ComparisonPagination page={cursorHistory.length + 1} pageSize={pageSize} count={visibleItems.length} canPrevious={cursorHistory.length > 0} canNext={Boolean(scopedItemPage?.nextCursor)} onPrevious={previousPage} onNext={nextPage} onPageSizeChange={(value) => setParam('comparison_size', String(value))} />
      </Card>
    </> : null}
    {configOpen ? <ComparisonConfigModal lifecycle={lifecycle} assessmentId={assessmentId} mode={mode} baselineAssessmentId={baselineAssessmentId} assessmentIds={assessmentIds} baselineSnapshotId={baselineSnapshotId} currentSnapshotId={currentSnapshotId} baselineSnapshots={baselineSnapshots} currentSnapshots={currentSnapshots} scope={scope} creating={creating} error={createError} onSetParam={setParam} onCompare={createComparison} onClose={() => setConfigOpen(false)} /> : null}
    {selectedItem ? <ReviewDrawer comparison={comparison} item={selectedItem} onClose={() => setSelectedItem(null)} onReplacement={(id) => { setSelectedItem(null); setParams((next) => { next.set('comparison_id', id); next.delete('comparison_cursor'); return next }) }} /> : null}
  </div>
}

function ComparisonState({ comparison, onRefresh }: { comparison: AssessmentComparison; onRefresh: () => void }) {
  const terminal = TERMINAL_STATUSES.includes(comparison.status)
  const failed = comparison.status === 'failed'
  if (terminal) return <div role="status" className="flex flex-wrap items-center justify-between gap-3 text-xs text-tertiary"><span>Comparison ready · projection v{comparison.version} · {comparison.id.slice(0, 8)}</span>{comparison.status === 'needs_review' ? <Pill className="bg-warning/10 text-warning-primary">Review required</Pill> : null}</div>
  return <div role="status" className={cn('flex flex-wrap items-center justify-between gap-4 rounded-xl border px-5 py-4', failed ? 'border-critical/30 bg-critical/5' : 'border-brand/30 bg-brand/5')}>
    <div className="flex items-start gap-3">
      {failed ? <AlertCircle className="mt-0.5 size-5 text-critical" /> : <RefreshCw01 className="mt-0.5 size-5 animate-spin text-brand-secondary" />}
      <div><p className="font-semibold text-primary">{failed ? 'Comparison could not be generated' : 'Calculating changes between snapshots'}</p><p className="mt-1 text-sm text-tertiary">{failed ? `Failure code: ${comparison.failureCode || 'unknown'}. Retry after checking the comparison worker.` : 'Synapse is matching identities and validating scan coverage. This page refreshes automatically.'}</p></div>
    </div>
    <Button variant="secondary" onClick={onRefresh}><RefreshCw01 className="size-4" />Refresh</Button>
  </div>
}

function ComparisonPairBar({ mode, baseline, current, baselineLabel, currentLabel, onConfigure }: { mode: AssessmentComparisonMode; baseline: AssessmentSnapshot | null; current: AssessmentSnapshot | null; baselineLabel: string; currentLabel: string; onConfigure: () => void }) {
  return <Card bodyClass="p-3" className="shadow-xs">
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-primary/10 text-brand-secondary"><GitBranch01 className="size-4" aria-hidden="true" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><p className="text-xs font-semibold uppercase tracking-wide text-tertiary">Active comparison</p><Pill className="bg-brand-primary/10 text-brand-secondary">{mode === 'lifecycle' ? 'Scan → re-scan' : 'Neutral diff'}</Pill></div>
          <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2 text-sm">
            <span className="truncate font-semibold text-primary">{baselineLabel}</span><SnapshotInline snapshot={baseline} />
            <ArrowNarrowRight className="size-4 shrink-0 text-quaternary" aria-hidden="true" />
            <span className="truncate font-semibold text-primary">{currentLabel}</span><SnapshotInline snapshot={current} />
          </div>
        </div>
      </div>
      <Button variant="secondary" className="h-9 shrink-0 text-xs" onClick={onConfigure}><Sliders04 className="size-4" />Change comparison</Button>
    </div>
  </Card>
}

function SnapshotInline({ snapshot }: { snapshot: AssessmentSnapshot | null }) {
  if (!snapshot) return <span className="text-xs text-tertiary">No snapshot</span>
  return <span className="whitespace-nowrap font-mono text-xs text-tertiary">Snapshot {snapshot.snapshotNumber} · {snapshot.id.slice(0, 8)}</span>
}

function ComparisonConfigModal({ lifecycle, assessmentId, mode, baselineAssessmentId, assessmentIds, baselineSnapshotId, currentSnapshotId, baselineSnapshots, currentSnapshots, scope, creating, error, onSetParam, onCompare, onClose }: { lifecycle: AssessmentLifecycle; assessmentId: string; mode: AssessmentComparisonMode; baselineAssessmentId: string; assessmentIds: string[]; baselineSnapshotId: string; currentSnapshotId: string; baselineSnapshots: AssessmentSnapshotListResponse | null | undefined; currentSnapshots: AssessmentSnapshotListResponse; scope: AssessmentComparisonScope; creating: boolean; error: string; onSetParam: (key: string, value: string, clearComparison?: boolean) => void; onCompare: () => void; onClose: () => void }) {
  const ready = Boolean(baselineAssessmentId && baselineSnapshotId && currentSnapshotId && baselineSnapshots)
  const invalidPair = !baselineSnapshotId || !currentSnapshotId || baselineSnapshotId === currentSnapshotId
  const baseline = baselineSnapshots?.items.find((item) => item.id === baselineSnapshotId) ?? null
  const current = currentSnapshots.items.find((item) => item.id === currentSnapshotId) ?? null
  return <ModalOverlay isOpen isDismissable={!creating} onOpenChange={(open) => { if (!open && !creating) onClose() }}>
    <Modal className="w-full max-w-3xl overflow-hidden rounded-2xl border border-secondary bg-primary shadow-2xl">
      <Dialog aria-label="Configure comparison" className="flex max-h-[85vh] flex-col overflow-hidden">
        <header className="flex shrink-0 items-start justify-between border-b border-secondary px-6 py-5">
          <div><div className="flex items-center gap-2"><div className="flex size-9 items-center justify-center rounded-lg bg-brand-primary/10 text-brand-secondary"><Sliders04 className="size-4" aria-hidden="true" /></div><div><h2 className="text-lg font-semibold text-primary">Configure comparison</h2><p className="mt-0.5 text-sm text-tertiary">Choose what Synapse should compare. The underlying comparison rules remain unchanged.</p></div></div></div>
          <button type="button" onClick={onClose} disabled={creating} aria-label="Close comparison configuration" className="flex size-9 shrink-0 items-center justify-center rounded-lg text-tertiary hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:opacity-50"><XClose className="size-4" aria-hidden="true" /></button>
        </header>
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-5">
          {!ready ? <div className="flex min-h-64 items-center justify-center"><Spinner label="Preparing comparison options…" /></div> : <>
          <section className="grid gap-4 rounded-xl border border-secondary bg-secondary/20 p-4 md:grid-cols-2" aria-label="Comparison behavior">
            <Field label="Comparison mode" hint="Lifecycle mode classifies fixed, new and re-opened findings."><Select disabled={creating} ariaLabel="Comparison mode" value={mode} onValueChange={(value) => onSetParam('comparison_mode', value, true)} options={[{ value: 'lifecycle', label: 'Scan → re-scan lifecycle' }, { value: 'neutral_diff', label: 'Neutral snapshot diff' }]} className="w-full" /></Field>
            <Field label="Result scope" hint="This changes presentation scope, not the immutable snapshots."><Select disabled={creating} ariaLabel="Comparison result scope" value={scope} onValueChange={(value) => onSetParam('comparison_scope', value)} options={SCOPES} className="w-full" /></Field>
          </section>
          <section aria-labelledby="comparison-pair-heading">
            <div className="mb-3"><h3 id="comparison-pair-heading" className="text-sm font-semibold text-primary">Select comparison pair</h3><p className="mt-1 text-xs text-tertiary">For a re-test, the closest previous finalized snapshot is selected by default.</p></div>
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Baseline assessment"><Select disabled={creating} ariaLabel="Baseline assessment" value={baselineAssessmentId} onValueChange={(value) => onSetParam('comparison_base_assessment', value, true)} options={assessmentIds.map((id) => ({ value: id, label: memberLabel(lifecycle, id) }))} className="w-full" /></Field>
              <Field label="Before snapshot"><Select disabled={creating} ariaLabel="Baseline snapshot" value={baselineSnapshotId} onValueChange={(value) => onSetParam('comparison_baseline', value, true)} options={(baselineSnapshots?.items ?? []).map(snapshotOption)} className="w-full" /></Field>
              <Field label="After snapshot"><Select disabled={creating} ariaLabel="Current snapshot" value={currentSnapshotId} onValueChange={(value) => onSetParam('comparison_current', value, true)} options={currentSnapshots.items.map(snapshotOption)} className="w-full" /></Field>
            </div>
          </section>
          <div className="grid items-stretch gap-3 md:grid-cols-[1fr_auto_1fr]">
            <SnapshotCard eyebrow="Before" snapshot={baseline} assessmentLabel={baselineAssessmentId ? memberLabel(lifecycle, baselineAssessmentId, false) : 'Select a baseline'} />
            <div className="flex items-center justify-center text-quaternary"><ArrowNarrowRight className="size-5 rotate-90 md:rotate-0" aria-hidden="true" /></div>
            <SnapshotCard eyebrow="After" snapshot={current} assessmentLabel={memberLabel(lifecycle, assessmentId, false)} current />
          </div>
          {error ? <ErrorState message={error} /> : null}
          </>}
        </div>
        <footer className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-secondary bg-primary px-6 py-4">
          <p className="text-xs text-tertiary">Metrics use immutable finding identities from this pair.</p>
          <div className="flex gap-3"><Button variant="ghost" disabled={creating} onClick={onClose}>Cancel</Button><Button loading={creating} disabled={!ready || invalidPair} onClick={onCompare}>Run comparison</Button></div>
        </footer>
      </Dialog>
    </Modal>
  </ModalOverlay>
}

function ComparisonFilterBar({ searchQuery, presence, severity, changeFlag, presenceOptions, hasFilters, onSetParam, onClear }: { searchQuery: string; presence: string; severity: string; changeFlag: string; presenceOptions: Array<{ value: string; label: string }>; hasFilters: boolean; onSetParam: (key: string, value: string) => void; onClear: () => void }) {
  return <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
    <div className="flex flex-1 flex-wrap items-center gap-2.5">
      <div className="relative min-w-[16rem] flex-1 sm:max-w-sm">
        <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-tertiary" aria-hidden="true" />
        <input type="text" value={searchQuery} onChange={(event) => onSetParam('comparison_q', event.target.value)} placeholder="Search current page: identity, target, tool, rule…" aria-label="Search compared findings" className="h-9 w-full rounded-lg border border-secondary bg-primary pl-9 pr-8 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid" />
        {searchQuery ? <button type="button" onClick={() => onSetParam('comparison_q', '')} aria-label="Clear comparison search" className="absolute right-2.5 top-1/2 -translate-y-1/2 text-quaternary hover:text-primary"><XClose className="size-3.5" /></button> : null}
      </div>
      <Select size="sm" ariaLabel="Presence filter" value={presence} onValueChange={(value) => onSetParam('comparison_presence', value)} options={presenceOptions} className="min-w-[10rem]" />
      <Select size="sm" ariaLabel="Severity filter" value={severity} onValueChange={(value) => onSetParam('comparison_severity', value)} options={SEVERITY} className="min-w-[9rem]" />
      <Select size="sm" ariaLabel="Changed field filter" value={changeFlag} onValueChange={(value) => onSetParam('comparison_change', value)} options={CHANGES} className="min-w-[11rem]" />
    </div>
    {hasFilters ? <Button variant="ghost" className="h-9 self-end px-3 text-xs lg:self-auto" onClick={onClear}><XClose className="size-3.5" />Clear filters</Button> : null}
  </div>
}

function CoverageBanner({ baseline, current }: { baseline: AssessmentSnapshot | null; current: AssessmentSnapshot | null }) {
  const counts = coverageCounts(baseline, current)
  const unsafe = !baseline || !current || baseline.provenance === 'legacy' || current.provenance === 'legacy' || counts.notComparable > 0
  const confidence = unsafe ? 'Low' : counts.partial ? 'Partial' : 'High'
  return <div className={cn('rounded-xl border px-4 py-4', unsafe ? 'border-warning/30 bg-warning/10' : counts.partial ? 'border-brand/30 bg-brand/5' : 'border-success/30 bg-success/10')}><div className="flex items-start gap-3">{unsafe ? <AlertCircle className="mt-0.5 size-5 shrink-0 text-warning" /> : counts.partial ? <InfoCircle className="mt-0.5 size-5 shrink-0 text-brand-secondary" /> : <CheckCircle className="mt-0.5 size-5 shrink-0 text-success" />}<div><p className="font-semibold text-primary">Comparison confidence: {confidence}</p><p className="mt-1 text-sm text-secondary">{unsafe ? 'Some scan lanes are not comparable. A missing finding is not automatically considered fixed.' : counts.partial ? 'Some scan lanes changed scope or tooling. Interpret reductions with the coverage details in mind.' : 'The selected snapshots have comparable scan coverage.'}</p><p className="mt-1 text-xs text-tertiary">{counts.comparable} comparable · {counts.partial} partial · {counts.notComparable} not comparable or unknown</p></div></div></div>
}

function Summary({ comparison, summary, scope, coverage, onPresenceChange, onSeverityChange }: { comparison: AssessmentComparison; summary: AssessmentComparisonSummary; scope: AssessmentComparisonScope; coverage: ReturnType<typeof coverageCounts>; onPresenceChange: (presence: string) => void; onSeverityChange: (severity: Severity) => void }) {
  const delta = summary.currentCount - summary.baselineCount
  const changeRate = summary.baselineCount > 0 ? (delta / summary.baselineCount) * 100 : null
  const comparable = coverage.notComparable === 0 && coverage.partial === 0
  const neutral = comparison.mode === 'neutral_diff'
  const conclusion = summary.baselineCount === summary.currentCount
    ? `No net change: ${summary.currentCount.toLocaleString()} ${scopeNoun(scope)} in both snapshots.`
    : `${Math.abs(delta).toLocaleString()} ${scopeNoun(scope)} ${delta < 0 ? 'fewer' : 'more'} after the re-scan (${formatSignedPercent(changeRate)}).`
  return <div className="space-y-6">
    <MetricStrip ariaLabel="Before and after comparison metrics">
      <Metric label="Before" value={summary.baselineCount} hint="Actionable finding identities in the baseline snapshot." />
      <Metric label="After" value={summary.currentCount} hint="Actionable finding identities in the current snapshot." />
      <Metric label="Net change" value={formatSignedNumber(delta)} tone={delta < 0 ? 'accent' : delta > 0 ? 'critical' : 'muted'} hint="After minus before. A negative value means fewer findings." />
      <Metric label="Change rate" value={formatSignedPercent(changeRate)} tone={delta < 0 ? 'accent' : delta > 0 ? 'critical' : 'muted'} hint="Net change divided by the before count." />
      <Metric label="Critical after" value={summary.currentSeverity.critical} tone="critical" hint="Critical actionable findings in the current snapshot." />
      <Metric label="High after" value={summary.currentSeverity.high} tone="high" hint="High-severity actionable findings in the current snapshot." />
    </MetricStrip>

    <div className={cn('flex items-start gap-3 rounded-lg border px-4 py-3', !comparable ? 'border-warning/30 bg-warning/10' : delta <= 0 ? 'border-success/30 bg-success/10' : 'border-critical/30 bg-critical/5')}>
      {!comparable ? <AlertCircle className="mt-0.5 size-5 shrink-0 text-warning" /> : delta <= 0 ? <ShieldTick className="mt-0.5 size-5 shrink-0 text-success" /> : <AlertCircle className="mt-0.5 size-5 shrink-0 text-critical" />}
      <div><p className="font-semibold text-primary">{conclusion}</p><p className="mt-1 text-sm text-secondary">{!comparable ? 'Coverage is incomplete, so this is a count comparison—not proof that every missing finding was remediated.' : neutral ? 'This is a neutral snapshot diff; lifecycle claims such as fixed or re-opened do not apply.' : `${summary.fixedCount.toLocaleString()} findings are classified as fixed under comparable coverage; ${summary.newCount + summary.reopenedCount} are new or re-opened.`}</p></div>
    </div>

    <TrendHighlights summary={summary} neutral={neutral} />

    {!neutral ? <section aria-labelledby="lifecycle-heading">
      <div className="mb-3 flex items-center justify-between gap-3"><h3 id="lifecycle-heading" className="text-sm font-semibold text-primary">Lifecycle outcome</h3><span className="text-xs text-tertiary">Select a metric to inspect its findings</span></div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <LifecycleMetric label="Fixed" value={summary.fixedCount} tone="success" onClick={() => onPresenceChange('not_detected_under_comparable_coverage')} />
        <LifecycleMetric label="New" value={summary.newCount} tone="critical" onClick={() => onPresenceChange('new')} />
        <LifecycleMetric label="Re-opened" value={summary.reopenedCount} tone="warning" onClick={() => onPresenceChange('reopened')} />
        <LifecycleMetric label="Still detected" value={summary.stillDetectedCount} onClick={() => onPresenceChange('still_detected')} />
        <LifecycleMetric label="Not evaluated" value={summary.notEvaluatedCount} tone="muted" onClick={() => onPresenceChange('not_evaluated')} />
        <LifecycleMetric label="Needs review" value={summary.reviewCount} tone="warning" onClick={() => onPresenceChange('needs_review')} />
      </div>
    </section> : null}

    <section aria-labelledby="severity-heading">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><h3 id="severity-heading" className="text-sm font-semibold text-primary">Severity movement</h3><span className="text-xs text-tertiary">Select a severity to filter · Before → after → net change</span></div>
      <SeverityComparison before={summary.baselineSeverity} after={summary.currentSeverity} onSelect={onSeverityChange} />
    </section>

    {!neutral ? <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-secondary pt-4 text-sm text-secondary"><span>Fixed rate <strong className="font-mono text-primary">{formatRatio(summary.fixedRate)}</strong></span><span>Risk reduction <strong className="font-mono text-primary">{formatRatio(summary.riskReduction)}</strong></span><span>Risk model <strong className="font-mono text-primary">v{summary.riskModelVersion}</strong></span></div> : null}
  </div>
}

function TrendHighlights({ summary, neutral }: { summary: AssessmentComparisonSummary; neutral: boolean }) {
  type TrendTone = 'critical' | 'success' | 'warning' | 'muted'
  const criticalDelta = summary.currentSeverity.critical - summary.baselineSeverity.critical
  const priorityBefore = summary.baselineSeverity.critical + summary.baselineSeverity.high
  const priorityAfter = summary.currentSeverity.critical + summary.currentSeverity.high
  const priorityDelta = priorityAfter - priorityBefore
  const highlights: Array<{ label: string; value: string; detail: string; tone: TrendTone }> = [
    { label: 'Critical trend', value: `${summary.baselineSeverity.critical.toLocaleString()} → ${summary.currentSeverity.critical.toLocaleString()}`, detail: trendLabel(criticalDelta), tone: criticalDelta > 0 ? 'critical' : criticalDelta < 0 ? 'success' : 'muted' },
    { label: 'High + critical', value: `${priorityBefore.toLocaleString()} → ${priorityAfter.toLocaleString()}`, detail: trendLabel(priorityDelta), tone: priorityDelta > 0 ? 'critical' : priorityDelta < 0 ? 'success' : 'muted' },
    neutral
      ? { label: 'Snapshot difference', value: formatSignedNumber(summary.currentCount - summary.baselineCount), detail: 'net finding identities', tone: summary.currentCount > summary.baselineCount ? 'critical' : summary.currentCount < summary.baselineCount ? 'success' : 'muted' }
      : { label: 'Remediation balance', value: `${summary.fixedCount.toLocaleString()} fixed`, detail: `${(summary.newCount + summary.reopenedCount).toLocaleString()} new or re-opened`, tone: summary.fixedCount >= summary.newCount + summary.reopenedCount ? 'success' : 'warning' },
  ]
  const styles: Record<TrendTone, string> = { critical: 'border-critical/25 bg-critical/5 text-criticaltext', success: 'border-success/25 bg-success/5 text-success-primary', warning: 'border-warning/25 bg-warning/5 text-warning-primary', muted: 'border-secondary bg-secondary/20 text-primary' }
  return <section aria-labelledby="notable-changes-heading"><h3 id="notable-changes-heading" className="mb-3 text-sm font-semibold text-primary">Notable changes</h3><div className="grid gap-3 md:grid-cols-3">{highlights.map((item) => <div key={item.label} className={cn('rounded-lg border px-4 py-3', styles[item.tone])}><p className="text-[10px] font-semibold uppercase tracking-wider text-tertiary">{item.label}</p><p className="mt-1 font-mono text-lg font-semibold tabular-nums">{item.value}</p><p className="mt-1 text-xs text-tertiary">{item.detail}</p></div>)}</div></section>
}

function SnapshotCard({ eyebrow, snapshot, assessmentLabel, current = false }: { eyebrow: string; snapshot: AssessmentSnapshot | null; assessmentLabel: string; current?: boolean }) {
  return <div className={cn('rounded-xl border p-4 shadow-xs', current ? 'border-brand/30 bg-brand-primary/10' : 'border-secondary bg-secondary/40')}>
    <div className="flex items-center justify-between gap-3"><p className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">{eyebrow}</p>{snapshot ? <Pill className={current ? 'bg-primary text-brand-secondary' : undefined}>Snapshot {snapshot.snapshotNumber}</Pill> : null}</div>
    <p className="mt-3 font-semibold text-primary">{assessmentLabel}</p>
    {snapshot ? <><p className="mt-1 text-sm text-secondary">{formatSnapshotTime(snapshot.finalizedAt || snapshot.createdAt)}</p><p className="mt-3 font-mono text-xs text-quaternary">{snapshot.id.slice(0, 12)}</p></> : <p className="mt-2 text-sm text-tertiary">No snapshot selected</p>}
  </div>
}

function ScopeTabs({ scope, onChange }: { scope: AssessmentComparisonScope; onChange: (scope: AssessmentComparisonScope) => void }) {
  return <div className="inline-flex max-w-full overflow-x-auto rounded-lg bg-secondary p-1" role="tablist" aria-label="Finding scope">
    {SCOPES.map((item) => <button key={item.value} type="button" role="tab" aria-selected={scope === item.value} onClick={() => onChange(item.value)} className={cn('whitespace-nowrap rounded-md px-3 py-2 text-sm font-semibold transition', scope === item.value ? 'bg-primary text-primary shadow-xs' : 'text-tertiary hover:text-primary')}>{item.label}</button>)}
  </div>
}

function LifecycleMetric({ label, value, tone = 'default', onClick }: { label: string; value: number; tone?: 'default' | 'success' | 'critical' | 'warning' | 'muted'; onClick: () => void }) {
  const tones = { default: 'text-primary', success: 'text-success-primary', critical: 'text-critical', warning: 'text-warning-primary', muted: 'text-tertiary' }
  return <button type="button" onClick={onClick} className="rounded-lg border border-secondary bg-secondary/30 p-3 text-left transition hover:border-primary hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
    <span className="text-xs font-medium text-tertiary">{label}</span><span className={cn('mt-1 block font-mono text-xl font-semibold tabular-nums', tones[tone])}>{value.toLocaleString()}</span>
  </button>
}

const SEVERITY_TONES: Record<Severity, { surface: string; bar: string; text: string; delta: string }> = {
  critical: { surface: 'border-critical/30 bg-critical/5', bar: 'bg-critical', text: 'text-criticaltext', delta: 'bg-critical/10 text-criticaltext' },
  high: { surface: 'border-high/30 bg-high/5', bar: 'bg-high', text: 'text-hightext', delta: 'bg-high/10 text-hightext' },
  medium: { surface: 'border-medium/30 bg-medium/5', bar: 'bg-medium', text: 'text-mediumtext', delta: 'bg-medium/10 text-mediumtext' },
  low: { surface: 'border-low/30 bg-low/5', bar: 'bg-low', text: 'text-lowtext', delta: 'bg-low/10 text-lowtext' },
  info: { surface: 'border-infosev/30 bg-infosev/5', bar: 'bg-infosev', text: 'text-infosevtext', delta: 'bg-infosev/10 text-infosevtext' },
  unknown: { surface: 'border-secondary bg-secondary/20', bar: 'bg-quaternary', text: 'text-tertiary', delta: 'bg-secondary text-tertiary' },
}

function severityTone(severity: Severity) {
  return SEVERITY_TONES[severity]
}

function SeverityTag({ severity, emptyLabel = 'Unknown' }: { severity: Severity | null | undefined; emptyLabel?: string }) {
  if (!severity) return <Pill>{emptyLabel}</Pill>
  if (severity === 'unknown') return <Pill>Unknown</Pill>
  return <SeverityBadge severity={severity} size="sm" />
}

function severityBarWidth(value: number, maximum: number) {
  if (!Number.isFinite(value) || value <= 0) return '0%'
  return `${Math.max(5, Math.min(100, (value / maximum) * 100))}%`
}

function SeverityComparison({ before, after, onSelect }: { before: Record<Severity, number>; after: Record<Severity, number>; onSelect: (severity: Severity) => void }) {
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
  const maximum = Math.max(1, ...severities.flatMap((severity) => [before[severity], after[severity]]))
  return <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{severities.map((severity) => {
    const delta = after[severity] - before[severity]
    const exposed = before[severity] > 0 || after[severity] > 0
    const tone = severityTone(severity)
    return <button type="button" key={severity} onClick={() => onSelect(severity)} aria-label={`${labelize(severity)}: ${before[severity]} before, ${after[severity]} after, ${delta === 0 ? 'no change' : `${formatSignedNumber(delta)} net change`}`} className={cn('relative overflow-hidden rounded-xl border p-4 text-left shadow-xs transition hover:-translate-y-0.5 hover:border-primary hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60', exposed ? tone.surface : 'border-secondary bg-secondary/20')}>
      <span className={cn('absolute inset-x-0 top-0 h-0.5', tone.bar)} aria-hidden="true" />
      <div className="flex items-center justify-between gap-3">
        <SeverityTag severity={severity} />
        <span className={cn('rounded-md px-2 py-1 font-mono text-xs font-semibold tabular-nums', delta < 0 ? 'bg-success/10 text-success-primary' : delta > 0 ? tone.delta : 'bg-secondary text-tertiary')}>{delta === 0 ? 'No change' : formatSignedNumber(delta)}</span>
      </div>
      <div className="mt-4 grid grid-cols-[1fr_auto_1fr] items-end gap-3">
        <div><p className="text-[10px] font-semibold uppercase tracking-wider text-quaternary">Before</p><p className="mt-1 font-mono text-xl font-semibold tabular-nums text-secondary">{before[severity].toLocaleString()}</p></div>
        <ArrowNarrowRight className="mb-1 size-4 text-quaternary" aria-hidden="true" />
        <div className="text-right"><p className="text-[10px] font-semibold uppercase tracking-wider text-quaternary">After</p><p className={cn('mt-1 font-mono text-xl font-semibold tabular-nums', after[severity] > 0 ? tone.text : 'text-tertiary')}>{after[severity].toLocaleString()}</p></div>
      </div>
      <div className="mt-4 space-y-1.5" aria-hidden="true">
        <div className="h-1 overflow-hidden rounded-full bg-secondary"><div className={cn('h-full rounded-full opacity-40', tone.bar)} style={{ width: severityBarWidth(before[severity], maximum) }} /></div>
        <div className="h-1.5 overflow-hidden rounded-full bg-secondary"><div className={cn('h-full rounded-full', tone.bar)} style={{ width: severityBarWidth(after[severity], maximum) }} /></div>
      </div>
    </button>
  })}</div>
}

function ComparisonSortableHeader({ label, column, active, direction, onSort, className }: { label: string; column: ComparisonSortKey; active: ComparisonSortKey; direction: SortDirection; onSort: (key: ComparisonSortKey) => void; className?: string }) {
  const selected = active === column
  const Icon = !selected ? SwitchVertical01 : direction === 'asc' ? ArrowUp : ArrowDown
  return <th scope="col" aria-sort={selected ? direction === 'asc' ? 'ascending' : 'descending' : 'none'} className={className}><button type="button" onClick={() => onSort(column)} className="inline-flex items-center gap-1 font-bold uppercase tracking-wider text-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid">{label}<Icon className={cn('size-3', selected ? 'text-primary' : 'text-quaternary')} aria-hidden="true" /></button></th>
}

function ItemTable({ loading, error, items, unfilteredCount, searchQuery, sortKey, sortDirection, expandedItemId, onSort, onToggle, onSelect }: { loading: boolean; error: string | null; items: AssessmentComparisonItem[]; unfilteredCount: number; searchQuery: string; sortKey: ComparisonSortKey; sortDirection: SortDirection; expandedItemId: string; onSort: (key: ComparisonSortKey) => void; onToggle: (id: string) => void; onSelect: (item: AssessmentComparisonItem) => void }) {
  if (loading && !unfilteredCount) return <div className="p-8"><Spinner label="Loading compared findings…" /></div>
  if (error) return <div className="p-4"><ErrorState message={error} /></div>
  if (!items.length) return <div className="p-8 text-center"><p className="text-sm font-medium text-primary">No compared findings match</p><p className="mt-1 text-sm text-tertiary">{searchQuery ? `No item on this page matches “${searchQuery}”.` : 'Adjust the lifecycle, severity, or change filters to see more results.'}</p></div>
  return <div className="w-full overflow-x-auto"><table className="w-full min-w-[980px] text-left text-sm"><thead><tr className="border-b border-secondary bg-secondary text-[11px] font-bold uppercase tracking-wider text-secondary"><th className="w-8 pl-3 py-2.5" /><ComparisonSortableHeader label="Lifecycle" column="lifecycle" active={sortKey} direction={sortDirection} onSort={onSort} className="px-2 py-2.5" /><ComparisonSortableHeader label="Severity" column="severity" active={sortKey} direction={sortDirection} onSort={onSort} className="px-2 py-2.5" /><ComparisonSortableHeader label="Finding & identity" column="identity" active={sortKey} direction={sortDirection} onSort={onSort} className="px-4 py-2.5" /><ComparisonSortableHeader label="Changed" column="change" active={sortKey} direction={sortDirection} onSort={onSort} className="px-4 py-2.5" /><ComparisonSortableHeader label="Coverage" column="coverage" active={sortKey} direction={sortDirection} onSort={onSort} className="px-4 py-2.5" /><th className="px-4 py-2.5">Review</th></tr></thead><tbody className="divide-y divide-secondary">{items.map((item) => {
    const currentSeverity = item.currentObservation?.severity
    const open = expandedItemId === item.id
    const lifecycleState = item.presence ?? item.neutralPresence ?? ''
    return <Fragment key={item.id}>
      <tr onClick={() => onToggle(item.id)} className={cn('cursor-pointer transition-colors hover:bg-secondary', open && 'bg-secondary', currentSeverity === 'critical' && !open && 'bg-critical/5')}>
        <td className="pl-3 py-3 align-top"><button type="button" aria-expanded={open} aria-label={`Toggle comparison details for ${item.identityId}`} onClick={(event) => { event.stopPropagation(); onToggle(item.id) }} className="rounded p-1 text-quaternary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"><ChevronRight className={cn('size-4 transition-transform', open && 'rotate-90')} aria-hidden="true" /></button></td>
        <td className="px-2 py-3 align-top" onClick={(event) => event.stopPropagation()}><button type="button" onClick={() => onSelect(item)} className="rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"><LifecyclePill state={lifecycleState} /></button></td>
        <td className="px-2 py-3 align-top"><div className="flex items-center gap-1.5"><SeverityTag severity={item.baselineObservation?.severity} emptyLabel="None" /><ArrowNarrowRight className="size-3.5 shrink-0 text-quaternary" aria-hidden="true" /><SeverityTag severity={currentSeverity} emptyLabel="None" /></div></td>
        <td className="px-4 py-3 align-top"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-primary">{item.producerKind || 'legacy'} / {item.findingKind || 'unknown'}</span>{item.currentActionable ? <Pill className="bg-brand-primary/10 text-brand-secondary">Actionable</Pill> : null}</div><p className="mt-1 max-w-sm truncate font-mono text-xs text-tertiary" title={item.targetCanonical || item.identityId}>{item.targetCanonical || item.identityId}</p><p className="mt-1 max-w-sm truncate text-xs text-quaternary">{comparisonItemSubtitle(item)}</p></td>
        <td className="px-4 py-3 align-top"><div className="flex max-w-64 flex-wrap gap-1">{item.changeFlags.length ? item.changeFlags.map((flag) => <Pill key={flag}>{labelize(flag)}</Pill>) : <span className="text-tertiary">No field change</span>}</div></td>
        <td className="px-4 py-3 align-top"><CoveragePill decision={item.coverageDecision} /></td>
        <td className="px-4 py-3 align-top">{item.reviewCandidateIds.length ? <Pill className="bg-warning/10 text-warning-primary">{item.reviewCandidateIds.length} candidate(s)</Pill> : item.verificationId ? <Pill className="bg-success/10 text-success-primary">Verified</Pill> : <span className="text-tertiary">Clear</span>}</td>
      </tr>
      {open ? <tr className="border-t border-secondary bg-secondary"><td /><td colSpan={6} className="p-4"><ComparisonItemDetail item={item} onReview={() => onSelect(item)} /></td></tr> : null}
    </Fragment>
  })}</tbody></table></div>
}

function LifecyclePill({ state }: { state: string }) {
  const style = state === 'new' || state === 'only_in_b' ? 'bg-critical/10 text-criticaltext ring-critical/25' : state === 'not_detected_under_comparable_coverage' ? 'bg-success/10 text-success-primary ring-success/25' : state === 'reopened' || state === 'needs_review' ? 'bg-warning/10 text-warning-primary ring-warning/25' : state === 'not_evaluated' || state === 'only_in_a' ? 'bg-secondary text-tertiary ring-secondary' : 'bg-brand-primary/10 text-brand-secondary ring-brand/25'
  return <span className={cn('inline-flex whitespace-nowrap rounded-md px-2 py-1 text-xs font-semibold ring-1 ring-inset', style)}>{lifecycleLabel(state)}</span>
}

function CoveragePill({ decision }: { decision: AssessmentComparisonItem['coverageDecision'] }) {
  const style = decision === 'comparable' ? 'bg-success/10 text-success-primary' : decision === 'not_comparable' ? 'bg-warning/10 text-warning-primary' : 'bg-secondary text-tertiary'
  return <Pill className={style}>{labelize(decision || 'unknown')}</Pill>
}

function ComparisonItemDetail({ item, onReview }: { item: AssessmentComparisonItem; onReview: () => void }) {
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-primary">Finding state transition</p><p className="mt-1 font-mono text-xs text-tertiary">{item.identityId}</p></div><div className="flex items-center gap-2"><Pill>{item.baselineObservation ? 'Detected' : 'Absent'}</Pill><ArrowNarrowRight className="size-4 text-quaternary" aria-hidden="true" /><LifecyclePill state={item.presence ?? item.neutralPresence ?? ''} /><ArrowNarrowRight className="size-4 text-quaternary" aria-hidden="true" /><Pill>{item.currentObservation ? 'Detected' : 'Absent'}</Pill></div></div>
    <div className="grid gap-3 lg:grid-cols-2"><ObservationPanel label="Before" observation={item.baselineObservation} /><ObservationPanel label="After" observation={item.currentObservation} current /></div>
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-secondary pt-3 text-xs text-tertiary"><span>Disposition <strong className="text-secondary">{item.currentActionable ? 'Current actionable' : item.baselineActionable ? 'Baseline only' : 'Non-actionable'}</strong></span><span>Match <strong className="text-secondary">{item.matchMethods.length ? item.matchMethods.join(', ') : 'Stored identity'}</strong></span><span>Fixed basis <strong className="text-secondary">{labelize(item.fixedBasis || 'none')}</strong></span>{item.reviewCandidateIds.length ? <Button variant="secondary" className="ml-auto h-8 text-xs" onClick={onReview}>Review match</Button> : null}</div>
  </div>
}

function ObservationPanel({ label, observation, current = false }: { label: string; observation: AssessmentComparisonItem['baselineObservation']; current?: boolean }) {
  if (!observation) return <section className="rounded-lg border border-dashed border-secondary p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-tertiary">{label}</p><p className="mt-3 text-sm text-tertiary">Finding was not observed in this snapshot.</p></section>
  return <section className={cn('rounded-lg border p-4', current ? 'border-brand/25 bg-brand/5' : 'border-secondary bg-primary')}><div className="flex items-center justify-between gap-2"><p className="text-[10px] font-semibold uppercase tracking-wider text-tertiary">{label}</p><SeverityTag severity={observation.severity} /></div><dl className="mt-3 grid gap-x-4 gap-y-3 text-xs sm:grid-cols-2"><ObservationDetail label="Location" value={observation.location || 'Unknown'} /><ObservationDetail label="Component version" value={observation.componentVersion || 'Unknown'} /><ObservationDetail label="Reachability" value={observation.reachability || 'Unknown'} /><ObservationDetail label="Scanner" value={[observation.scanner.toolName, observation.scanner.toolVersion].filter(Boolean).join(' ') || 'Unknown'} /><ObservationDetail label="Rule" value={observation.scanner.ruleId || 'Unknown'} /><ObservationDetail label="Observed" value={formatSnapshotTime(observation.observedAt)} /></dl></section>
}

function ObservationDetail({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><dt className="font-semibold text-tertiary">{label}</dt><dd className="mt-0.5 truncate text-secondary" title={value}>{value}</dd></div>
}

function ComparisonPagination({ page, pageSize, count, canPrevious, canNext, onPrevious, onNext, onPageSizeChange }: { page: number; pageSize: number; count: number; canPrevious: boolean; canNext: boolean; onPrevious: () => void; onNext: () => void; onPageSizeChange: (size: number) => void }) {
  return <div className="flex flex-wrap items-center justify-between gap-3 border-t border-secondary px-4 py-3"><span className="text-xs text-tertiary">Page <span className="font-semibold text-primary">{page}</span> · <span className="font-semibold text-primary">{count}</span> findings shown</span><div className="flex items-center gap-2"><Select value={String(pageSize)} onValueChange={(value) => onPageSizeChange(Number(value))} size="sm" ariaLabel="Compared findings per page" className="w-28" options={PAGE_SIZE_OPTIONS.map((size) => ({ value: String(size), label: `${size} / page` }))} /><button type="button" onClick={onPrevious} disabled={!canPrevious} aria-label="Previous comparison page" className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"><ChevronLeft className="size-4" aria-hidden="true" /></button><span className="text-xs tabular-nums text-tertiary">Page <span className="font-semibold text-primary">{page}</span></span><button type="button" onClick={onNext} disabled={!canNext} aria-label="Next comparison page" className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"><ChevronRight className="size-4" aria-hidden="true" /></button></div></div>
}

function ReviewDrawer({ comparison, item, onClose, onReplacement }: { comparison: AssessmentComparison | null; item: AssessmentComparisonItem; onClose: () => void; onReplacement: (id: string) => void }) {
  const [candidateId, setCandidateId] = useState(item.reviewCandidateIds[0] ?? '')
  const candidate = item.reviewCandidates.find((value) => value.id === candidateId)
  const sourceOptions = candidate?.sourceObservationIds.map((id) => ({ value: id, label: id })) ?? []
  const [sourceObservationId, setSourceObservationId] = useState(sourceOptions[0]?.value ?? '')
  const [reason, setReason] = useState('operator_review')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    setSourceObservationId(item.reviewCandidates.find((value) => value.id === candidateId)?.sourceObservationIds[0] ?? '')
  }, [candidateId, item.reviewCandidates])
  async function submit(action: 'confirm' | 'unlink') {
    if (!comparison || !candidateId || !sourceObservationId || !reason.trim()) return
    setSubmitting(true); setError('')
    try {
      const result = await api.reviewAssessmentComparisonItem({ comparisonId: comparison.id, itemId: item.id, comparisonVersion: comparison.version, action, candidateId, sourceObservationId, reason: reason.trim() })
      onReplacement(result.replacementComparisonId)
    } catch (cause) { setError(cause instanceof ApiError && cause.status === 409 ? 'The review projection changed. Your filters and item context are preserved; refresh and retry.' : cause instanceof Error ? cause.message : 'Review failed.') }
    finally { setSubmitting(false) }
  }
  return <SlideoutMenu isOpen onOpenChange={(open) => { if (!open) onClose() }}><SlideoutMenu.Header onClose={onClose}><h2 className="text-lg font-semibold text-primary">Immutable item detail</h2><p className="mt-1 font-mono text-xs text-tertiary">{item.id}</p></SlideoutMenu.Header><SlideoutMenu.Content><dl className="space-y-3 text-sm"><Detail label="Identity" value={item.identityId} /><Detail label="Identity explanation" value={`${item.producerKind || 'legacy'} / ${item.findingKind || 'unknown'} on ${item.targetCanonical || 'unknown target'}`} /><Detail label="Ancestry path" value={`${item.baselineObservationId || 'none'} → ${item.identityId} → ${item.currentObservationId || 'none'}`} /><Detail label="Match methods" value={item.matchMethods.length ? item.matchMethods.join(', ') : 'Stored identity; method provenance unavailable'} /><Detail label="Coverage" value={labelize(item.coverageDecision || 'unknown')} /><Detail label="Verification" value={item.verificationId ? `${item.verificationState} · ${item.verificationId}` : 'None'} /><Detail label="Evidence references" value={[item.baselineObservation?.evidenceDigest, item.currentObservation?.evidenceDigest].filter(Boolean).join(' → ') || 'None'} /></dl>{item.reviewCandidateIds.length ? <section className="space-y-4 border-t border-secondary pt-5"><Field label="Candidate"><Select ariaLabel="Review candidate" value={candidateId} onValueChange={setCandidateId} options={item.reviewCandidateIds.map((id) => ({ value: id, label: id }))} className="w-full" /></Field>{sourceOptions.length ? <Field label="Source observation"><Select ariaLabel="Review source observation" value={sourceObservationId} onValueChange={setSourceObservationId} options={sourceOptions} className="w-full" /></Field> : <ErrorState message="This immutable candidate has no reviewable source observation metadata." />}<Field label="Reason"><Input value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} /></Field>{error ? <ErrorState message={error} /> : null}<div className="flex gap-3"><Button disabled={!sourceObservationId} loading={submitting} onClick={() => submit('confirm')}>Confirm link</Button><Button disabled={!sourceObservationId} variant="danger" loading={submitting} onClick={() => submit('unlink')}>Unlink</Button></div><p className="text-xs text-tertiary">Review appends an override and follows a replacement comparison; this completed item is never mutated.</p></section> : <p className="rounded-lg bg-secondary p-3 text-sm text-tertiary">No open review candidate is attached to this item.</p>}</SlideoutMenu.Content></SlideoutMenu>
}

function comparisonAssessmentIds(lifecycle: AssessmentLifecycle | null, assessmentId: string, mode: AssessmentComparisonMode) {
  if (!lifecycle) return []
  if (mode === 'neutral_diff') return lifecycle.members.map((member) => member.assessmentId)
  const byId = new Map(lifecycle.members.map((member) => [member.assessmentId, member]))
  const result: string[] = []
  let member = byId.get(assessmentId)
  while (member?.predecessorAssessmentId) { result.push(member.predecessorAssessmentId); member = byId.get(member.predecessorAssessmentId) }
  result.push(assessmentId)
  return [...new Set(result)]
}

function chooseBaselineSnapshot(snapshots: AssessmentSnapshotListResponse, sameAssessment: boolean, currentId: string) {
  const available = snapshots.items.filter((item) => item.id !== currentId)
  if (!available.length) return ''
  if (!sameAssessment) return snapshots.defaultSnapshotId && snapshots.defaultSnapshotId !== currentId ? snapshots.defaultSnapshotId : available.at(-1)?.id ?? ''
  const currentIndex = snapshots.items.findIndex((item) => item.id === currentId)
  return currentIndex > 0 ? snapshots.items[currentIndex - 1].id : available[0].id
}

function filterComparisonItems(items: AssessmentComparisonItem[], query: string) {
  const normalized = query.trim().toLowerCase()
  if (!normalized) return items
  return items.filter((item) => [
    item.identityId, item.producerKind, item.findingKind, item.targetCanonical,
    item.presence, item.neutralPresence, item.coverageDecision, item.fixedBasis,
    ...item.changeFlags, ...item.matchMethods,
    item.baselineObservation?.location, item.currentObservation?.location,
    item.baselineObservation?.scanner.toolName, item.currentObservation?.scanner.toolName,
    item.baselineObservation?.scanner.ruleId, item.currentObservation?.scanner.ruleId,
  ].filter(Boolean).join(' ').toLowerCase().includes(normalized))
}

function sortComparisonItems(items: AssessmentComparisonItem[], key: ComparisonSortKey, direction: SortDirection) {
  const value = (item: AssessmentComparisonItem): string | number => {
    if (key === 'severity') return sevRank(item.currentObservation?.severity ?? item.baselineObservation?.severity ?? 'unknown')
    if (key === 'lifecycle') return lifecycleLabel(item.presence ?? item.neutralPresence ?? '')
    if (key === 'identity') return `${item.producerKind} ${item.findingKind} ${item.targetCanonical || item.identityId}`
    if (key === 'change') return item.changeFlags.join(' ')
    return item.coverageDecision
  }
  const sign = direction === 'asc' ? 1 : -1
  return items.map((item, index) => ({ item, index })).sort((left, right) => {
    const a = value(left.item)
    const b = value(right.item)
    const comparison = typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b))
    return sign * comparison || left.index - right.index
  }).map(({ item }) => item)
}

function lifecycleLabel(state: string) {
  const labels: Record<string, string> = {
    new: 'New',
    still_detected: 'Still detected',
    not_detected_under_comparable_coverage: 'Fixed',
    not_evaluated: 'Not evaluated',
    reopened: 'Re-opened',
    needs_review: 'Needs review',
    only_in_a: 'Only before',
    both: 'Both snapshots',
    only_in_b: 'Only after',
  }
  return labels[state] ?? labelize(state)
}

function comparisonItemSubtitle(item: AssessmentComparisonItem) {
  const observation = item.currentObservation ?? item.baselineObservation
  if (!observation) return item.identityId
  return [observation.location, observation.scanner.toolName, observation.scanner.ruleId].filter(Boolean).join(' · ') || item.identityId
}

function coverageCounts(baseline: AssessmentSnapshot | null, current: AssessmentSnapshot | null) {
  if (!baseline || !current) return { comparable: 0, partial: 0, notComparable: 1 }
  const dimensionKey = (dimension: AssessmentSnapshot['dimensions'][number]) => JSON.stringify([dimension.producer, dimension.findingKind, dimension.target.kind, dimension.target.schemaVersion, dimension.target.canonical])
  const currentByKey = new Map(current.dimensions.map((dimension) => [dimensionKey(dimension), dimension]))
  const sameValues = (left: string[], right: string[]) => JSON.stringify([...left].sort()) === JSON.stringify([...right].sort())
  const versionValues = (dimension: AssessmentSnapshot['dimensions'][number], kinds: string[]) => dimension.versions.filter((version) => kinds.includes(version.kind)).map((version) => JSON.stringify([version.kind, version.name, version.version, version.digest]))
  let comparable = 0, partial = 0, notComparable = 0
  for (const dimension of baseline.dimensions) {
    const match = currentByKey.get(dimensionKey(dimension))
    if (!match || match.state === 'unknown') notComparable++
    else if (dimension.state !== 'complete' || match.state !== 'complete') partial++
    else if (!sameValues(dimension.includedScope, match.includedScope) || !sameValues(dimension.excludedScope, match.excludedScope)) partial++
    else if (!sameValues(versionValues(dimension, ['rule_pack', 'profile']), versionValues(match, ['rule_pack', 'profile']))) notComparable++
    else if (!sameValues(versionValues(dimension, ['advisory_database', 'tool', 'scanner', 'correlation', 'schema']), versionValues(match, ['advisory_database', 'tool', 'scanner', 'correlation', 'schema']))) partial++
    else comparable++
  }
  if (!baseline.dimensions.length) notComparable++
  return { comparable, partial, notComparable }
}

function formatRatio(value: AssessmentComparisonRatio) { return value.naReason || value.denominator <= 0 ? 'N/A' : `${Math.round((value.numerator / value.denominator) * 100)}%` }
function trendLabel(delta: number) { return delta === 0 ? 'No net change' : `${formatSignedNumber(delta)} ${delta > 0 ? 'increase' : 'reduction'}` }
function snapshotOption(snapshot: AssessmentSnapshot) { return { value: snapshot.id, label: `Snapshot ${snapshot.snapshotNumber} · ${snapshot.id.slice(0, 8)} · ${snapshot.provenance} · ${snapshot.lifecycle}` } }
function memberLabel(lifecycle: AssessmentLifecycle, id: string, includeId = true) { const member = lifecycle.members.find((value) => value.assessmentId === id); const label = member?.assessmentType === 'retest' ? `Re-test #${member.retestNumber}` : 'Initial assessment'; return includeId ? `${label} · ${id}` : label }
function setOrDelete(params: URLSearchParams, key: string, value: string) { if (value) params.set(key, value); else params.delete(key) }
function option(value: string) { return { value, label: labelize(value) } }
function labelize(value: string) { return value ? value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()) : 'Unknown' }
function formatSignedNumber(value: number) { return value > 0 ? `+${value.toLocaleString()}` : value.toLocaleString() }
function formatSignedPercent(value: number | null) { if (value === null || !Number.isFinite(value)) return 'N/A'; if (value === 0) return '0%'; return `${value > 0 ? '+' : '−'}${Math.abs(value).toLocaleString(undefined, { maximumFractionDigits: 1 })}%` }
function scopeNoun(scope: AssessmentComparisonScope) { return scope === 'vulnerability' ? 'vulnerabilities' : scope === 'security' ? 'security findings' : 'findings' }
function formatSnapshotTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'Finalization time unavailable' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date) }
function Detail({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs font-semibold uppercase tracking-wide text-tertiary">{label}</dt><dd className="mt-1 break-all text-primary">{value}</dd></div> }
