import { AlertCircle, CheckCircle, GitBranch01, InfoCircle, RefreshCw01, SearchLg } from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { SlideoutMenu } from '../../components/application/slideout-menus/slideout-menu'
import { Button, Card, EmptyState, ErrorState, Field, Input, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import type { AssessmentComparison, AssessmentComparisonChangeFlag, AssessmentComparisonItem, AssessmentComparisonMode, AssessmentComparisonRatio, AssessmentLifecycle, AssessmentSnapshot, AssessmentSnapshotListResponse, Severity } from '../../lib/types'

const ALL = 'all'
const PRESENCE = ['all', 'new', 'still_detected', 'not_detected_under_comparable_coverage', 'not_evaluated', 'reopened', 'needs_review'].map(option)
const SEVERITY = ['all', 'critical', 'high', 'medium', 'low', 'info', 'unknown'].map(option)
const REVIEW = ['all', 'needs_review', 'verified', 'clear'].map(option)
const DISPOSITION = ['all', 'current_actionable', 'baseline_only', 'non_actionable'].map(option)
const CHANGES = ['all', 'severity_increased', 'severity_decreased', 'component_version_changed', 'location_changed', 'reachability_changed', 'evidence_changed', 'scanner_changed', 'rule_profile_changed', 'advisory_changed'].map(option)

export function AssessmentComparisonTab({ assessmentId }: { assessmentId: string }) {
  const [params, setParams] = useSearchParams()
  const mode = (params.get('comparison_mode') === 'neutral_diff' ? 'neutral_diff' : 'lifecycle') as AssessmentComparisonMode
  const baselineAssessmentParam = params.get('comparison_base_assessment') ?? ''
  const baselineSnapshotId = params.get('comparison_baseline') ?? ''
  const currentSnapshotId = params.get('comparison_current') ?? ''
  const comparisonId = params.get('comparison_id') ?? ''
  const cursor = params.get('comparison_cursor') ?? ''
  const presence = params.get('comparison_presence') ?? ALL
  const severity = params.get('comparison_severity') ?? ALL
  const changeFlag = params.get('comparison_change') ?? ALL
  const reviewState = params.get('comparison_review') ?? ALL
  const disposition = params.get('comparison_disposition') ?? ALL
  const producer = params.get('comparison_producer') ?? ''
  const findingKind = params.get('comparison_kind') ?? ''
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')
  const [selectedItem, setSelectedItem] = useState<AssessmentComparisonItem | null>(null)

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
  useEffect(() => {
    if (!comparison || !['queued', 'generating'].includes(comparison.status)) return
    const timer = window.setInterval(comparisonFetch.refetch, 2000)
    return () => window.clearInterval(timer)
  }, [comparison, comparisonFetch.refetch])

  const itemFetch = useFetch(() => api.assessmentComparisonItems(comparisonId, {
    cursor: cursor || undefined, limit: 50,
    presence: presence === ALL ? undefined : presence,
    severity: severity === ALL ? undefined : severity,
    changeFlag: changeFlag === ALL ? undefined : changeFlag as AssessmentComparisonChangeFlag,
    reviewState: reviewState === ALL ? undefined : reviewState,
    disposition: disposition === ALL ? undefined : disposition,
    producer: producer || undefined, findingKind: findingKind || undefined,
  }), {
    enabled: Boolean(comparisonId) && ['complete', 'needs_review', 'superseded'].includes(comparison?.status ?? ''),
    deps: [changeFlag, comparisonId, cursor, disposition, findingKind, presence, producer, reviewState, severity],
  })

  const baselineSnapshot = baselineSnapshots?.items.find((item) => item.id === baselineSnapshotId) ?? null
  const currentSnapshot = currentSnapshots?.items.find((item) => item.id === currentSnapshotId) ?? null

  function setParam(key: string, value: string, clearComparison = false) {
    setParams((next) => {
      setOrDelete(next, key, value === ALL ? '' : value)
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
    } catch (error) { setCreateError(error instanceof Error ? error.message : 'Comparison request failed.') }
    finally { setCreating(false) }
  }

  if (context.loading && !context.data) return <Spinner label="Loading assessment comparison context…" />
  if (context.error) return <ErrorState message={context.error} />
  if (!lifecycle || !currentSnapshots?.items.length) return <EmptyState icon={GitBranch01} title="No immutable snapshots to compare" hint="Finalize at least one assessment snapshot before creating a comparison." />

  return <div className="space-y-5">
    <Card title="Comparison pair">
      <p className="mb-4 text-sm text-tertiary">Lifecycle direction is server-enforced; sibling or reverse pairs require explicit neutral diff.</p>
      <div className="grid gap-4 lg:grid-cols-4">
        <Field label="Mode"><Select ariaLabel="Comparison mode" value={mode} onValueChange={(value) => setParam('comparison_mode', value, true)} options={[option('lifecycle'), option('neutral_diff')]} className="w-full" /></Field>
        <Field label="Baseline assessment"><Select ariaLabel="Baseline assessment" value={baselineAssessmentId} onValueChange={(value) => setParam('comparison_base_assessment', value, true)} options={assessmentIds.map((id) => ({ value: id, label: memberLabel(lifecycle, id) }))} className="w-full" /></Field>
        <Field label="Baseline snapshot"><Select ariaLabel="Baseline snapshot" value={baselineSnapshotId} onValueChange={(value) => setParam('comparison_baseline', value, true)} options={(baselineSnapshots?.items ?? []).map(snapshotOption)} className="w-full" /></Field>
        <Field label="Current snapshot"><Select ariaLabel="Current snapshot" value={currentSnapshotId} onValueChange={(value) => setParam('comparison_current', value, true)} options={currentSnapshots.items.map(snapshotOption)} className="w-full" /></Field>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3"><Button loading={creating} onClick={createComparison}>Compare snapshots</Button>{comparisonId ? <span className="font-mono text-xs text-tertiary">Projection {comparisonId}</span> : null}</div>
      {createError ? <ErrorState className="mt-4" message={createError} /> : null}
    </Card>
    <CoverageBanner baseline={baselineSnapshot} current={currentSnapshot} />
    {comparisonId && comparisonFetch.loading && !comparison ? <Spinner label="Loading immutable comparison…" /> : null}
    {comparisonFetch.error ? <ErrorState message={comparisonFetch.error} /> : null}
    {comparison ? <ComparisonState comparison={comparison} onRefresh={comparisonFetch.refetch} /> : null}
    {comparison && ['complete', 'needs_review', 'superseded'].includes(comparison.status) ? <>
      <Summary comparison={comparison} />
      <Card title="Comparison items">
        <p className="mb-4 text-sm text-tertiary">Server-backed filters and a stable cursor keep large comparisons bounded.</p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-7">
          <Select ariaLabel="Presence filter" value={presence} onValueChange={(value) => setParam('comparison_presence', value)} options={PRESENCE} className="w-full" />
          <Select ariaLabel="Severity filter" value={severity} onValueChange={(value) => setParam('comparison_severity', value)} options={SEVERITY} className="w-full" />
          <Select ariaLabel="Changed field filter" value={changeFlag} onValueChange={(value) => setParam('comparison_change', value)} options={CHANGES} className="w-full" />
          <Select ariaLabel="Review state filter" value={reviewState} onValueChange={(value) => setParam('comparison_review', value)} options={REVIEW} className="w-full" />
          <Select ariaLabel="Disposition filter" value={disposition} onValueChange={(value) => setParam('comparison_disposition', value)} options={DISPOSITION} className="w-full" />
          <Input aria-label="Producer filter" placeholder="Producer" value={producer} onChange={(event) => setParam('comparison_producer', event.target.value)} />
          <Input aria-label="Finding kind filter" placeholder="Finding kind" value={findingKind} onChange={(event) => setParam('comparison_kind', event.target.value)} />
        </div>
        <ItemTable loading={itemFetch.loading} error={itemFetch.error} items={itemFetch.data?.items ?? []} onSelect={setSelectedItem} />
        <div className="mt-4 flex justify-end"><Button variant="secondary" disabled={!itemFetch.data?.nextCursor} onClick={() => setParam('comparison_cursor', itemFetch.data?.nextCursor ?? '')}>Next page</Button></div>
      </Card>
    </> : null}
    {selectedItem ? <ReviewDrawer comparison={comparison} item={selectedItem} onClose={() => setSelectedItem(null)} onReplacement={(id) => { setSelectedItem(null); setParams((next) => { next.set('comparison_id', id); next.delete('comparison_cursor'); return next }) }} /> : null}
  </div>
}

function ComparisonState({ comparison, onRefresh }: { comparison: AssessmentComparison; onRefresh: () => void }) {
  const terminal = ['complete', 'needs_review', 'superseded'].includes(comparison.status)
  return <div role="status" className={cn('flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 text-sm', terminal ? 'border-secondary bg-primary' : 'border-brand/30 bg-brand-primary')}><span><strong>{labelize(comparison.status)}</strong> · v{comparison.version} · {comparison.baselineSnapshotId} → {comparison.currentSnapshotId}</span><Button variant="ghost" onClick={onRefresh}><RefreshCw01 className="size-4" />Refresh</Button></div>
}

function CoverageBanner({ baseline, current }: { baseline: AssessmentSnapshot | null; current: AssessmentSnapshot | null }) {
  const counts = coverageCounts(baseline, current)
  const unsafe = !baseline || !current || baseline.provenance === 'legacy' || current.provenance === 'legacy' || counts.notComparable > 0
  return <div className={cn('rounded-xl border px-4 py-4', unsafe ? 'border-warning/30 bg-warning/10' : counts.partial ? 'border-brand/30 bg-brand-primary' : 'border-success/30 bg-success/10')}><div className="flex items-start gap-3">{unsafe ? <AlertCircle className="mt-0.5 size-5 text-warning" /> : counts.partial ? <InfoCircle className="mt-0.5 size-5 text-brand" /> : <CheckCircle className="mt-0.5 size-5 text-success" />}<div><p className="font-semibold text-primary">Coverage before metrics</p><p className="mt-1 text-sm text-secondary">Comparable {counts.comparable} · Partial {counts.partial} · Not comparable/unknown {counts.notComparable}. Legacy or unknown coverage never implies success.</p></div></div></div>
}

function Summary({ comparison }: { comparison: AssessmentComparison }) {
  const value = comparison.summary
  const metrics = [['Fixed rate', formatRatio(value.fixedRate)], ['Count reduction', formatRatio(value.countReduction)], ['Risk reduction', formatRatio(value.riskReduction)], ['Fixed', String(value.fixedCount)], ['New / re-opened', `${value.newCount} / ${value.reopenedCount}`], ['Needs review', String(value.reviewCount)]]
  return <Card title="Immutable summary"><p className="mb-4 text-sm text-tertiary">Comparison {value.comparisonId}; baseline {value.baselineSnapshotId}; current {value.currentSnapshotId}.</p><dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">{metrics.map(([label, metric]) => <div key={label} className="rounded-lg border border-secondary bg-secondary/40 p-3"><dt className="text-xs text-tertiary">{label}</dt><dd className="mt-1 text-xl font-semibold text-primary">{metric}</dd></div>)}</dl><div className="mt-4 grid gap-3 md:grid-cols-2"><SeverityLine label="Before severity" values={value.baselineSeverity} /><SeverityLine label="Current severity" values={value.currentSeverity} /></div><p className="mt-3 text-xs text-tertiary">New risk {value.newRisk} · Re-opened risk {value.reopenedRisk} · Risk model v{value.riskModelVersion}</p></Card>
}

function ItemTable({ loading, error, items, onSelect }: { loading: boolean; error: string | null; items: AssessmentComparisonItem[]; onSelect: (item: AssessmentComparisonItem) => void }) {
  if (loading && !items.length) return <Spinner label="Loading comparison items…" />
  if (error) return <ErrorState className="mt-4" message={error} />
  if (!items.length) return <EmptyState icon={SearchLg} title="No comparison items" hint="No immutable item matches the selected filters." />
  return <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[900px] text-left text-sm"><thead><tr className="border-b border-secondary text-xs text-tertiary"><th className="px-3 py-3">Lifecycle</th><th className="px-3 py-3">Identity</th><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Changed</th><th className="px-3 py-3">Disposition</th><th className="px-3 py-3">Coverage</th><th className="px-3 py-3">Review</th></tr></thead><tbody>{items.map((item) => <tr key={item.id} className="border-b border-secondary last:border-0"><td className="px-3 py-3"><button className="font-semibold text-brand-secondary hover:underline focus-visible:outline-2 focus-visible:outline-brand" onClick={() => onSelect(item)}>{labelize(item.presence ?? item.neutralPresence ?? '')}</button></td><td className="px-3 py-3"><div>{item.producerKind || 'legacy'} / {item.findingKind || 'unknown'}</div><div className="max-w-64 truncate font-mono text-xs text-tertiary" title={item.targetCanonical}>{item.targetCanonical || item.identityId}</div></td><td className="px-3 py-3">{item.baselineObservation?.severity ?? '—'} → {item.currentObservation?.severity ?? '—'}</td><td className="px-3 py-3">{item.changeFlags.length ? item.changeFlags.map(labelize).join(', ') : 'None'}</td><td className="px-3 py-3">{item.currentActionable ? 'Current actionable' : item.baselineActionable ? 'Baseline only' : 'Non-actionable'}</td><td className="px-3 py-3">{labelize(item.coverageDecision || 'unknown')}</td><td className="px-3 py-3">{item.reviewCandidateIds.length ? `${item.reviewCandidateIds.length} candidate(s)` : item.verificationId ? 'Verified' : 'Clear'}</td></tr>)}</tbody></table></div>
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

function coverageCounts(baseline: AssessmentSnapshot | null, current: AssessmentSnapshot | null) {
  if (!baseline || !current) return { comparable: 0, partial: 0, notComparable: 1 }
  const currentByKey = new Map(current.dimensions.map((dimension) => [`${dimension.producer}\0${dimension.findingKind}\0${dimension.target.canonical}`, dimension]))
  let comparable = 0, partial = 0, notComparable = 0
  for (const dimension of baseline.dimensions) {
    const match = currentByKey.get(`${dimension.producer}\0${dimension.findingKind}\0${dimension.target.canonical}`)
    if (!match || match.state === 'unknown') notComparable++
    else if (dimension.state !== 'complete' || match.state !== 'complete') partial++
    else comparable++
  }
  if (!baseline.dimensions.length) notComparable++
  return { comparable, partial, notComparable }
}

function formatRatio(value: AssessmentComparisonRatio) { return value.naReason || value.denominator <= 0 ? 'N/A' : `${Math.round((value.numerator / value.denominator) * 100)}%` }
function snapshotOption(snapshot: AssessmentSnapshot) { return { value: snapshot.id, label: `Snapshot ${snapshot.snapshotNumber} · ${snapshot.provenance} · ${snapshot.lifecycle}` } }
function memberLabel(lifecycle: AssessmentLifecycle, id: string) { const member = lifecycle.members.find((value) => value.assessmentId === id); return member?.assessmentType === 'retest' ? `Re-test #${member.retestNumber} · ${id}` : `Initial · ${id}` }
function setOrDelete(params: URLSearchParams, key: string, value: string) { if (value) params.set(key, value); else params.delete(key) }
function option(value: string) { return { value, label: labelize(value) } }
function labelize(value: string) { return value ? value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()) : 'Unknown' }
function SeverityLine({ label, values }: { label: string; values: Record<Severity, number> }) { return <div className="rounded-lg border border-secondary p-3"><p className="text-xs font-semibold text-tertiary">{label}</p><p className="mt-2 text-sm text-secondary">Critical {values.critical} · High {values.high} · Medium {values.medium} · Low {values.low} · Info {values.info} · Unknown {values.unknown}</p></div> }
function Detail({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs font-semibold uppercase tracking-wide text-tertiary">{label}</dt><dd className="mt-1 break-all text-primary">{value}</dd></div> }
