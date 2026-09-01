import { AlertCircle, GitBranch01, Link01, Plus, RefreshCw01 } from '@untitledui/icons'
import { useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { SlideoutMenu } from '../../components/application/slideout-menus/slideout-menu'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { newIdempotencyKey } from '../../lib/api/client'
import type { AssessmentClosureManifest, AssessmentCycleMember, AssessmentLifecycle, AssessmentRelationshipChangeRequest, AssessmentRelationshipPreview } from '../../lib/types'

type Drawer = 'retest' | 'reparent' | 'select_head' | null

export function AssessmentLifecyclePanel({ assessmentId, engagementStatus }: { assessmentId: string; engagementStatus: string }) {
  const meFetch = useFetch(() => api.me().catch(() => null), { deps: [] })
  const lifecycleUIEnabled = meFetch.data?.features?.assessmentLifecycleUIDefault === true
  const lifecycleFetch = useFetch(() => api.assessmentLifecycle(assessmentId), { enabled: lifecycleUIEnabled, deps: [assessmentId, lifecycleUIEnabled] })
  const [drawer, setDrawer] = useState<Drawer>(null)
  const lifecycle = lifecycleFetch.data
  const manifestFetch = useFetch(() => api.listAssessmentClosureManifests(lifecycle?.cycle.id ?? ''), {
    enabled: lifecycleUIEnabled && Boolean(lifecycle?.cycle.activeClosureManifestId), deps: [lifecycleUIEnabled, lifecycle?.cycle.activeClosureManifestId, lifecycle?.cycle.id],
  })
  const current = lifecycle?.members.find((member) => member.assessmentId === assessmentId)

  if (meFetch.loading || !lifecycleUIEnabled) return null
  if (lifecycleFetch.loading && !lifecycle) return <Spinner label="Loading Assessment lifecycle…" />
  if (lifecycleFetch.error) return <ErrorState message={lifecycleFetch.error} />
  if (!lifecycle) return <EmptyState icon={GitBranch01} title="Lifecycle migration pending" hint="This Assessment does not yet have a readable Cycle projection." />

  const role = meFetch.data?.role ?? ''
  const canOperate = ['admin', 'consultant', 'member'].includes(role)
  const canReview = role === 'admin' || role === 'reviewer'
  const canCreateRetest = canOperate && lifecycle.cycle.status === 'open' && engagementStatus === 'completed'
  const selectableHeads = lifecycle.branchHeads.filter((member) => member.assessmentId !== lifecycle.cycle.selectedHeadAssessmentId && !member.archivedAt)
  const activeManifest = manifestFetch.data?.find((manifest) => manifest.lifecycle === 'active') ?? null
  const finalAssessmentId = activeManifest?.finalAssessmentId ?? ''
  return <>
    <Card title="Assessment lifecycle" actions={<div className="flex flex-wrap gap-2">
      <Link to={`/engagements/${encodeURIComponent(assessmentId)}/comparison`}><Button variant="secondary">Compare</Button></Link>
      {canOperate ? <Button disabled={!canCreateRetest} onClick={() => setDrawer('retest')}><Plus className="size-4" />Create Re-test</Button> : null}
      {canReview && current?.assessmentType === 'retest' && !current.archivedAt && lifecycle.cycle.status === 'open' ? <Button variant="secondary" onClick={() => setDrawer('reparent')}><Link01 className="size-4" />More · Change relationship</Button> : null}
      {canReview && selectableHeads.length ? <Button variant="secondary" onClick={() => setDrawer('select_head')}><GitBranch01 className="size-4" />Select Cycle head</Button> : null}
      {canReview && lifecycle.cycle.status === 'completed' ? <Link to={`/assessment-cycles/${encodeURIComponent(lifecycle.cycle.id)}`}><Button variant="secondary"><RefreshCw01 className="size-4" />Review reopen</Button></Link> : null}
    </div>}>
      <nav aria-label="Assessment lifecycle breadcrumb" className="mb-3 flex flex-wrap items-center gap-2 text-xs text-tertiary">
        {boundaryParts(lifecycle).map((part, index) => <span key={part} className="contents">{index ? <span aria-hidden="true">/</span> : null}<span>{part}</span></span>)}
        <span aria-hidden="true">/</span><span>{lifecycle.cycle.name}</span><span aria-hidden="true">/</span><span className="font-mono">{assessmentId}</span>
      </nav>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill>{current?.assessmentType === 'retest' ? `Re-test #${current.retestNumber}` : 'Initial'}</Pill>
        <Pill>{engagementStatus || 'unknown'} Assessment</Pill><Pill>{lifecycle.cycle.status} Cycle</Pill>
        {assessmentId === lifecycle.cycle.selectedHeadAssessmentId ? <Pill className="text-brand-secondary">Selected head</Pill> : null}
        {assessmentId === displayLatest(lifecycle)?.assessmentId ? <span title="Display-only recency; not semantic precedence."><Pill>Display latest</Pill></span> : null}
        {assessmentId === finalAssessmentId ? <Pill className="text-success">Final</Pill> : null}
      </div>
      {!canCreateRetest ? <p className="mt-3 text-xs text-tertiary">Re-test creation requires operate permission and a completed Assessment in an open Cycle. Completed Cycles must be reopened first; authorization is always entered again.</p> : null}
      <LifecycleTree lifecycle={lifecycle} currentAssessmentId={assessmentId} activeManifest={activeManifest} />
    </Card>
    {drawer === 'retest' ? <RetestDrawer lifecycle={lifecycle} assessmentId={assessmentId} onClose={() => setDrawer(null)} onCreated={() => lifecycleFetch.refetch()} /> : null}
    {drawer === 'reparent' && current ? <RelationshipDrawer lifecycle={lifecycle} member={current} command="reparent_within_cycle" onClose={() => setDrawer(null)} onCommitted={() => { setDrawer(null); lifecycleFetch.refetch() }} /> : null}
    {drawer === 'select_head' ? <RelationshipDrawer lifecycle={lifecycle} command="select_head" onClose={() => setDrawer(null)} onCommitted={() => { setDrawer(null); lifecycleFetch.refetch() }} /> : null}
  </>
}

function LifecycleTree({ lifecycle, currentAssessmentId, activeManifest }: { lifecycle: AssessmentLifecycle; currentAssessmentId: string; activeManifest: AssessmentClosureManifest | null }) {
  const children = useMemo(() => {
    const result = new Map<string, AssessmentCycleMember[]>()
    for (const member of lifecycle.members) {
      const key = member.predecessorAssessmentId
      result.set(key, [...(result.get(key) ?? []), member])
    }
    for (const values of result.values()) values.sort((left, right) => left.retestNumber - right.retestNumber || left.assessmentId.localeCompare(right.assessmentId))
    return result
  }, [lifecycle.members])
  const finalPath = new Map(activeManifest?.path.map((member) => [member.assessmentId, member.snapshotId]) ?? [])
  function render(parentId: string, depth: number): ReactNode {
    return (children.get(parentId) ?? []).map((member) => <li key={member.assessmentId} role="treeitem" className="relative">
      <Link to={`/engagements/${encodeURIComponent(member.assessmentId)}`} aria-label={memberLabel(member)} aria-current={member.assessmentId === currentAssessmentId ? 'page' : undefined} className="flex flex-wrap items-center gap-2 rounded-lg border border-secondary px-3 py-2 text-sm hover:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand" style={{ marginLeft: depth * 20 }}>
        <span className="font-semibold text-primary">{member.assessmentType === 'retest' ? `Re-test #${member.retestNumber}` : 'Initial'}</span><span className="font-mono text-xs text-tertiary">{member.assessmentId}</span>
        {member.assessmentId === lifecycle.cycle.selectedHeadAssessmentId ? <Pill className="text-brand-secondary">Selected head</Pill> : null}
        {lifecycle.branchHeads.some((head) => head.assessmentId === member.assessmentId) ? <Pill>Branch head</Pill> : null}
        {member.assessmentId === displayLatest(lifecycle)?.assessmentId ? <Pill>Display latest</Pill> : null}
        {member.assessmentId === activeManifest?.finalAssessmentId ? <Pill className="text-success">Final</Pill> : null}
        {member.archivedAt ? <Pill className="text-warning">Archived</Pill> : null}
        <span className="ml-auto text-xs text-quaternary">{finalPath.get(member.assessmentId) ? `Snapshot ${finalPath.get(member.assessmentId)} · ` : ''}{formatDate(member.createdAt)} · Relationship v{member.relationshipVersion}</span>
      </Link>
      {(children.get(member.assessmentId)?.length ?? 0) > 0 ? <ul role="group" className="mt-2 space-y-2">{render(member.assessmentId, depth + 1)}</ul> : null}
    </li>)
  }
  return <div className="mt-5 border-t border-secondary pt-4"><div className="mb-3 flex items-center justify-between"><h3 className="text-sm font-semibold text-primary">Cycle history</h3><span className="text-xs text-tertiary">{lifecycle.members.length} member(s) · {lifecycle.branchHeads.length} branch head(s)</span></div><ul role="tree" aria-label="Assessment Cycle history" className="space-y-2">{render('', 0)}</ul></div>
}

function boundaryParts(lifecycle: AssessmentLifecycle) {
  const parts: string[] = []
  if (lifecycle.cycle.businessAssetId) parts.push(`Asset ${lifecycle.cycle.businessAssetId}`)
  if (lifecycle.cycle.projectId) parts.push(`Project ${lifecycle.cycle.projectId}`)
  return parts.length ? parts : ['Standalone']
}

function formatDate(value: string) {
  return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(value)) : 'Unknown date'
}

function RetestDrawer({ lifecycle, assessmentId, onClose, onCreated }: { lifecycle: AssessmentLifecycle; assessmentId: string; onClose: () => void; onCreated: () => void }) {
  const navigate = useNavigate()
  const activeMembers = lifecycle.members.filter((member) => !member.archivedAt)
  const [predecessor, setPredecessor] = useState(activeMembers.some((member) => member.assessmentId === assessmentId) ? assessmentId : lifecycle.cycle.selectedHeadAssessmentId)
  const [name, setName] = useState('')
  const [plannedDate, setPlannedDate] = useState('')
  const [scopeStrategy, setScopeStrategy] = useState('copy')
  const [authorizedFrom, setAuthorizedFrom] = useState('')
  const [authorizedTo, setAuthorizedTo] = useState('')
  const [timezone, setTimezone] = useState('UTC')
  const [toolClasses, setToolClasses] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [created, setCreated] = useState<Awaited<ReturnType<typeof api.createRetest>> | null>(null)
  const [idempotencyKey] = useState(newIdempotencyKey)
  async function submit(draft: boolean) {
    setSubmitting(true); setError('')
    try {
      const result = await api.createRetest(assessmentId, {
        name, predecessorAssessmentId: predecessor, scopeStrategy: scopeStrategy as 'copy' | 'empty', profileStrategy: 'none',
        authorizedFrom: draft ? '' : toRFC3339(authorizedFrom), authorizedTo: draft ? '' : toRFC3339(authorizedTo), timezone,
        roe: draft ? undefined : { allowedToolClasses: toolClasses.split(',').map((value) => value.trim()).filter(Boolean), blackouts: [] }, idempotencyKey,
      })
      setCreated(result); onCreated()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Re-test creation failed.') }
    finally { setSubmitting(false) }
  }
  return <SlideoutMenu isOpen onOpenChange={(open) => { if (!open) onClose() }}><SlideoutMenu.Header onClose={onClose}><h2 className="text-lg font-semibold text-primary">Create Re-test</h2><p className="mt-1 text-sm text-tertiary">Cycle and boundary are frozen. Planned date never grants execution authorization.</p></SlideoutMenu.Header><SlideoutMenu.Content>{created ? <div role="status" className="space-y-4"><div className="rounded-lg border border-success/30 bg-success/10 p-4"><p className="font-semibold text-primary">Re-test created</p><p className="mt-1 text-sm text-secondary">Scope: {created.inheritanceDiff.scope} · Authorization: {created.inheritanceDiff.authorization} · RoE: {created.inheritanceDiff.roe} · Scanner profile: {created.inheritanceDiff.scannerProfile}</p></div>{created.warnings.map((warning) => <p key={warning} className="flex gap-2 text-sm text-warning"><AlertCircle className="size-4 shrink-0" aria-hidden="true" />{labelize(warning)}</p>)}<Button onClick={() => navigate(`/engagements/${encodeURIComponent(created.engagement.id)}`)}>Open Re-test</Button></div> : <div className="space-y-4"><div className="rounded-lg bg-secondary p-3 text-sm text-secondary">{lifecycle.cycle.boundaryKind} boundary · Cycle {lifecycle.cycle.id} · Type Re-test</div><Field label="Based on Assessment"><Select ariaLabel="Based on Assessment" value={predecessor} onValueChange={setPredecessor} options={activeMembers.map((member) => ({ value: member.assessmentId, label: member.assessmentType === 'retest' ? `Re-test #${member.retestNumber} · ${member.assessmentId}` : `Initial · ${member.assessmentId}` }))} className="w-full" /></Field><Field label="Name"><Input aria-label="Name" value={name} onChange={(event) => setName(event.target.value)} placeholder="Optional server-derived name" /></Field><Field label="Planned date" hint="Planning only; not execution authorization."><Input aria-label="Planned date" type="date" value={plannedDate} onChange={(event) => setPlannedDate(event.target.value)} /></Field><Field label="Scope strategy"><Select ariaLabel="Scope strategy" value={scopeStrategy} onValueChange={setScopeStrategy} options={[{ value: 'copy', label: 'Copy frozen scope' }, { value: 'empty', label: 'Start with empty scope' }]} className="w-full" /></Field><div className="grid gap-3 sm:grid-cols-2"><Field label="Authorized from"><Input aria-label="Authorized from" type="datetime-local" value={authorizedFrom} onChange={(event) => setAuthorizedFrom(event.target.value)} /></Field><Field label="Authorized to"><Input aria-label="Authorized to" type="datetime-local" value={authorizedTo} onChange={(event) => setAuthorizedTo(event.target.value)} /></Field></div><Field label="Timezone"><Input aria-label="Timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} /></Field><Field label="Allowed tool classes"><Input aria-label="Allowed tool classes" value={toolClasses} onChange={(event) => setToolClasses(event.target.value)} placeholder="sca, sast" /></Field>{error ? <ErrorState message={error} /> : null}<div className="flex flex-wrap gap-3"><Button loading={submitting} onClick={() => submit(false)}>Create with authorization</Button><Button variant="secondary" loading={submitting} onClick={() => submit(true)}>Save non-executable draft</Button></div></div>}</SlideoutMenu.Content></SlideoutMenu>
}

function RelationshipDrawer({ lifecycle, member, command, onClose, onCommitted }: { lifecycle: AssessmentLifecycle; member?: AssessmentCycleMember; command: 'reparent_within_cycle' | 'select_head'; onClose: () => void; onCommitted: () => void }) {
  const options = command === 'reparent_within_cycle'
    ? lifecycle.members.filter((value) => !value.archivedAt && value.assessmentId !== member?.assessmentId).map((value) => ({ value: value.assessmentId, label: memberLabel(value) }))
    : lifecycle.branchHeads.filter((value) => !value.archivedAt && value.assessmentId !== lifecycle.cycle.selectedHeadAssessmentId).map((value) => ({ value: value.assessmentId, label: memberLabel(value) }))
  const [target, setTarget] = useState(options[0]?.value ?? '')
  const [preview, setPreview] = useState<AssessmentRelationshipPreview | null>(null)
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [idempotencyKey, setIdempotencyKey] = useState('')
  const change: AssessmentRelationshipChangeRequest = command === 'reparent_within_cycle'
    ? { command, assessmentId: member?.assessmentId, newPredecessorAssessmentId: target }
    : { command, selectedHeadAssessmentId: target }
  async function loadPreview() {
    if (!target) return
    setLoading(true); setError('')
    try { setPreview(await api.previewAssessmentRelationshipChange(lifecycle.cycle.id, change)); setIdempotencyKey(newIdempotencyKey()) }
    catch (cause) { setError(cause instanceof ApiError && cause.status === 403 ? 'Review permission is required.' : cause instanceof Error ? cause.message : 'Preview failed.') }
    finally { setLoading(false) }
  }
  async function commit() {
    if (!preview?.commitAllowed || !preview.previewToken || preview.reasonRequired && !reason.trim()) return
    setLoading(true); setError('')
    try { await api.commitAssessmentRelationshipChange(lifecycle.cycle.id, preview.cycleVersion, change, preview.previewToken, reason.trim(), idempotencyKey); onCommitted() }
    catch (cause) { setError(cause instanceof ApiError && cause.status === 409 ? 'Preview is stale, expired, or already used. Refresh the authoritative preview; your selection and reason are preserved.' : cause instanceof Error ? cause.message : 'Commit failed.') }
    finally { setLoading(false) }
  }
  return <SlideoutMenu isOpen onOpenChange={(open) => { if (!open) onClose() }}><SlideoutMenu.Header onClose={onClose}><h2 className="text-lg font-semibold text-primary">{command === 'reparent_within_cycle' ? 'Change relationship' : 'Select Cycle head'}</h2><p className="mt-1 text-sm text-tertiary">Only supported same-Cycle commands are exposed. Raw scans and evidence are never deleted.</p></SlideoutMenu.Header><SlideoutMenu.Content><div className="space-y-4"><Field label={command === 'reparent_within_cycle' ? 'New predecessor' : 'Eligible branch head'}><Select ariaLabel="Relationship target" value={target} onValueChange={(value) => { setTarget(value); setPreview(null) }} options={options} className="w-full" /></Field><Button variant="secondary" loading={loading} disabled={!target} onClick={loadPreview}><RefreshCw01 className="size-4" aria-hidden="true" />Preview server impact</Button>{preview ? <div role="status" aria-live="polite" className="space-y-3 rounded-lg border border-secondary p-4 text-sm"><p><strong>Selected head:</strong> {preview.oldSelectedHeadAssessmentId} → {preview.newSelectedHeadAssessmentId}</p>{command === 'reparent_within_cycle' ? <p><strong>Predecessor:</strong> {preview.oldPredecessorAssessmentId} → {preview.newPredecessorAssessmentId}</p> : null}<p><strong>Descendants:</strong> {preview.descendantAssessmentIds.join(', ') || 'None'}</p><p><strong>Impacted:</strong> {preview.impact.memberIds.length} members · {preview.impact.snapshotIds.length} snapshots · {preview.impact.identityIds.length} identities · {preview.impact.comparisonIds.length} comparisons · {preview.impact.projectionIds.length} projections</p>{preview.locks.length ? <div className="rounded-lg bg-warning/10 p-3 text-warning"><strong>Commit locked:</strong> {preview.locks.map(labelize).join(', ')}</div> : <p className="text-success">No server lock is active.</p>}<p className="font-mono text-xs text-tertiary">Preview v{preview.cycleVersion} · expires {preview.expiresAt || 'not issued'}</p></div> : null}{preview?.reasonRequired ? <Field label="Reason"><Input aria-label="Reason" value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} /></Field> : null}{error ? <ErrorState message={error} /> : null}<Button loading={loading} disabled={!preview?.commitAllowed || !preview.previewToken || Boolean(preview.reasonRequired && !reason.trim())} onClick={commit}>Commit authoritative preview</Button></div></SlideoutMenu.Content></SlideoutMenu>
}

function displayLatest(lifecycle: AssessmentLifecycle) { return [...lifecycle.members].filter((member) => !member.archivedAt).sort((left, right) => right.retestNumber - left.retestNumber || right.assessmentId.localeCompare(left.assessmentId))[0] }
function memberLabel(member: AssessmentCycleMember) { return member.assessmentType === 'retest' ? `Re-test #${member.retestNumber} · ${member.assessmentId}` : `Initial · ${member.assessmentId}` }
function labelize(value: string) { return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()) }
function toRFC3339(value: string) { return value ? new Date(value).toISOString() : '' }
