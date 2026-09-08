import { AlertCircle, ChevronDown, GitBranch01, InfoCircle, Link01, Plus, RefreshCw01 } from '@untitledui/icons'
import { useId, useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { SlideoutMenu } from '../../components/application/slideout-menus/slideout-menu'
import { styles as buttonStyles } from '../../components/base/buttons/button'
import { Tooltip, TooltipTrigger } from '../../components/base/tooltip/tooltip'
import { Button, Card, cn, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { newIdempotencyKey } from '../../lib/api/client'
import type { AssessmentClosureManifest, AssessmentCycleMember, AssessmentLifecycle, AssessmentRelationshipChangeRequest, AssessmentRelationshipPreview } from '../../lib/types'

type Drawer = 'retest' | 'reparent' | 'select_head' | null
const RETEST_REQUIREMENTS = 'Re-test creation requires operate permission and a completed Assessment in an open Cycle. Completed Cycles must be reopened first; authorization is always entered again.'
const actionLinkClass = cn(buttonStyles.common.root, buttonStyles.sizes.sm.root, buttonStyles.colors.secondary.root)

export function AssessmentLifecyclePanel({ assessmentId, engagementStatus }: { assessmentId: string; engagementStatus: string }) {
  const meFetch = useFetch(() => api.me().catch(() => null), { deps: [] })
  const lifecycleUIEnabled = meFetch.data?.features?.assessmentLifecycleUIDefault === true
  const lifecycleFetch = useFetch(() => api.assessmentLifecycle(assessmentId), { enabled: lifecycleUIEnabled, deps: [assessmentId, lifecycleUIEnabled, engagementStatus] })
  const [drawer, setDrawer] = useState<Drawer>(null)
  const [expandedAssessmentId, setExpandedAssessmentId] = useState<string | null>(null)
  const detailsId = useId()
  const detailsExpanded = expandedAssessmentId === assessmentId
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
  const canCreateRetest = canOperate && !lifecycleFetch.loading && lifecycle.cycle.status === 'open' && engagementStatus === 'completed'
  const selectableHeads = lifecycle.branchHeads.filter((member) => member.assessmentId !== lifecycle.cycle.selectedHeadAssessmentId && !member.archivedAt)
  const activeManifest = manifestFetch.data?.find((manifest) => manifest.lifecycle === 'active') ?? null
  const finalAssessmentId = activeManifest?.finalAssessmentId ?? ''
  return <>
    <Card bodyClass="p-0">
      <div className="space-y-2 px-4 py-3 sm:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-primary">
              <GitBranch01 className="size-4 text-fg-brand-primary" aria-hidden="true" />Assessment lifecycle
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <Pill>{current?.assessmentType === 'retest' ? `Re-test #${current.retestNumber}` : 'Initial'}</Pill>
              <span className="text-xs capitalize text-tertiary">{engagementStatus || 'unknown'} Assessment</span>
              <span aria-hidden="true" className="text-quaternary">·</span>
              <span className="text-xs capitalize text-secondary">{lifecycle.cycle.status} Cycle</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link to={`/engagements/${encodeURIComponent(assessmentId)}/comparison`} className={actionLinkClass}>Compare</Link>
            {canOperate ? <Button disabled={!canCreateRetest} aria-describedby={!canCreateRetest ? `${detailsId}-eligibility` : undefined} onClick={() => setDrawer('retest')}>
              <Plus className="size-4" aria-hidden="true" />Create Re-test
            </Button> : null}
            {!canCreateRetest ? <Tooltip title="Re-test requirements" description={RETEST_REQUIREMENTS} placement="bottom end">
              <TooltipTrigger aria-label="Re-test requirements" onPress={() => setExpandedAssessmentId(assessmentId)} className="flex items-center justify-center rounded-lg p-2 text-tertiary hover:bg-secondary hover:text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"><InfoCircle className="size-4" aria-hidden="true" /></TooltipTrigger>
            </Tooltip> : null}
            {canReview && lifecycle.cycle.status === 'completed' ? <Link to={`/assessment-cycles/${encodeURIComponent(lifecycle.cycle.id)}`} className={actionLinkClass}><RefreshCw01 className="size-4" aria-hidden="true" />Review reopen</Link> : null}
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
            <Link to={`/assessment-cycles/${encodeURIComponent(lifecycle.cycle.id)}`} className="max-w-full break-all rounded font-medium text-secondary hover:text-brand-secondary hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand">{lifecycle.cycle.name}</Link>
            {assessmentId === lifecycle.cycle.selectedHeadAssessmentId ? <span className="inline-flex items-center gap-1.5 font-medium text-brand-secondary"><span aria-hidden="true" className="size-1.5 rounded-full bg-brand-solid" />Selected head</span> : null}
            {assessmentId === displayLatest(lifecycle)?.assessmentId ? <span className="text-tertiary" title="Display-only recency; not semantic precedence.">Display latest</span> : null}
            {assessmentId === finalAssessmentId ? <Pill className="text-success">Final</Pill> : null}
          </div>
          <button type="button" aria-expanded={detailsExpanded} aria-controls={detailsId} onClick={() => setExpandedAssessmentId(detailsExpanded ? null : assessmentId)} className="flex min-h-8 flex-wrap items-center gap-x-3 gap-y-1 rounded-lg text-xs text-tertiary hover:text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand">
            <span className="tabular-nums">{lifecycle.members.length} {lifecycle.members.length === 1 ? 'member' : 'members'} · {lifecycle.branchHeads.length} {lifecycle.branchHeads.length === 1 ? 'branch head' : 'branch heads'}</span>
            <span className="flex items-center gap-1.5 font-semibold text-secondary">Details &amp; history<ChevronDown className={cn('size-4 transition-transform motion-reduce:transition-none', detailsExpanded && 'rotate-180')} aria-hidden="true" /></span>
          </button>
        </div>
        {!canCreateRetest ? <p id={`${detailsId}-eligibility`} className="sr-only">{RETEST_REQUIREMENTS} Open Details &amp; history for more information.</p> : null}
      </div>
      <div id={detailsId} hidden={!detailsExpanded} className="space-y-4 border-t border-secondary px-4 py-4 sm:px-5">
        <nav aria-label="Assessment lifecycle breadcrumb" className="flex flex-wrap items-center gap-2 text-xs text-tertiary">
          {boundaryParts(lifecycle).map((part, index) => <span key={part} className="contents">{index ? <span aria-hidden="true">/</span> : null}<span className="break-all">{part}</span></span>)}
          <span aria-hidden="true">/</span><span className="break-all">{lifecycle.cycle.name}</span><span aria-hidden="true">/</span><span className="break-all font-mono">{assessmentId}</span>
        </nav>
        {!canCreateRetest ? <p className="flex items-start gap-2 text-xs leading-relaxed text-tertiary"><AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><span>{RETEST_REQUIREMENTS}</span></p> : null}
        <LifecycleTree lifecycle={lifecycle} currentAssessmentId={assessmentId} activeManifest={activeManifest} />
        {canReview && ((current?.assessmentType === 'retest' && !current.archivedAt && lifecycle.cycle.status === 'open') || selectableHeads.length > 0) ? <div className="flex flex-wrap gap-2 border-t border-secondary pt-3">
          {current?.assessmentType === 'retest' && !current.archivedAt && lifecycle.cycle.status === 'open' ? <Button variant="secondary" onClick={() => setDrawer('reparent')}><Link01 className="size-4" aria-hidden="true" />Change relationship</Button> : null}
          {selectableHeads.length ? <Button variant="secondary" onClick={() => setDrawer('select_head')}><GitBranch01 className="size-4" aria-hidden="true" />Select Cycle head</Button> : null}
        </div> : null}
      </div>
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
    return (children.get(parentId) ?? []).map((member) => <li key={member.assessmentId} className="relative">
      <Link to={`/engagements/${encodeURIComponent(member.assessmentId)}`} aria-label={memberLabel(member)} aria-current={member.assessmentId === currentAssessmentId ? 'page' : undefined} className={cn('flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg px-3 py-2 text-sm hover:bg-secondary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand', member.assessmentId === currentAssessmentId && 'bg-secondary')} style={{ marginLeft: Math.min(depth, 4) * 12 }}>
        <span className="font-semibold text-primary">{member.assessmentType === 'retest' ? `Re-test #${member.retestNumber}` : 'Initial'}</span><span className="break-all font-mono text-xs text-tertiary">{member.assessmentId}</span>
        {member.assessmentId === lifecycle.cycle.selectedHeadAssessmentId ? <Pill className="text-brand-secondary">Selected head</Pill> : null}
        {lifecycle.branchHeads.some((head) => head.assessmentId === member.assessmentId) ? <Pill>Branch head</Pill> : null}
        {member.assessmentId === displayLatest(lifecycle)?.assessmentId ? <Pill>Display latest</Pill> : null}
        {member.assessmentId === activeManifest?.finalAssessmentId ? <Pill className="text-success">Final</Pill> : null}
        {member.archivedAt ? <Pill className="text-warning">Archived</Pill> : null}
        {member.plannedDate ? <Pill>Planned {member.plannedDate}</Pill> : null}
        <span className="ml-auto break-all text-xs text-tertiary">{finalPath.get(member.assessmentId) ? `Snapshot ${finalPath.get(member.assessmentId)} · ` : ''}{formatDate(member.createdAt)} · Relationship v{member.relationshipVersion}</span>
      </Link>
      {(children.get(member.assessmentId)?.length ?? 0) > 0 ? <ul role="list" className="mt-1 space-y-1">{render(member.assessmentId, depth + 1)}</ul> : null}
    </li>)
  }
  return <div><h3 className="mb-2 text-xs font-semibold text-secondary">Cycle history</h3><ul role="list" aria-label="Assessment Cycle history" className="space-y-1">{render('', 0)}</ul></div>
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
  const activeMembers = lifecycle.members.filter((member) => !member.archivedAt && member.assessmentStatus === 'completed')
  const [predecessor, setPredecessor] = useState(activeMembers.some((member) => member.assessmentId === assessmentId) ? assessmentId : activeMembers[0]?.assessmentId ?? '')
  const [name, setName] = useState('')
  const [plannedDate, setPlannedDate] = useState('')
  const [source, setSource] = useState<File | undefined>()
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
    if (submitting || created) return
    if (source && (!/\.(zip|tar|tar\.gz|tgz)$/i.test(source.name) || source.size === 0 || source.size > 512 * 1024 * 1024)) { setError('Choose a non-empty ZIP or TAR source archive up to 512 MiB.'); return }
    if (!predecessor) { setError('Choose a completed predecessor Assessment.'); return }
    if (!draft && (!authorizedFrom || !authorizedTo || !toolClasses.trim())) { setError('Enter a separate authorization window and allowed tool classes, or save a non-executable draft.'); return }
    setSubmitting(true); setError('')
    try {
      const result = await api.createRetest(predecessor, {
        name, plannedDate, source, predecessorAssessmentId: predecessor, scopeStrategy: scopeStrategy as 'copy' | 'empty', profileStrategy: 'none',
        authorizedFrom: draft ? '' : toRFC3339(authorizedFrom), authorizedTo: draft ? '' : toRFC3339(authorizedTo), timezone,
        roe: draft ? undefined : { allowedToolClasses: toolClasses.split(',').map((value) => value.trim()).filter(Boolean), blackouts: [] }, idempotencyKey,
      })
      setCreated(result); onCreated()
    } catch (cause) { setError(cause instanceof Error && cause.message.includes('source_package_required_for_retest') ? 'This Assessment uses an uploaded source archive. Choose the source revision to evaluate in this Re-test.' : cause instanceof Error ? cause.message : 'Re-test creation failed.') }
    finally { setSubmitting(false) }
  }
  return <SlideoutMenu isOpen onOpenChange={(open) => { if (!open) onClose() }}><SlideoutMenu.Header onClose={onClose}><h2 className="text-lg font-semibold text-primary">Create Re-test</h2><p className="mt-1 text-sm text-tertiary">Cycle and boundary are frozen. Planned date never grants execution authorization.</p></SlideoutMenu.Header><SlideoutMenu.Content>{created ? <div role="status" className="space-y-4"><div className="rounded-lg border border-success/30 bg-success/10 p-4"><p className="font-semibold text-primary">Re-test created</p><p className="mt-1 text-sm text-secondary">{created.member.plannedDate ? `Planned: ${created.member.plannedDate} · ` : ''}Scope: {created.inheritanceDiff.scope} · Authorization: {created.inheritanceDiff.authorization} · RoE: {created.inheritanceDiff.roe} · Scanner profile: {created.inheritanceDiff.scannerProfile}</p></div>{created.warnings.map((warning) => <p key={warning} className="flex gap-2 text-sm text-warning"><AlertCircle className="size-4 shrink-0" aria-hidden="true" />{labelize(warning)}</p>)}<Button onClick={() => navigate(`/engagements/${encodeURIComponent(created.engagement.id)}`)}>Open Re-test</Button></div> : <div className="space-y-4"><div className="rounded-lg bg-secondary p-3 text-sm text-secondary">{lifecycle.cycle.boundaryKind} boundary · Cycle {lifecycle.cycle.id} · Type Re-test</div><Field label="Based on Assessment"><Select ariaLabel="Based on Assessment" value={predecessor} onValueChange={setPredecessor} options={activeMembers.map((member) => ({ value: member.assessmentId, label: member.assessmentType === 'retest' ? `Re-test #${member.retestNumber} · ${member.assessmentId}` : `Initial · ${member.assessmentId}` }))} className="w-full" /></Field><Field label="Name"><Input aria-label="Name" value={name} onChange={(event) => setName(event.target.value)} placeholder="Optional server-derived name" /></Field><Field label="Source archive" hint="Required when copying an uploaded-source scope. Choose the revision to evaluate; the previous archive is never silently reused."><Input aria-label="Re-test source archive" type="file" accept=".zip,.tar,.tar.gz,.tgz" onChange={(event) => setSource(event.target.files?.[0])} /></Field><Field label="Planned date" hint="Planning only; not execution authorization."><Input aria-label="Planned date" type="date" value={plannedDate} onChange={(event) => setPlannedDate(event.target.value)} /></Field><Field label="Scope strategy"><Select ariaLabel="Scope strategy" value={scopeStrategy} onValueChange={setScopeStrategy} options={[{ value: 'copy', label: 'Copy frozen scope' }, { value: 'empty', label: 'Start with empty scope' }]} className="w-full" /></Field><div className="grid gap-3 sm:grid-cols-2"><Field label="Authorized from"><Input aria-label="Authorized from" type="datetime-local" value={authorizedFrom} onChange={(event) => setAuthorizedFrom(event.target.value)} /></Field><Field label="Authorized to"><Input aria-label="Authorized to" type="datetime-local" value={authorizedTo} onChange={(event) => setAuthorizedTo(event.target.value)} /></Field></div><Field label="Timezone"><Input aria-label="Timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} /></Field><Field label="Allowed tool classes"><Input aria-label="Allowed tool classes" value={toolClasses} onChange={(event) => setToolClasses(event.target.value)} placeholder="sca, sast" /></Field>{error ? <ErrorState message={error} /> : null}<div className="flex flex-wrap gap-3"><Button loading={submitting} onClick={() => submit(false)}>Create with authorization</Button><Button variant="secondary" loading={submitting} onClick={() => submit(true)}>Save non-executable draft</Button></div></div>}</SlideoutMenu.Content></SlideoutMenu>
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
