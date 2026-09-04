import { AlertTriangle, ArrowLeft, CheckCircle, Download01, Lock01, RefreshCw01, XClose } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Dialog, Modal, ModalOverlay } from '../../components/application/modals/modal'
import { Button, Card, EmptyState, ErrorState, Field, Pill, Spinner } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { newIdempotencyKey } from '../../lib/api/client'
import type {
  AssessmentClosureBlocker,
  AssessmentClosureManifest,
  AssessmentClosurePreview,
  AssessmentClosurePreviewInput,
  AssessmentCycleDetail,
  AssessmentReopenPreview,
} from '../../lib/types'

type CycleDetailData = [AssessmentCycleDetail, AssessmentClosureManifest[], { role: string }]

export function AssessmentCycleDetailPage() {
  const { cycleId = '' } = useParams()
  const result = useParallelFetch<CycleDetailData>(() => Promise.all([
    api.assessmentCycle(cycleId), api.listAssessmentClosureManifests(cycleId), api.me(),
  ]), { enabled: Boolean(cycleId), deps: [cycleId] })
  const [dialog, setDialog] = useState<'close' | 'reopen' | null>(null)
  const [downloadError, setDownloadError] = useState('')
  const [downloading, setDownloading] = useState('')

  if (result.loading && !result.data) return <Spinner label="Loading Assessment Cycle…" />
  if (result.error) return <ErrorState message={result.error} />
  if (!result.data) return <EmptyState icon={Lock01} title="Assessment Cycle not found" />

  const [detail, manifests, me] = result.data
  const cycle = detail.cycle
  const activeManifest = manifests.find((manifest) => manifest.lifecycle === 'active') ?? null
  const superseded = manifests.filter((manifest) => manifest.lifecycle === 'superseded')
  const canReview = me.role === 'admin' || me.role === 'reviewer'

  async function download(manifest: AssessmentClosureManifest) {
    setDownloading(manifest.id)
    setDownloadError('')
    try {
      await api.downloadAssessmentClosureReport(cycle.id, manifest.id)
    } catch (cause) {
      setDownloadError(cause instanceof Error ? cause.message : 'Report download failed.')
    } finally {
      setDownloading('')
    }
  }

  return <div className="mx-auto max-w-[1400px] animate-fade-in space-y-6">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <Link to="/assessment-cycles" className="inline-flex items-center gap-2 text-sm font-semibold text-brand-secondary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"><ArrowLeft className="size-4" />Assessment Cycles</Link>
        <div className="mt-3 flex flex-wrap items-center gap-2"><h1 className="text-2xl font-bold tracking-tight text-primary">{cycle.name}</h1><Pill>{cycle.status} Cycle</Pill>{activeManifest ? <Pill className="text-success">Closure v{activeManifest.manifestVersion}</Pill> : null}</div>
        <p className="mt-1 font-mono text-xs text-tertiary">{cycle.id}</p>
        <p className="mt-2 text-sm text-tertiary">Final Assessment <strong className="text-primary">{activeManifest?.finalAssessmentId || cycle.selectedHeadAssessmentId}</strong> · Cycle version {cycle.version}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" onClick={result.refetch}><RefreshCw01 className="size-4" />Refresh</Button>
        {canReview && cycle.status === 'open' ? <Button onClick={() => setDialog('close')}><Lock01 className="size-4" />Review closure</Button> : null}
        {canReview && cycle.status === 'completed' && activeManifest ? <Button variant="secondary-color" onClick={() => setDialog('reopen')}><RefreshCw01 className="size-4" />Review reopen</Button> : null}
      </div>
    </header>

    {!canReview ? <p className="rounded-lg border border-secondary bg-primary px-4 py-3 text-sm text-tertiary">Review permission is required to close or reopen a Cycle.</p> : null}

    <Card title="Final state">
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Detail label="Root Assessment" value={activeManifest?.rootAssessmentId || cycle.rootAssessmentId} />
        <Detail label="Selected / final Assessment" value={activeManifest?.finalAssessmentId || cycle.selectedHeadAssessmentId} />
        <Detail label="Final Snapshot" value={activeManifest?.finalSnapshotId || 'Not closed'} />
        <Detail label="Final Comparison" value={activeManifest?.comparisonId || 'Not closed'} />
      </dl>
      {activeManifest ? <PathList manifest={activeManifest} /> : <p className="mt-5 text-sm text-tertiary">The Cycle remains open. Closure uses a server-authoritative preview and immutable root-to-final references.</p>}
    </Card>

    <Card title="Closure history" actions={<Pill>{manifests.length} manifests</Pill>}>
      {downloadError ? <ErrorState className="mb-4" message={downloadError} /> : null}
      {manifests.length ? <ul className="space-y-3">{manifests.map((manifest) => <li key={manifest.id} className="rounded-lg border border-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3"><div><div className="flex flex-wrap items-center gap-2"><strong className="text-sm text-primary">Closure v{manifest.manifestVersion}</strong><Pill className={manifest.lifecycle === 'active' ? 'text-success' : 'text-warning'}>{manifest.lifecycle}</Pill></div><p className="mt-1 font-mono text-xs text-tertiary">{manifest.id}</p></div><Button variant="secondary" loading={downloading === manifest.id} onClick={() => download(manifest)}><Download01 className="size-4" />Download report</Button></div>
        <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4"><Detail label="Manifest hash" value={shortHash(manifest.contentHash)} mono /><Detail label="Renderer" value={manifest.rendererContractVersion} /><Detail label="Generated" value={formatDateTime(manifest.sealedAt)} /><Detail label="Final Assessment" value={manifest.finalAssessmentId} /></dl>
        {manifest.lifecycle === 'superseded' ? <p className="mt-3 rounded-md bg-warning/10 px-3 py-2 text-xs text-warning">Superseded {formatDateTime(manifest.supersededAt)}. The manifest and downloaded report remain immutable.</p> : null}
      </li>)}</ul> : <EmptyState icon={Lock01} title="No closure manifests" hint="A sealed manifest appears after a successful closure commit." />}
      {superseded.length ? <p className="mt-4 text-xs text-tertiary">{superseded.length} prior closure{(superseded.length === 1) ? '' : 's'} remain available for audit and report download.</p> : null}
    </Card>

    {dialog === 'close' ? <ClosureDialog cycleId={cycle.id} onClose={() => setDialog(null)} onCommitted={() => { setDialog(null); result.refetch() }} /> : null}
    {dialog === 'reopen' && activeManifest ? <ReopenDialog cycleId={cycle.id} manifest={activeManifest} onClose={() => setDialog(null)} onCommitted={() => { setDialog(null); result.refetch() }} /> : null}
  </div>
}

function ClosureDialog({ cycleId, onClose, onCommitted }: { cycleId: string; onClose: () => void; onCommitted: () => void }) {
  const [input, setInput] = useState<AssessmentClosurePreviewInput>({ reason: '', overrideBlockerIds: [], overrideReason: '' })
  const [preview, setPreview] = useState<AssessmentClosurePreview | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [conflict, setConflict] = useState(false)
  const [idempotencyKey, setIdempotencyKey] = useState(() => newIdempotencyKey())

  function change(next: Partial<AssessmentClosurePreviewInput>) {
    setInput((current) => ({ ...current, ...next }))
    setPreview(null)
    setConflict(false)
    setError('')
  }

  async function loadPreview() {
    setLoading(true)
    setError('')
    setConflict(false)
    try {
      const value = await api.previewAssessmentClosure(cycleId, input)
      setPreview(value)
      setIdempotencyKey(newIdempotencyKey())
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Closure preview failed.')
    } finally {
      setLoading(false)
    }
  }

  async function commit() {
    if (!preview?.previewToken) return
    setLoading(true)
    setError('')
    try {
      await api.commitAssessmentClosure(cycleId, preview.cycleVersion, input, preview.previewToken, idempotencyKey)
      onCommitted()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 409) {
        setConflict(true)
        setPreview(null)
        setIdempotencyKey(newIdempotencyKey())
      } else {
        setError(cause instanceof Error ? cause.message : 'Closure commit failed.')
      }
    } finally {
      setLoading(false)
    }
  }

  const unknownCoverage = preview ? [...preview.policy.coverageDecisions.initial, ...preview.policy.coverageDecisions.final].filter((decision) => decision.state !== 'complete' && !decision.waived) : []
  const canCommit = Boolean(preview?.policy.commitAllowed && preview.previewToken && input.reason.trim())
  return <WorkflowModal title="Review Cycle closure" onClose={onClose} loading={loading}>
    <Field label="Closure reason" hint="Required and stored in the immutable manifest."><textarea aria-label="Closure reason" maxLength={4096} value={input.reason} disabled={loading} onChange={(event) => change({ reason: event.target.value })} className={textareaClass} /></Field>
    {preview ? <div className="space-y-4" aria-live="polite">
      <div className="rounded-lg border border-secondary bg-secondary/30 p-4 text-sm"><p><strong>Selected final:</strong> {preview.finalAssessmentId}</p><p><strong>Immutable pair:</strong> {preview.initialSnapshotId || 'missing'} → {preview.finalSnapshotId || 'missing'}</p><p><strong>Comparison:</strong> {preview.comparisonId || 'missing'} · renderer {preview.rendererContractVersion}</p><p className="mt-2 font-mono text-xs text-tertiary">Preview Cycle v{preview.cycleVersion} · expires {formatDateTime(preview.expiresAt)}</p></div>
      <PathList preview={preview} />
      <PolicyPanel preview={preview} unknownCoverage={unknownCoverage} input={input} onChange={change} disabled={loading} />
      <ReferencePanel preview={preview} />
    </div> : <p className="text-sm text-tertiary">Preview the server policy after every reason or override change. No client-side state can authorize closure.</p>}
    {conflict ? <ErrorState message="Another operator changed, closed, reopened, or consumed this preview. Refresh the Cycle, review a new preview, and submit again." /> : null}
    {error ? <ErrorState message={error} /> : null}
    <div className="flex flex-wrap justify-end gap-2"><Button variant="secondary" disabled={loading} onClick={loadPreview}>Preview server policy</Button><Button loading={loading} disabled={!canCommit} onClick={commit}>Close from authoritative preview</Button></div>
  </WorkflowModal>
}

function ReopenDialog({ cycleId, manifest, onClose, onCommitted }: { cycleId: string; manifest: AssessmentClosureManifest; onClose: () => void; onCommitted: () => void }) {
  const [preview, setPreview] = useState<AssessmentReopenPreview | null>(null)
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [conflict, setConflict] = useState(false)
  const [idempotencyKey, setIdempotencyKey] = useState(() => newIdempotencyKey())

  useEffect(() => {
    let active = true
    api.previewAssessmentReopen(cycleId).then((value) => { if (active) { setPreview(value); setIdempotencyKey(newIdempotencyKey()) } }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : 'Reopen preview failed.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [cycleId])

  async function commit() {
    if (!preview?.previewToken || !reason.trim()) return
    setLoading(true)
    setError('')
    try {
      await api.commitAssessmentReopen(cycleId, preview.cycleVersion, preview.previewToken, reason.trim(), idempotencyKey)
      onCommitted()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 409) {
        setConflict(true)
        setPreview(null)
        setIdempotencyKey(newIdempotencyKey())
      } else {
        setError(cause instanceof Error ? cause.message : 'Reopen commit failed.')
      }
    } finally {
      setLoading(false)
    }
  }

  return <WorkflowModal title="Review Cycle reopen" onClose={onClose} loading={loading}>
    <div className="rounded-lg border border-warning/30 bg-warning/10 p-4 text-sm text-warning"><p className="font-semibold">Closure v{manifest.manifestVersion} remains immutable.</p><p className="mt-1">Manifest {shortHash(manifest.contentHash)} and its report stay downloadable; the Cycle returns to open for additional work.</p></div>
    {preview ? <div className="rounded-lg border border-secondary p-4 text-sm"><p>{preview.impact}</p><p className="mt-2 font-mono text-xs text-tertiary">Preview Cycle v{preview.cycleVersion} · expires {formatDateTime(preview.expiresAt)}</p></div> : null}
    <Field label="Reopen reason" hint="Required for the audit record."><textarea aria-label="Reopen reason" maxLength={4096} value={reason} disabled={loading} onChange={(event) => setReason(event.target.value)} className={textareaClass} /></Field>
    {conflict ? <ErrorState message="Another operator changed or reopened this Cycle. Refresh and review the current immutable manifest before retrying." /> : null}
    {error ? <ErrorState message={error} /> : null}
    <div className="flex justify-end"><Button loading={loading} disabled={!preview?.previewToken || !reason.trim()} onClick={commit}>Reopen from authoritative preview</Button></div>
  </WorkflowModal>
}

function WorkflowModal({ title, onClose, loading, children }: { title: string; onClose: () => void; loading: boolean; children: React.ReactNode }) {
  return <ModalOverlay isOpen isDismissable={!loading} onOpenChange={(open) => { if (!open && !loading) onClose() }}><Modal className="w-full max-w-3xl"><Dialog aria-label={title}>
    <div className="flex items-start justify-between gap-3 border-b border-secondary px-6 py-4"><div><h2 className="text-lg font-semibold text-primary">{title}</h2><p className="mt-1 text-sm text-tertiary">Signed previews expire and are single-use.</p></div><button type="button" aria-label="Close dialog" disabled={loading} onClick={onClose} className="rounded-lg p-2 text-tertiary hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand disabled:opacity-50"><XClose className="size-5" /></button></div>
    <div className="space-y-5 p-6">{children}</div>
  </Dialog></Modal></ModalOverlay>
}

function PolicyPanel({ preview, unknownCoverage, input, onChange, disabled }: { preview: AssessmentClosurePreview; unknownCoverage: AssessmentClosurePreview['policy']['coverageDecisions']['initial']; input: AssessmentClosurePreviewInput; onChange: (next: Partial<AssessmentClosurePreviewInput>) => void; disabled: boolean }) {
  const blockers = preview.policy.blockers
  return <section aria-labelledby="closure-policy-title" className="space-y-3"><div className="flex flex-wrap items-center gap-2"><h3 id="closure-policy-title" className="text-sm font-semibold text-primary">Closure policy</h3><Pill className={preview.policy.commitAllowed ? 'text-success' : 'text-critical'}>{preview.policy.commitAllowed ? 'Commit allowed' : 'Blocked'}</Pill></div>
    {blockers.length ? <ul className="space-y-2">{blockers.map((blocker) => <BlockerRow key={blocker.id} blocker={blocker} selected={input.overrideBlockerIds.includes(blocker.id)} disabled={disabled} onToggle={() => onChange({ overrideBlockerIds: toggle(input.overrideBlockerIds, blocker.id) })} />)}</ul> : <p className="flex items-center gap-2 text-sm text-success"><CheckCircle className="size-4" />No policy blocker is active.</p>}
    {unknownCoverage.length ? <div role="alert" className="rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-critical"><strong>Coverage is not complete.</strong> {unknownCoverage.length} unwaived dimensions remain partial or unknown; this never renders as success.</div> : null}
    {preview.policy.warnings.length ? <ul className="space-y-1 text-sm text-warning">{preview.policy.warnings.map((warning) => <li key={warning.code}><AlertTriangle className="mr-2 inline size-4" />{warning.message}</li>)}</ul> : null}
    {input.overrideBlockerIds.length ? <Field label="Override reason" hint="Required only for policy-approved override IDs."><textarea aria-label="Override reason" maxLength={4096} value={input.overrideReason} disabled={disabled} onChange={(event) => onChange({ overrideReason: event.target.value })} className={textareaClass} /></Field> : null}
  </section>
}

function BlockerRow({ blocker, selected, disabled, onToggle }: { blocker: AssessmentClosureBlocker; selected: boolean; disabled: boolean; onToggle: () => void }) {
  return <li className="rounded-lg border border-critical/25 bg-critical/5 p-3 text-sm"><div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-critical" /><div className="min-w-0 flex-1"><p className="font-semibold text-primary">{blocker.message}</p><p className="mt-1 font-mono text-xs text-tertiary">{blocker.code} · {blocker.id}</p></div>{blocker.overrideable ? <label className="flex items-center gap-2 text-xs font-semibold text-tertiary"><input type="checkbox" checked={selected} disabled={disabled} onChange={onToggle} />Override</label> : <Pill className="text-critical">Hard blocker</Pill>}</div></li>
}

function ReferencePanel({ preview }: { preview: AssessmentClosurePreview }) {
  return <section aria-labelledby="closure-references-title"><h3 id="closure-references-title" className="text-sm font-semibold text-primary">Effective references and changes</h3><p className="mt-1 text-xs text-tertiary">{preview.references.length} verification / accepted-risk / waiver references · {preview.scopeProfileChanges.length} scope or profile changes · {preview.nonFinalBranches.length} non-final branches</p>{preview.references.length ? <ul className="mt-2 grid gap-2 sm:grid-cols-2">{preview.references.map((reference) => <li key={`${reference.kind}:${reference.id}`} className="rounded-md border border-secondary px-3 py-2 text-xs"><strong className="text-primary">{reference.kind}</strong><span className="ml-2 font-mono text-tertiary">{reference.id}</span>{reference.expiresAt ? <span className="mt-1 block text-warning">Expires {formatDateTime(reference.expiresAt)}</span> : null}</li>)}</ul> : null}</section>
}

function PathList({ manifest, preview }: { manifest?: AssessmentClosureManifest; preview?: AssessmentClosurePreview }) {
  const path = manifest?.path ?? preview?.path ?? []
  return <div className="mt-5"><h3 className="text-sm font-semibold text-primary">Frozen root-to-final path</h3><ol className="mt-2 flex flex-wrap gap-2" aria-label="Frozen root-to-final path">{path.map((member) => <li key={`${member.pathPosition}:${member.assessmentId}`} className="rounded-lg border border-secondary bg-secondary/30 px-3 py-2 text-xs"><span className="font-semibold text-primary">{member.assessmentType === 'initial' ? 'Initial' : `Re-test #${member.retestNumber}`}</span><span className="ml-2 font-mono text-tertiary">{member.assessmentId}</span>{member.snapshotId ? <span className="mt-1 block font-mono text-quaternary">{member.snapshotId}</span> : null}</li>)}</ol></div>
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><dt className="text-[11px] font-semibold uppercase tracking-wide text-quaternary">{label}</dt><dd className={`mt-1 break-all text-sm text-primary ${mono ? 'font-mono text-xs' : 'font-semibold'}`}>{value}</dd></div>
}

function toggle(values: string[], value: string) { return values.includes(value) ? values.filter((item) => item !== value) : [...values, value].sort() }
function shortHash(value: string) { return value ? `${value.slice(0, 12)}…${value.slice(-8)}` : 'N/A' }
function formatDateTime(value: string | null) { return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Pending' }
const textareaClass = 'input-inset min-h-24 w-full resize-y rounded-lg border border-secondary bg-secondary px-3.5 py-2.5 text-sm text-primary outline-none placeholder:text-quaternary focus:border-brand focus:ring-2 focus:ring-brand/40 disabled:opacity-50'
