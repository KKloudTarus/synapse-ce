import { AlertTriangle } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { CheckCircle, File06, LinkExternal02, Trash01 } from '@untitledui/icons'
import { Button, EmptyState, ErrorState, Spinner } from '../../../components/ui'
import { ConfirmDialog } from '../../../components/synapse/ConfirmDialog'
import { api } from '../../../lib/api'
import { documentsApi, type DocumentIntent, type DocumentLink, type DocumentSourceKind } from '../../../lib/api/documents'
import { integrationsApi } from '../../../lib/api/integrations'
import type { AssessmentCycleSummary, Integration } from '../../../lib/types'
import { isAdminRole } from '../../../lib/roles'
import { DocumentSchedulePanel } from './DocumentSchedulePanel'

const confluenceProviders = new Set(['confluence-cloud', 'confluence-dc'])
const terminalStates = new Set(['done', 'failed', 'uncertain'])
const cyclePageLimit = 100
const maxCyclePages = 3
const intentStoragePrefix = 'synapse.document-publication.intent'

type ProjectContext = { id: string; key: string }
export type DocumentSourceOption = { kind: DocumentSourceKind; sourceRef: string; label: string }

export type DocumentPublishingPanelProps =
  | { engagementId: string; project?: never }
  | { engagementId?: never; project: ProjectContext }

function requestKey(prefix: string): string {
  const suffix = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`
  return `${prefix}-${suffix}`
}

function shortHash(value: string): string {
  return value.length > 16 ? `${value.slice(0, 12)}…${value.slice(-4)}` : value
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : 'The document request could not be completed.'
}

function intentStorageKey(tenantID: string | undefined, userID: string | undefined, scope: 'engagement' | 'project', scopeID: string): string | null {
  if (!tenantID || !userID || !scopeID) return null
  return `${intentStoragePrefix}:${encodeURIComponent(tenantID)}:${encodeURIComponent(userID)}:${scope}:${encodeURIComponent(scopeID)}`
}

function storedIntentID(key: string | null): string | null {
  if (!key || typeof window === 'undefined') return null
  try {
    const value = window.sessionStorage.getItem(key)
    return value ? value : null
  } catch {
    return null
  }
}

function storeIntentID(key: string | null, intentID: string | null): void {
  if (!key || typeof window === 'undefined') return
  try {
    if (intentID) window.sessionStorage.setItem(key, intentID)
    else window.sessionStorage.removeItem(key)
  } catch {
    // Session storage is only a convenience for restoring the read-only status view.
  }
}

function statusOf(cause: unknown): number | undefined {
  const status = (cause as { status?: unknown } | null)?.status
  return typeof status === 'number' ? status : undefined
}

function projectSources(project: ProjectContext, cycles: AssessmentCycleSummary[]): DocumentSourceOption[] {
	const result: DocumentSourceOption[] = [{ kind: 'project_quality_summary', sourceRef: `project:${project.id}`, label: 'Project quality summary' }]
  for (const cycle of cycles) {
    if (cycle.projectId === project.id && cycle.status === 'completed' && cycle.activeClosureManifestId) {
      result.push({ kind: 'assessment_closure_report', sourceRef: `assessment-cycle:${cycle.id}`, label: `Closure report · ${cycle.name}` })
    }
  }
  return result
}

async function currentProjectCycles(projectID: string): Promise<{ items: AssessmentCycleSummary[]; incomplete: boolean }> {
  const items: AssessmentCycleSummary[] = []
  let cursor = ''
  for (let page = 0; page < maxCyclePages; page++) {
    const result = await api.listAssessmentCycles({ boundaryKind: 'project', limit: cyclePageLimit, cursor })
    items.push(...result.items.filter((cycle) => cycle.projectId === projectID && cycle.status === 'completed' && Boolean(cycle.activeClosureManifestId)))
    if (!result.nextCursor) return { items, incomplete: false }
    cursor = result.nextCursor
  }
  return { items, incomplete: true }
}

export function DocumentPublishingPanel({ engagementId, project }: DocumentPublishingPanelProps) {
  const isProject = project !== undefined
  const scopeID = project?.id ?? engagementId ?? ''
  const baseSources = useMemo<DocumentSourceOption[]>(() => project
    ? [{ kind: 'project_quality_summary', sourceRef: `project:${project.id}`, label: 'Project quality summary' }]
    : [{ kind: 'engagement_report', sourceRef: `engagement:${engagementId}`, label: 'Engagement report' }], [engagementId, project])
  const [links, setLinks] = useState<DocumentLink[]>([])
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [sources, setSources] = useState<DocumentSourceOption[]>(baseSources)
  const [selectedIntegration, setSelectedIntegration] = useState('')
  const [selectedSourceRef, setSelectedSourceRef] = useState(baseSources[0]?.sourceRef ?? '')
  const [canPublish, setCanPublish] = useState(false)
  const [cyclesIncomplete, setCyclesIncomplete] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState<DocumentIntent | null>(null)
  const [purge, setPurge] = useState<DocumentLink | null>(null)
  const [pendingStorageKey, setPendingStorageKey] = useState<string | null>(null)
  const epoch = useRef(0)
  const pendingStorageKeyRef = useRef<string | null>(null)
  const intentGeneration = useRef(0)
  const pendingNeedsPoll = pending !== null && !terminalStates.has(pending.state)

  const setTrackedPending = (next: DocumentIntent | null) => {
    setPending(next)
    storeIntentID(pendingStorageKeyRef.current, next?.id ?? null)
  }

  const isCurrentIntentOperation = (current: number, storageKey: string | null, generation: number) =>
    current === epoch.current && storageKey === pendingStorageKeyRef.current && generation === intentGeneration.current

  const refresh = async (current = epoch.current) => {
    try {
      const linksRequest = project ? documentsApi.listProjectDocuments(project.key) : documentsApi.listEngagementDocuments(engagementId ?? '')
      const [nextLinks, nextIntegrations, me] = await Promise.all([linksRequest, integrationsApi.listIntegrations(), api.me()])
      if (current !== epoch.current) return
      const cycleResult = project && me?.features?.assessmentLifecycleRead !== false
        ? await currentProjectCycles(project.id)
        : { items: [] as AssessmentCycleSummary[], incomplete: false }
      if (current !== epoch.current) return
      const available = nextIntegrations.filter((item) => confluenceProviders.has(item.provider) && item.enabled && !item.archived && item.credentialConfigured)
      const nextSources = project ? projectSources(project, cycleResult.items) : baseSources
      const nextPendingStorageKey = intentStorageKey(me?.tenantId, me?.id, isProject ? 'project' : 'engagement', scopeID)
      if (pendingStorageKeyRef.current !== nextPendingStorageKey) {
        intentGeneration.current++
        setPending(null)
        setBusy(false)
        setPurge(null)
      }
      pendingStorageKeyRef.current = nextPendingStorageKey
      setPendingStorageKey(nextPendingStorageKey)
      setLinks(nextLinks)
      setIntegrations(available)
      setSources(nextSources)
      setCyclesIncomplete(cycleResult.incomplete)
      setSelectedIntegration((old) => available.some((item) => item.id === old) ? old : available[0]?.id ?? '')
      setSelectedSourceRef((old) => nextSources.some((item) => item.sourceRef === old) ? old : nextSources[0]?.sourceRef ?? '')
      setCanPublish(me?.role === 'reviewer' || isAdminRole(me?.role))
      setError(null)
    } catch (cause) {
      if (current === epoch.current) setError(message(cause))
    }
  }

  useEffect(() => {
    const current = ++epoch.current
    intentGeneration.current++
    pendingStorageKeyRef.current = null
    setPendingStorageKey(null)
    setPending(null)
    setBusy(false)
    setPurge(null)
    setLoading(true)
    void refresh(current).finally(() => {
      if (current === epoch.current) setLoading(false)
    })
    return () => { epoch.current++ }
  }, [engagementId, project?.id, project?.key])

  useEffect(() => {
    if (!pendingStorageKey) return
    const intentID = storedIntentID(pendingStorageKey)
    if (!intentID) return
    const current = epoch.current
    const generation = intentGeneration.current
    let cancelled = false
    void documentsApi.documentIntent(intentID).then((next) => {
      if (cancelled || !isCurrentIntentOperation(current, pendingStorageKey, generation) || storedIntentID(pendingStorageKey) !== intentID) return
      setTrackedPending(next)
    }, (cause) => {
      if (cancelled || !isCurrentIntentOperation(current, pendingStorageKey, generation) || storedIntentID(pendingStorageKey) !== intentID) return
      const status = statusOf(cause)
      if (status === 404 || status === 403) {
        storeIntentID(pendingStorageKey, null)
        setPending(null)
        if (status === 403) setError('You no longer have access to this publication intent.')
        return
      }
      setError(message(cause))
    })
    return () => { cancelled = true }
  }, [pendingStorageKey])

  useEffect(() => {
    if (!pending || terminalStates.has(pending.state)) return
    let cancelled = false
    let remaining = 3
    const current = epoch.current
    const storageKey = pendingStorageKeyRef.current
    const generation = intentGeneration.current
    const poll = async () => {
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      try {
        const next = await documentsApi.documentIntent(pending.id)
        if (cancelled || !isCurrentIntentOperation(current, storageKey, generation)) return
        setTrackedPending(next)
        if (!terminalStates.has(next.state) && --remaining > 0) window.setTimeout(() => { void poll() }, 1500)
        else if (next.state === 'done') void refresh(current)
      } catch (cause) {
        if (!cancelled && isCurrentIntentOperation(current, storageKey, generation)) setError(message(cause))
      }
    }
    const timer = window.setTimeout(() => { void poll() }, 1500)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [pending?.id, pendingNeedsPoll])

  async function publish() {
    const source = sources.find((item) => item.sourceRef === selectedSourceRef)
    if (!selectedIntegration || !source || busy) return
    const current = epoch.current
    const storageKey = pendingStorageKeyRef.current
    const generation = ++intentGeneration.current
    setBusy(true)
    setError(null)
    try {
      const result = await documentsApi.publish({ integrationId: selectedIntegration, sourceKind: source.kind, scopeId: scopeID, sourceRef: source.sourceRef, requestKey: requestKey('publish') })
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      setTrackedPending(result.intent ?? null)
      if (result.skipped || result.link) await refresh()
    } catch (cause) {
      if (isCurrentIntentOperation(current, storageKey, generation)) setError(message(cause))
    } finally {
      if (isCurrentIntentOperation(current, storageKey, generation)) setBusy(false)
    }
  }

  async function unpublish() {
    if (!purge || busy) return
    const current = epoch.current
    const storageKey = pendingStorageKeyRef.current
    const generation = ++intentGeneration.current
    setBusy(true)
    setError(null)
    try {
      const result = await documentsApi.unpublish(purge.id, requestKey('unpublish'))
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      setTrackedPending(result.intent ?? null)
      setPurge(null)
      if (result.skipped || result.link) await refresh()
    } catch (cause) {
      if (isCurrentIntentOperation(current, storageKey, generation)) setError(message(cause))
    } finally {
      if (isCurrentIntentOperation(current, storageKey, generation)) setBusy(false)
    }
  }

  async function resumePreparedPublication() {
    if (!pending || pending.state !== 'failed' || pending.errorCode !== 'provider_refused' || pending.action !== 'create' || busy) return
    const current = epoch.current
    const storageKey = pendingStorageKeyRef.current
    const generation = ++intentGeneration.current
    setBusy(true)
    setError(null)
    try {
      const next = await documentsApi.resumePreparedPublication(pending.id, pending.version)
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      setTrackedPending(next)
      await refresh()
    } catch (cause) {
      if (isCurrentIntentOperation(current, storageKey, generation)) setError(message(cause))
    } finally {
      if (isCurrentIntentOperation(current, storageKey, generation)) setBusy(false)
    }
  }

  async function refreshPendingStatus() {
    if (!pending || busy) return
    const current = epoch.current
    const storageKey = pendingStorageKeyRef.current
    const generation = ++intentGeneration.current
    setBusy(true)
    setError(null)
    try {
      const next = await documentsApi.documentIntent(pending.id)
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      setTrackedPending(next)
      if (next.state === 'done') await refresh(current)
    } catch (cause) {
      if (!isCurrentIntentOperation(current, storageKey, generation)) return
      const status = statusOf(cause)
      if (status === 404 || status === 403) {
        storeIntentID(storageKey, null)
        setPending(null)
        if (status === 403) setError('You no longer have access to this publication intent.')
        return
      }
      setError(message(cause))
    } finally {
      if (isCurrentIntentOperation(current, storageKey, generation)) setBusy(false)
    }
  }

  if (loading) return <Spinner label="Loading document publications…" />
  return (
    <section aria-labelledby="document-publishing-title" className="space-y-3 rounded-xl border border-secondary bg-primary p-4">
      <div>
        <h3 id="document-publishing-title" className="text-sm font-semibold text-primary">Publish report</h3>
        <p className="mt-1 text-xs text-tertiary">Publishes the governed PDF report to an administrator-configured Confluence destination.</p>
      </div>
      {error ? <ErrorState message={error} /> : null}
      {pending ? <div className="space-y-2 rounded-md bg-secondary px-3 py-2 text-xs text-secondary"><p>Publication intent {pending.state}{pending.errorCode ? ` (${pending.errorCode})` : ''}. Automatic status refresh is bounded; use Refresh status to check it again.</p><Button variant="secondary" className="px-2 py-1 text-xs" loading={busy} disabled={busy} onClick={() => void refreshPendingStatus()}>Refresh status</Button>{canPublish && pending.state === 'failed' && pending.errorCode === 'provider_refused' && pending.action === 'create' ? <div className="flex flex-wrap items-center gap-2"><p>After destination access is fixed, Synapse verifies restricted sharing before any report content is uploaded.</p><Button variant="secondary" className="px-2 py-1 text-xs" loading={busy} disabled={busy} onClick={() => void resumePreparedPublication()}>Resume prepared publication</Button></div> : null}</div> : null}
      {links.length ? <ul className="space-y-2">{links.map((link) => <li key={link.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-secondary px-3 py-2 text-xs"><div className="min-w-0"><div className="flex items-center gap-1.5 font-medium text-primary">{!link.retiredAt && (link.restrictionStatus === 'restriction_lost' || link.restrictionStatus === 'unverifiable') ? <AlertTriangle className="size-4 text-warning-primary" /> : <CheckCircle className="size-4 text-success" />}{link.retiredAt ? 'Unpublished' : link.restrictionStatus === 'restriction_lost' ? <span role="status">Restricted sharing lost</span> : link.restrictionStatus === 'unverifiable' ? <span role="status">Sharing could not be verified</span> : 'Published'} · v{link.remoteVersion}</div>{!link.retiredAt && link.restrictionCheckedAt ? <p className="mt-1 text-tertiary">Last sharing check: {new Date(link.restrictionCheckedAt).toLocaleString()}</p> : null}<p className="mt-1 truncate font-mono text-tertiary" title={link.contentHash}>{shortHash(link.contentHash)}</p></div><div className="flex items-center gap-1.5">{!link.retiredAt && link.remoteUrl ? <a className="inline-flex items-center gap-1 text-brand-secondary underline" href={link.remoteUrl} target="_blank" rel="noreferrer"><LinkExternal02 className="size-3" />Open</a> : null}{canPublish && !link.retiredAt ? <Button variant="secondary" className="px-2 py-1 text-xs" onClick={() => setPurge(link)} disabled={busy}><Trash01 className="size-3.5" />Unpublish</Button> : null}</div></li>)}</ul> : <EmptyState icon={File06} title="No published report" hint="Choose a configured Confluence connection to request publication." />}
      {cyclesIncomplete ? <p className="text-xs text-warning-primary">Only the first {maxCyclePages * cyclePageLimit} project cycles were checked. Use the cycle view before publishing a closure report if it is not listed.</p> : null}
      {!canPublish ? <p className="text-xs text-tertiary">A reviewer or administrator can request publication and unpublish a report.</p> : integrations.length === 0 ? <p className="text-xs text-tertiary">No enabled Confluence connection with credentials is available.</p> : <div className="flex flex-wrap items-end gap-2">{isProject && sources.length > 1 ? <label className="grid gap-1 text-xs font-medium text-secondary">Report source<select aria-label="Report source" className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary" value={selectedSourceRef} onChange={(event) => setSelectedSourceRef(event.target.value)} disabled={busy}>{sources.map((item) => <option key={item.sourceRef} value={item.sourceRef}>{item.label}</option>)}</select></label> : null}<label className="grid gap-1 text-xs font-medium text-secondary">Connection<select aria-label="Confluence connection" className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary" value={selectedIntegration} onChange={(event) => setSelectedIntegration(event.target.value)} disabled={busy}>{integrations.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><Button className="px-3 py-1.5 text-xs" loading={busy} onClick={() => void publish()} disabled={!selectedIntegration || !selectedSourceRef || busy}><File06 className="size-4" />Publish report</Button></div>}
      <DocumentSchedulePanel scope={isProject ? 'project' : 'engagement'} scopeID={scopeID} sources={sources} canManage={canPublish} />
      <ConfirmDialog open={purge !== null} title="Unpublish report" description="This permanently removes the page, its attachments, and its version history from Confluence." confirmLabel="Unpublish permanently" busy={busy} error={error} onCancel={() => { if (!busy) setPurge(null) }} onConfirm={() => void unpublish()} />
    </section>
  )
}
