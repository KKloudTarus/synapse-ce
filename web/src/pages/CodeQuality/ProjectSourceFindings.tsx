import { ChevronLeft, ChevronRight, Package, RefreshCw } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, SevBadge, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, type ProjectSourceFinding } from '../../lib/api'
import { statusLabel } from '../../lib/format'
import { TicketsPanel } from '../EngagementDetail/components/TicketsPanel'
import { useProjectRouteContext } from './CodeQualityProject'

const triageRoles = new Set(['admin', 'consultant', 'member', 'reviewer'])
const statuses = ['open', 'triage', 'confirmed', 'false_positive', 'remediated']

function findingFromHash(hash: string): string {
  if (!hash.startsWith('#finding-')) return ''
  try {
    return decodeURIComponent(hash.slice('#finding-'.length))
  } catch {
    return ''
  }
}

function SourceFindingStatus({ finding, projectKey, canTriage, onUpdated }: {
  finding: ProjectSourceFinding
  projectKey: string
  canTriage: boolean
  onUpdated: (next: ProjectSourceFinding) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const activeRef = useRef(true)
  const identityRef = useRef(`${projectKey}:${finding.id}`)
  const identity = `${projectKey}:${finding.id}`
  identityRef.current = identity

  useEffect(() => {
    activeRef.current = true
    return () => { activeRef.current = false }
  }, [])

  function isCurrent() {
    return activeRef.current && identityRef.current === identity
  }

  async function update(status: string) {
    if (!canTriage || busy || status === finding.status) return
    setBusy(true)
    setError(null)
    try {
      const next = await api.updateProjectSourceFindingStatus(projectKey, finding.id, status, finding.version)
      if (isCurrent()) onUpdated(next)
    } catch (cause) {
      if (isCurrent()) setError(cause instanceof Error ? cause.message : 'Could not update source finding status.')
    } finally {
      if (isCurrent()) setBusy(false)
    }
  }

  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-secondary" htmlFor={`source-finding-status-${finding.id}`}>Triage status</label>
      <select
        id={`source-finding-status-${finding.id}`}
        value={finding.status}
        disabled={!canTriage || busy}
        onChange={(event) => void update(event.target.value)}
        className="w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {statuses.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}
      </select>
      {!canTriage && <p className="text-xs text-tertiary">A consultant, reviewer, or administrator can change source-finding triage.</p>}
      {error && <p role="alert" className="text-xs text-error-primary">{error}</p>}
    </div>
  )
}

function Sources({ sources }: { sources: string[] | undefined }) {
  if (!sources?.length) return <p className="text-sm text-tertiary">No source provenance was recorded for this finding.</p>
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-sm">
        <thead className="border-b border-secondary text-xs uppercase tracking-wide text-tertiary"><tr><th className="pb-2 pr-4 font-semibold">Evidence source</th></tr></thead>
        <tbody>{sources.map((source) => <tr key={source} className="border-b border-secondary/70 last:border-0"><td className="py-2 font-mono text-xs text-secondary">{source}</td></tr>)}</tbody>
      </table>
    </div>
  )
}

/** Project-scoped SCA findings. The client never receives the internal engagement identity backing a source scan. */
export function ProjectSourceFindings() {
  const { projectKey } = useProjectRouteContext()
  const location = useLocation()
  const navigate = useNavigate()
  const [after, setAfter] = useState('')
  const [previous, setPrevious] = useState<string[]>([])
  const { data: page, loading, error, refetch } = useFetch(() => api.listProjectSourceFindings(projectKey, after), { deps: [projectKey, after] })
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const [selectedID, setSelectedID] = useState('')
  const requestedID = useMemo(() => findingFromHash(location.hash), [location.hash])
  const { data: deepLinked, loading: loadingDeepLink, error: deepLinkError, refetch: refetchDeepLink } = useFetch(
    () => api.getProjectSourceFinding(projectKey, requestedID),
    { deps: [projectKey, requestedID], enabled: !!requestedID },
  )
  const findings = page?.items ?? []
  const selected = requestedID
    ? (deepLinked?.id === requestedID ? deepLinked : findings.find((finding) => finding.id === requestedID)) ?? null
    : findings.find((finding) => finding.id === selectedID) ?? null
  const canTriage = triageRoles.has(me?.role ?? '')
  const selectedIdentityRef = useRef('')
  selectedIdentityRef.current = `${projectKey}:${selected?.id ?? ''}`

  useEffect(() => {
    const next = requestedID && findings.some((finding) => finding.id === requestedID)
      ? requestedID
      : findings.some((finding) => finding.id === selectedID)
        ? selectedID
        : findings[0]?.id ?? ''
    setSelectedID(next)
    if (requestedID && next === requestedID) document.getElementById(`finding-${next}`)?.scrollIntoView?.({ block: 'nearest' })
  }, [findings, requestedID, selectedID])

  useEffect(() => {
    setAfter('')
    setPrevious([])
    setSelectedID('')
  }, [projectKey])

  function select(findingID: string) {
    setSelectedID(findingID)
    navigate({ hash: `finding-${encodeURIComponent(findingID)}` }, { replace: true })
  }

  function updated(_next: ProjectSourceFinding) {
    if (selectedIdentityRef.current !== `${projectKey}:${_next.id}`) return
    // useFetch owns this read cache; refresh from the scoped server route after a successful triage write.
    refetch()
    if (requestedID === _next.id) refetchDeepLink()
  }

  function refreshSelected() {
    refetch()
    if (requestedID) refetchDeepLink()
  }

  function nextPage() {
    if (!page?.nextCursor) return
    setPrevious((current) => [...current, after])
    setAfter(page.nextCursor)
  }

  function previousPage() {
    setPrevious((current) => {
      const next = [...current]
      const cursor = next.pop()
      if (cursor !== undefined) setAfter(cursor)
      return next
    })
  }

  if (loading && !page) return <Card><Spinner label="Loading source findings…" /></Card>
  if (error && !page) return <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={refetch}>Retry source findings</Button></div>
  if (!findings.length && !requestedID) return <Card><EmptyState icon={Package} title="No source findings" hint="Run a Project source scan to inspect SCA results here. Full quality analysis remains separate." /></Card>
  if (!findings.length && requestedID && loadingDeepLink) return <Card><Spinner label="Loading linked source finding…" /></Card>
  if (!findings.length && requestedID && deepLinkError) return <div className="space-y-3"><ErrorState message="The linked source finding is no longer available in this Project." /><Button variant="secondary" onClick={refetchDeepLink}>Retry linked finding</Button></div>

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(18rem,0.7fr)_minmax(0,1.3fr)]">
      <Card title="Source findings" actions={<div className="flex gap-1"><Button variant="secondary" className="px-2 py-1" disabled={previous.length === 0 || loading} onClick={previousPage}><ChevronLeft className="size-4" /> Previous</Button><Button variant="secondary" className="px-2 py-1" disabled={!page?.nextCursor || loading} onClick={nextPage}>Next <ChevronRight className="size-4" /></Button></div>} bodyClass="p-0">
        <ul className="divide-y divide-secondary">
          {findings.map((finding) => (
            <li key={finding.id} id={`finding-${finding.id}`}>
              <button
                type="button"
                aria-current={selected?.id === finding.id ? 'true' : undefined}
                onClick={() => select(finding.id)}
                className={cn('flex w-full items-start gap-3 p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/60', selected?.id === finding.id ? 'bg-brand/10' : 'hover:bg-secondary/60')}
              >
                <SevBadge sev={finding.severity} />
                <span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold text-primary">{finding.title}</span><span className="mt-0.5 block text-xs text-tertiary">{statusLabel(finding.status)}</span></span>
                <ChevronRight className="mt-0.5 size-4 shrink-0 text-quaternary" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      </Card>
      {selected && (
        <div id={`finding-${selected.id}-detail`} className="space-y-4">
          <Card title={<span className="flex flex-wrap items-center gap-2"><SevBadge sev={selected.severity} /> <span>{selected.title}</span></span>} actions={<Button variant="secondary" className="px-2 py-1" onClick={refreshSelected}><RefreshCw className="size-4" /> Refresh</Button>} bodyClass="space-y-4">
            {selected.description && <p className="whitespace-pre-wrap text-sm leading-relaxed text-secondary">{selected.description}</p>}
            <div className="grid gap-3 border-y border-secondary py-3 sm:grid-cols-3"><Detail label="Status" value={statusLabel(selected.status)} /><Detail label="CWE" value={selected.cwe || 'Not recorded'} /><Detail label="Fixed in" value={selected.fixedVersion || 'No fixed version recorded'} /></div>
            <section aria-label="Source provenance"><h2 className="mb-2 text-sm font-semibold text-primary">Source provenance</h2><Sources sources={selected.sources} /></section>
            <SourceFindingStatus key={`${projectKey}:${selected.id}`} finding={selected} projectKey={projectKey} canTriage={canTriage} onUpdated={updated} />
          </Card>
          <TicketsPanel projectKey={projectKey} findingId={selected.id} />
        </div>
      )}
      {requestedID && !loadingDeepLink && deepLinkError && <div className="xl:col-span-2"><ErrorState message="The linked source finding is no longer available in this Project." /></div>}
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><p className="text-xs font-medium uppercase tracking-wide text-tertiary">{label}</p><p className="mt-1 text-sm text-primary">{value}</p></div>
}
