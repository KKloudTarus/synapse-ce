import { useEffect, useRef, useState } from 'react'
import { Button, ErrorState, Spinner } from '../../../components/ui'
import { api, type TicketMapping, type TicketPreview } from '../../../lib/api'
import { newIdempotencyKey } from '../../../lib/api/client'
import { ticketDestination, ticketDestinationLabel } from '../../../lib/ticket-destinations'
import type { Integration, IntegrationProviderDescriptor } from '../../../lib/types'
import { TicketPreviewView } from './TicketPreviewView'

const submitRoles = new Set(['admin', 'consultant', 'member', 'reviewer'])
const message = (cause: unknown) => cause instanceof Error ? cause.message : 'Ticket preparation failed.'
const bulkLimit = 50

/** Bulk ticket creation snapshots and shows every selected provider-ready ticket before one submission. */
export function BulkTicketsPanel({ engagementId, findingIds, onDone }: { engagementId: string; findingIds: string[]; onDone: () => void }) {
  const [mappings, setMappings] = useState<TicketMapping[] | null>(null); const [role, setRole] = useState(''); const [mappingId, setMappingId] = useState('')
  const [previews, setPreviews] = useState<Array<{ findingId: string; preview: TicketPreview; requestKey: string }>>([]); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [notice, setNotice] = useState<string | null>(null)
  const [destinations, setDestinations] = useState<{ integrations: Integration[]; providers: IntegrationProviderDescriptor[]; error: string | null; loading: boolean }>({ integrations: [], providers: [], error: null, loading: true })
  const generation = useRef(0); const destinationLoad = useRef(0); const selection = useRef(findingIds); selection.current = findingIds; const selectionKey = findingIds.join('\u001f')
  useEffect(() => {
    const current = ++generation.current
    const destinationCurrent = ++destinationLoad.current
    setMappings(null); setRole(''); setMappingId(''); setPreviews([]); setBusy(false); setError(null); setNotice(null); setDestinations({ integrations: [], providers: [], error: null, loading: true })
    const selectedFindings = selection.current
    if (selectedFindings.length === 0) { setMappings([]); setError('Select at least one finding before preparing tickets.'); return }
    if (selectedFindings.length > bulkLimit) { setMappings([]); setError(`Select no more than ${bulkLimit} findings for one ticket batch.`); return }
    Promise.all([api.findingTickets(engagementId, selectedFindings[0]), api.me()]).then(([tickets, me]) => {
      if (current === generation.current) { setMappings(tickets.mappings); setMappingId(tickets.mappings[0]?.id ?? ''); setRole(me?.role ?? '') }
    }, (cause) => { if (current === generation.current) setError(message(cause)) })
    Promise.all([api.listIntegrations(), api.listIntegrationProviders()]).then(([integrations, providers]) => {
      if (destinationCurrent === destinationLoad.current) setDestinations({ integrations, providers, error: null, loading: false })
    }, (cause) => { if (destinationCurrent === destinationLoad.current) setDestinations({ integrations: [], providers: [], error: message(cause), loading: false }) })
  }, [engagementId, selectionKey])
  async function prepare() { if (!mappingId || findingIds.length === 0 || findingIds.length > bulkLimit) return; const current = generation.current; const selectedMapping = mappingId; const selectedFindings = [...findingIds]; setBusy(true); setError(null); setNotice(null); try { const result = await Promise.all(selectedFindings.map(async (findingId) => ({ findingId, preview: await api.previewTicket(engagementId, findingId, selectedMapping), requestKey: newIdempotencyKey() }))); if (current !== generation.current || selectedMapping !== mappingId) return; setPreviews(result); setNotice(`${result.length} ticket previews are ready. Review every ticket and submit when ready.`) } catch (cause) { if (current === generation.current) { setPreviews([]); setError(message(cause)) } } finally { if (current === generation.current) setBusy(false) } }
  async function submit() {
    if (!mappingId || !previews.length) return
    const current = generation.current; const selectedMapping = mappingId
    setBusy(true); setError(null); setNotice(null)
    try {
      const results = await api.bulkTickets(engagementId, selectedMapping, previews.map((item) => ({ findingId: item.findingId, previewDigest: item.preview.digest, requestKey: item.requestKey })))
      if (current !== generation.current || selectedMapping !== mappingId) return
      const byFinding = new Map(results.map((result) => [result.findingId, result]))
      const rejected = previews.filter(({ findingId }) => { const result = byFinding.get(findingId); return !result?.intent || !!result.errorCode })
      if (results.length !== previews.length) { setError('The provider returned an incomplete bulk ticket response. Refresh the findings before treating any request as complete.'); return }
      if (rejected.length > 0) { const details = rejected.map(({ findingId }) => `${findingId}${byFinding.get(findingId)?.errorCode ? ` (${byFinding.get(findingId)?.errorCode})` : ''}`).join(', '); setError(`Only ${previews.length - rejected.length} of ${previews.length} ticket requests were recorded. Review the rejected findings: ${details}.`); return }
      setNotice(`Recorded ${previews.length} durable ticket requests.`); onDone()
    } catch (cause) { if (current === generation.current) setError(message(cause)) } finally { if (current === generation.current) setBusy(false) }
  }
  const allowed = submitRoles.has(role)
  const selectedMapping = mappings?.find((mapping) => mapping.id === mappingId)
  const selectedDestination = selectedMapping ? ticketDestination(selectedMapping, destinations.integrations, destinations.providers) : null
  const destinationReady = !destinations.loading && !destinations.error && Boolean(selectedDestination)
  if (mappings === null && !error) return <Spinner label="Loading Ticket mappings…" />
  return <section aria-label="Bulk tickets" className="space-y-3 rounded-lg border border-secondary bg-secondary/40 p-3"><p className="text-sm font-semibold text-primary">Create tickets for {findingIds.length} selected findings</p>{error && <ErrorState message={error} />}{notice && <p role="status" className="text-xs text-success-primary">{notice}</p>}{!allowed && mappings?.length ? <p className="text-xs text-tertiary">A consultant, reviewer, or administrator must prepare and submit tickets.</p> : null}{!mappings?.length ? <p className="text-xs text-tertiary">No ticket mapping is configured for this engagement. An administrator can add one in Settings → Ticket providers or Settings → Jira.</p> : <><select aria-label="Bulk Ticket mapping" value={mappingId} disabled={busy} onChange={(event) => { generation.current++; setMappingId(event.target.value); setPreviews([]); setNotice(null); setError(null) }} className="w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary">{mappings.map((mapping) => <option key={mapping.id} value={mapping.id}>{ticketDestinationLabel(mapping, destinations.integrations, destinations.providers)}</option>)}</select>{destinations.loading ? <p role="status" className="text-xs text-tertiary">Loading ticket destination details…</p> : destinations.error ? <p role="alert" className="text-xs text-error-primary">Ticket destination details are unavailable. Refresh the findings before preparing previews.</p> : !selectedDestination ? <p role="alert" className="text-xs text-error-primary">The selected mapping no longer resolves to a provider connection. Preparing previews is disabled.</p> : <p className="text-xs text-secondary">Destination: {selectedDestination.provider} · {selectedDestination.connection} · {selectedDestination.endpoint}</p>}<div className="flex flex-wrap gap-2"><Button variant="secondary" disabled={!allowed || busy || !destinationReady} onClick={() => void prepare()}>Prepare previews</Button><Button disabled={!allowed || busy || previews.length !== findingIds.length || previews.some((item) => !item.preview.provider || !item.preview.endpoint)} onClick={() => void submit()}>Submit {previews.length || ''} tickets</Button><Button variant="ghost" disabled={busy} onClick={onDone}>Cancel</Button></div></>}{previews.length > 0 && <div className="space-y-3" aria-label="Bulk ticket previews">{previews.map((item) => <TicketPreviewView key={item.findingId} findingId={item.findingId} preview={item.preview} />)}</div>}</section>
}
