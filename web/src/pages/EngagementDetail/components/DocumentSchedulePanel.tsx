import { useEffect, useRef, useState } from 'react'
import { Calendar, Clock, Mail01, Trash01 } from '@untitledui/icons'
import { Button, EmptyState, ErrorState, Spinner } from '../../../components/ui'
import { ConfirmDialog } from '../../../components/synapse/ConfirmDialog'
import { integrationsApi } from '../../../lib/api/integrations'
import { documentSchedulesApi, type DocumentSchedule, type DocumentScheduleDestination, type DocumentScheduleFrequency, type DocumentScheduleRun, type DocumentScheduleScope } from '../../../lib/api/document-schedules'
import type { Integration } from '../../../lib/types'
import type { DocumentSourceOption } from './DocumentPublishingPanel'

const documentProviders = new Set(['confluence-cloud', 'confluence-dc', 'google-drive', 'sharepoint', 'onedrive'])
const weekdayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

function message(cause: unknown): string { return cause instanceof Error ? cause.message : 'The schedule request could not be completed.' }
function timeParts(value: string) { const [hour = '09', minute = '00'] = value.split(':'); return { hour: Number(hour), minute: Number(minute) } }
function displayDue(value: string, zone: string) { try { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: zone }).format(new Date(value)) } catch { return value } }
function destinationLabel(destination: DocumentScheduleDestination) { return destination === 'confluence' ? 'Document publishing' : 'Email' }

export function DocumentSchedulePanel({ scope, scopeID, sources, canManage }: { scope: DocumentScheduleScope; scopeID: string; sources: DocumentSourceOption[]; canManage: boolean }) {
  const [items, setItems] = useState<DocumentSchedule[]>([])
	const [runs, setRuns] = useState<Record<string, DocumentScheduleRun[]>>({})
	const [runsUnavailable, setRunsUnavailable] = useState(false)
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [emailDestinations, setEmailDestinations] = useState<{ id: string; name: string; recipientCount: number }[]>([])
  const [sourceRef, setSourceRef] = useState(sources[0]?.sourceRef ?? '')
  const [destination, setDestination] = useState<DocumentScheduleDestination>('confluence')
  const [destinationID, setDestinationID] = useState('')
  const [frequency, setFrequency] = useState<DocumentScheduleFrequency>('weekly')
  const [weekday, setWeekday] = useState(1)
  const [day, setDay] = useState(1)
  const [wallTime, setWallTime] = useState('09:00')
  const [timezone, setTimezone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<DocumentSchedule | null>(null)
  const epoch = useRef(0)

  const refresh = async (current = epoch.current) => {
    try {
      const schedules = await documentSchedulesApi.list(scope, scopeID)
		const runRows = await Promise.all(schedules.slice(0, 10).map(async (schedule) => {
			try { return [schedule.id, await documentSchedulesApi.runs(schedule.id)] as const } catch { return [schedule.id, null] as const }
		}))
      const auxiliary = canManage ? await Promise.all([integrationsApi.listIntegrations(), documentSchedulesApi.emailDestinations()]) : [[], []] as const
      if (current !== epoch.current) return
      const available = (auxiliary[0] as Integration[]).filter((item) => documentProviders.has(item.provider) && item.enabled && !item.archived && item.credentialConfigured)
      const emails = auxiliary[1] as { id: string; name: string; recipientCount: number }[]
      setItems(schedules)
		setRuns(Object.fromEntries(runRows.filter((row): row is readonly [string, DocumentScheduleRun[]] => row[1] !== null)))
		setRunsUnavailable(runRows.some((row) => row[1] === null))
      setIntegrations(available)
      setEmailDestinations(emails)
      setDestinationID((old) => {
        const choices = destination === 'email' ? emails : available
        return choices.some((item) => item.id === old) ? old : choices[0]?.id ?? ''
      })
      setError(null)
    } catch (cause) {
      if (current === epoch.current) setError(message(cause))
    }
  }

  useEffect(() => {
    const current = ++epoch.current
    setLoading(true)
    void refresh(current).finally(() => { if (current === epoch.current) setLoading(false) })
    return () => { epoch.current++ }
  }, [scope, scopeID, canManage])

  useEffect(() => {
    setSourceRef((current) => sources.some((item) => item.sourceRef === current) ? current : sources[0]?.sourceRef ?? '')
  }, [sources])

  useEffect(() => {
    const choices = destination === 'email' ? emailDestinations : integrations
    setDestinationID(choices[0]?.id ?? '')
  }, [destination, emailDestinations, integrations])

  async function save() {
    const source = sources.find((item) => item.sourceRef === sourceRef)
    if (!source || !destinationID || saving) return
    const { hour, minute } = timeParts(wallTime)
    setSaving(true)
    setError(null)
    try {
      await documentSchedulesApi.save({ sourceKind: source.kind, sourceRef: source.sourceRef, scopeId: scopeID, destination, integrationId: destination === 'confluence' ? destinationID : undefined, emailChannelId: destination === 'email' ? destinationID : undefined, timezone, frequency, weekday: frequency === 'weekly' ? weekday : 0, day: frequency === 'monthly' ? day : 0, hour, minute, enabled: true })
      await refresh()
    } catch (cause) {
      setError(message(cause))
    } finally {
      setSaving(false)
    }
  }

  async function disable() {
    if (!removing || saving) return
    setSaving(true)
    setError(null)
    try {
      await documentSchedulesApi.disable(removing.id, removing.version)
      setRemoving(null)
      await refresh()
    } catch (cause) {
      setError(message(cause))
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <Spinner label="Loading scheduled deliveries…" />
  const destinations = destination === 'email' ? emailDestinations : integrations
  return <section aria-labelledby="document-schedule-title" className="space-y-3 rounded-xl border border-secondary bg-primary p-4"><div><h3 id="document-schedule-title" className="flex items-center gap-1.5 text-sm font-semibold text-primary"><Calendar className="size-4" />Scheduled delivery</h3><p className="mt-1 text-xs text-tertiary">Uses calendar time in the selected IANA timezone. Email uses a configured, verified detail channel.</p></div>{error ? <ErrorState message={error} /> : null}{items.length ? <ul className="space-y-2">{items.map((item) => <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-secondary px-3 py-2 text-xs"><div><p className="font-medium text-primary">{item.frequency === 'weekly' ? `${weekdayNames[item.weekday] ?? 'Weekly'} at` : `Day ${item.day} at`} {String(item.hour).padStart(2, '0')}:{String(item.minute).padStart(2, '0')} · {destinationLabel(item.destination)}</p><p className="mt-1 text-tertiary">{item.enabled ? <>Next due: {displayDue(item.nextDueAt, item.timezone)} ({item.timezone})</> : 'Disabled'} · v{item.version}</p>{runs[item.id]?.length ? <ul aria-label={`Recent runs for ${item.id}`} className="mt-2 space-y-1 border-t border-secondary pt-2 text-tertiary">{runs[item.id].slice(0, 3).map((run) => <li key={run.id}><span className="font-medium text-primary">{run.state}</span> · due {displayDue(run.dueAt, item.timezone)} · delivered {run.deliveredCount}, uncertain {run.uncertainCount}, failed {run.failedCount}{run.contentHash ? ` · ${run.contentHash.slice(0, 12)}` : ''}{run.remotePageId ? ` · page ${run.remotePageId} v${run.remoteVersion}` : ''}</li>)}</ul> : null}</div>{canManage && item.enabled ? <Button variant="secondary" className="px-2 py-1 text-xs" disabled={saving} onClick={() => setRemoving(item)}><Trash01 className="size-3.5" />Disable</Button> : null}</li>)}</ul> : <EmptyState icon={Clock} title="No scheduled delivery" hint="Set a weekly or monthly report delivery using an existing governed destination." />}{runsUnavailable ? <p className="text-xs text-warning-primary">Some recent run history is unavailable. Refresh the panel to try again.</p> : null}{!canManage ? <p className="text-xs text-tertiary">A reviewer or administrator can create or disable delivery schedules.</p> : <div className="grid gap-2 border-t border-secondary pt-3 sm:grid-cols-2"><label className="grid gap-1 text-xs font-medium text-secondary">Report source<select aria-label="Schedule report source" value={sourceRef} onChange={(event) => setSourceRef(event.target.value)} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary">{sources.map((item) => <option key={item.sourceRef} value={item.sourceRef}>{item.label}</option>)}</select></label><label className="grid gap-1 text-xs font-medium text-secondary">Destination type<select aria-label="Schedule destination type" value={destination} onChange={(event) => setDestination(event.target.value === 'email' ? 'email' : 'confluence')} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary"><option value="confluence">Document publishing</option><option value="email">Verified email channel</option></select></label><label className="grid gap-1 text-xs font-medium text-secondary">Destination<select aria-label="Schedule destination" value={destinationID} onChange={(event) => setDestinationID(event.target.value)} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary">{destinations.map((item) => <option key={item.id} value={item.id}>{item.name}{'recipientCount' in item ? ` (${item.recipientCount} recipients)` : ''}</option>)}</select></label><label className="grid gap-1 text-xs font-medium text-secondary">Frequency<select aria-label="Schedule frequency" value={frequency} onChange={(event) => setFrequency(event.target.value === 'monthly' ? 'monthly' : 'weekly')} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary"><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></label>{frequency === 'weekly' ? <label className="grid gap-1 text-xs font-medium text-secondary">Day of week<select aria-label="Schedule weekday" value={weekday} onChange={(event) => setWeekday(Number(event.target.value))} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary">{weekdayNames.map((name, value) => <option key={name} value={value}>{name}</option>)}</select></label> : <label className="grid gap-1 text-xs font-medium text-secondary">Day of month<input aria-label="Schedule day" type="number" min="1" max="31" value={day} onChange={(event) => setDay(Number(event.target.value))} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary" /></label>}<label className="grid gap-1 text-xs font-medium text-secondary">Calendar time<input aria-label="Schedule time" type="time" value={wallTime} onChange={(event) => setWallTime(event.target.value)} disabled={saving} className="rounded-md border border-secondary bg-primary px-2 py-1.5 text-sm text-primary" /></label><label className="grid gap-1 text-xs font-medium text-secondary">IANA timezone<input aria-label="Schedule timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} disabled={saving} spellCheck={false} className="rounded-md border border-secondary bg-primary px-2 py-1.5 font-mono text-sm text-primary" /></label><div className="sm:col-span-2"><Button loading={saving} disabled={!sourceRef || !destinationID || !timezone.trim() || saving} onClick={() => void save()}><Mail01 className="size-4" />Schedule delivery</Button></div></div>}<ConfirmDialog open={removing !== null} title="Disable scheduled delivery" description="This stops future scheduled report deliveries." confirmLabel="Disable schedule" busy={saving} error={error} onCancel={() => { if (!saving) setRemoving(null) }} onConfirm={() => void disable()} /></section>
}
