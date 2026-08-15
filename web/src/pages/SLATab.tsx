import { AlertTriangle, CalendarClock, CheckCircle2, Clock3, RefreshCw, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ApiError } from '../lib/api'
import type { Finding, SLARemediationStatus, SLAView } from '../lib/types'
import { Button, Card, cn, EmptyState, ErrorState, Spinner } from '../components/ui'

const STATUS_LABEL: Record<SLARemediationStatus, string> = {
  open: 'Open',
  mitigating: 'Mitigating',
  remediated: 'Remediated',
  accepted_risk: 'Accepted risk',
}

const TIER_STYLE: Record<string, string> = {
  emergency: 'bg-critical/15 text-critical ring-critical/30',
  critical: 'bg-critical/15 text-critical ring-critical/30',
  high: 'bg-high/15 text-high ring-high/30',
  medium: 'bg-medium/15 text-medium ring-medium/30',
  low: 'bg-low/15 text-low ring-low/30',
  exception: 'bg-muted text-mutedfg ring-borderstrong',
}

export function SLATab({ engagementId, findings }: { engagementId: string; findings: Finding[] | null }) {
  const [items, setItems] = useState<SLAView[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [disabled, setDisabled] = useState(false)
  const [selected, setSelected] = useState<SLAView | null>(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      setItems(await api.slas(engagementId))
      setDisabled(false)
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setDisabled(true)
        setItems([])
      } else {
        setError(err instanceof Error ? err.message : 'Failed to load remediation SLAs')
        setItems([])
      }
    }
  }, [engagementId])

  useEffect(() => { void load() }, [load])

  const findingByID = useMemo(() => new Map((findings ?? []).map((item) => [item.id, item])), [findings])
  const stats = useMemo(() => {
    const values = items ?? []
    return {
      overdue: values.filter((item) => item.overdue).length,
      emergency: values.filter((item) => item.assessment.result.tier === 'emergency').length,
      accepted: values.filter((item) => item.effectiveState === 'accepted_risk').length,
      remediated: values.filter((item) => item.effectiveState === 'remediated').length,
    }
  }, [items])

  if (items === null) return <Spinner label="Loading remediation SLAs…" />
  if (error) return <ErrorState message={error} />
  if (disabled) {
    return <EmptyState icon={CalendarClock} title="Remediation SLA is not enabled" hint="Set SYNAPSE_SLA_ENABLED=true to create governed, versioned deadlines for findings." />
  }
  if (items.length === 0) {
    return <EmptyState icon={CheckCircle2} title="No SLA assessments yet" hint="Run a scan after enabling SLA governance. Existing findings are unchanged until explicitly reassessed." />
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Overdue" value={stats.overdue} icon={AlertTriangle} tone={stats.overdue > 0 ? 'text-critical' : 'text-mutedfg'} />
        <Stat label="Emergency" value={stats.emergency} icon={Clock3} tone={stats.emergency > 0 ? 'text-critical' : 'text-mutedfg'} />
        <Stat label="Accepted risk" value={stats.accepted} icon={ShieldCheck} tone="text-medium" />
        <Stat label="Remediated" value={stats.remediated} icon={CheckCircle2} tone="text-low" />
      </div>

      <Card
        title="Risk-based remediation deadlines"
        actions={<Button variant="secondary" onClick={() => void load()} className="px-3 py-1.5"><RefreshCw className="size-3.5" /> Refresh</Button>}
        bodyClass="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-border bg-elevated text-xs uppercase tracking-wide text-subtlefg">
              <tr>
                <th className="px-5 py-3">Finding</th>
                <th className="px-4 py-3">Tier / score</th>
                <th className="px-4 py-3">Mitigate by</th>
                <th className="px-4 py-3">Remediate by</th>
                <th className="px-4 py-3">Workflow</th>
                <th className="px-4 py-3">Policy</th>
                <th className="px-5 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((item) => {
                const finding = findingByID.get(item.assessment.findingId)
                return (
                  <tr key={item.assessment.findingId} className={cn('hover:bg-elevated/60', item.overdue && 'bg-critical/5')}>
                    <td className="max-w-sm px-5 py-4">
                      <div className="truncate font-medium text-foreground">{finding?.title ?? item.assessment.findingId}</div>
                      <div className="mt-1 font-mono text-[11px] text-subtlefg">{item.assessment.findingId}</div>
                    </td>
                    <td className="px-4 py-4">
                      <span className={cn('inline-flex rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ring-inset', TIER_STYLE[item.assessment.result.tier])}>
                        {item.assessment.result.tier}
                      </span>
                      <span className="ml-2 font-mono tabular-nums text-mutedfg">{item.assessment.result.score.toFixed(1)}</span>
                    </td>
                    <Deadline value={item.assessment.result.mitigateBy} />
                    <Deadline value={item.assessment.result.remediateBy} overdue={item.overdue} />
                    <td className="px-4 py-4">
                      <div className="font-medium text-foreground">{STATUS_LABEL[item.effectiveState]}</div>
                      {item.acceptanceExpired && <div className="mt-1 text-xs font-semibold text-critical">Acceptance expired</div>}
                      <div className="mt-1 font-mono text-[11px] text-subtlefg">v{item.lifecycle.version}</div>
                    </td>
                    <td className="px-4 py-4 font-mono text-xs text-mutedfg">{item.assessment.result.configVersion}</td>
                    <td className="px-5 py-4 text-right">
                      <Button variant="secondary" className="px-3 py-1.5" onClick={() => setSelected(item)} disabled={item.effectiveState === 'remediated'}>
                        Transition
                      </Button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {selected && (
        <TransitionPanel
          item={selected}
          findingTitle={findingByID.get(selected.assessment.findingId)?.title ?? selected.assessment.findingId}
          onClose={() => setSelected(null)}
          onSaved={(updated) => {
            setItems((current) => (current ?? []).map((item) => item.assessment.findingId === updated.assessment.findingId ? updated : item))
            setSelected(null)
          }}
        />
      )}
    </div>
  )
}

function Stat({ label, value, icon: Icon, tone }: { label: string; value: number; icon: typeof AlertTriangle; tone: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-subtlefg"><Icon className={cn('size-4', tone)} />{label}</div>
      <div className={cn('mt-2 font-mono text-2xl font-semibold tabular-nums', tone)}>{value}</div>
    </div>
  )
}

function Deadline({ value, overdue = false }: { value: string; overdue?: boolean }) {
  const date = value ? new Date(value) : null
  return (
    <td className={cn('px-4 py-4 font-mono text-xs tabular-nums', overdue ? 'font-semibold text-critical' : 'text-mutedfg')}>
      {date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : '—'}
    </td>
  )
}

function TransitionPanel({ item, findingTitle, onClose, onSaved }: { item: SLAView; findingTitle: string; onClose: () => void; onSaved: (item: SLAView) => void }) {
  const [to, setTo] = useState<SLARemediationStatus>(item.effectiveState === 'open' ? 'mitigating' : 'remediated')
  const [reason, setReason] = useState('')
  const [control, setControl] = useState('')
  const [expiry, setExpiry] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function save() {
    setSaving(true)
    setError(null)
    try {
      const updated = await api.transitionSLA(item.assessment.engagementId, item.assessment.findingId, {
        to,
        reason,
        compensatingControl: control,
        acceptanceExpiresAt: expiry ? new Date(expiry).toISOString() : undefined,
        version: item.lifecycle.version,
      })
      onSaved(updated)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to transition remediation SLA')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title={`Transition: ${findingTitle}`}>
      <div className="grid gap-4 lg:grid-cols-2">
        <label className="text-sm text-mutedfg">New state
          <select value={to} onChange={(event) => setTo(event.target.value as SLARemediationStatus)} className="mt-1 block w-full rounded-lg border border-border bg-elevated px-3 py-2 text-foreground">
            <option value="open">Open</option>
            <option value="mitigating">Mitigating</option>
            <option value="remediated">Remediated</option>
            <option value="accepted_risk">Accepted risk</option>
          </select>
        </label>
        <label className="text-sm text-mutedfg">Reason
          <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Required audit rationale" className="mt-1 block w-full rounded-lg border border-border bg-elevated px-3 py-2 text-foreground" />
        </label>
        {to === 'accepted_risk' && <>
          <label className="text-sm text-mutedfg">Compensating control
            <input value={control} onChange={(event) => setControl(event.target.value)} placeholder="Required control" className="mt-1 block w-full rounded-lg border border-border bg-elevated px-3 py-2 text-foreground" />
          </label>
          <label className="text-sm text-mutedfg">Acceptance expires
            <input type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)} className="mt-1 block w-full rounded-lg border border-border bg-elevated px-3 py-2 text-foreground" />
          </label>
        </>}
      </div>
      {error && <div className="mt-4"><ErrorState message={error} /></div>}
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button loading={saving} onClick={() => void save()} disabled={!reason.trim() || (to === 'accepted_risk' && (!control.trim() || !expiry))}>Save transition</Button>
      </div>
    </Card>
  )
}
