import { useEffect, useMemo, useState } from 'react'
import { CheckCircle, ChevronDown, Package, ShieldTick } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Pill, SevBadge, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { VulnerabilityOccurrenceEvent } from '../../lib/api'
import type { Severity, VulnerabilityAction, VulnerabilityAssessment, VulnerabilityOccurrence } from '../../lib/types'

const STATUS_ORDER: Record<string, number> = { open: 0, acknowledged: 1, resolved: 2 }

function statusTone(status: string): string {
  switch (status) {
    case 'open':
      return 'text-warning-primary bg-warning-primary/10 border-warning-primary/25'
    case 'acknowledged':
      return 'text-utility-blue-600 dark:text-utility-blue-400 bg-utility-blue-500/10 border-utility-blue-500/25'
    case 'resolved':
      return 'text-success-primary bg-success-primary/10 border-success-primary/25'
    default:
      return 'text-tertiary bg-secondary border-secondary'
  }
}

function occStateTone(state: string): string {
  const s = state.toLowerCase()
  if (s === 'open' || s === 'active') return 'text-error-primary'
  if (s === 'fixed' || s === 'resolved') return 'text-success-primary'
  return 'text-tertiary'
}

function ActionRow({
  action,
  busy,
  onAck,
  onResolve,
}: {
  action: VulnerabilityAction
  busy: boolean
  onAck: () => void
  onResolve: () => void
}) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-secondary/60 py-3 first:border-t-0">
      <ShieldTick className="size-4 shrink-0 text-quaternary" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm text-primary" title={action.title}>
          {action.title || action.type || action.id}
        </span>
        {action.reasonCodes.length > 0 && (
          <span className="mt-1 flex flex-wrap gap-1">
            {action.reasonCodes.map((c) => (
              <Pill key={c} className="font-mono">
                {c}
              </Pill>
            ))}
          </span>
        )}
      </span>
      <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-bold', statusTone(action.status))}>
        {action.status}
      </span>
      <span className="flex items-center gap-2">
        {action.status === 'open' && (
          <Button variant="secondary" onClick={onAck} loading={busy} className="px-2.5 py-1 text-xs">
            Acknowledge
          </Button>
        )}
        {action.status !== 'resolved' && (
          <Button variant="primary" onClick={onResolve} loading={busy} className="px-2.5 py-1 text-xs">
            Resolve
          </Button>
        )}
      </span>
    </li>
  )
}

const EVENT_LABEL: Record<string, string> = {
  detected: 'Detected',
  updated: 'Updated',
  no_longer_detected: 'No longer detected',
  withdrawn: 'Withdrawn',
  reexposed: 'Re-exposed',
}

function formatWhen(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** The events, current risk, and risk history for one occurrence, loaded lazily when a row expands. */
function OccurrenceDetail({ engagementId, occurrenceId }: { engagementId: string; occurrenceId: string }) {
  const { data, loading, error } = useParallelFetch<[VulnerabilityOccurrenceEvent[], VulnerabilityAssessment | null, VulnerabilityAssessment[]]>(
    () => Promise.all([
      api.engagementVulnerabilityOccurrenceEvents(engagementId, occurrenceId),
      api.engagementVulnerabilityOccurrenceRisk(engagementId, occurrenceId),
      api.engagementVulnerabilityOccurrenceRiskHistory(engagementId, occurrenceId),
    ]),
    { deps: [engagementId, occurrenceId] },
  )
  if (loading) return <div className="px-1 py-2 text-xs text-tertiary">Loading occurrence detail…</div>
  if (error) return <div className="px-1 py-2"><ErrorState message={error} /></div>
  const [events, risk, history] = data ?? [[], null, []]
  return (
    <div className="space-y-3 rounded-lg bg-secondary/30 p-3">
      {risk ? (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <SevBadge sev={(risk.severity as Severity) || 'info'} />
          <span className="text-xs text-tertiary">risk <span className="font-mono tabular-nums text-secondary">{risk.riskScore.toFixed(1)}</span></span>
          <span className="text-xs text-tertiary">priority <span className="font-mono tabular-nums text-secondary">{risk.priority}</span></span>
          <span className="text-xs text-tertiary">CVSS <span className="font-mono tabular-nums text-secondary">{risk.cvssScore.toFixed(1)}</span></span>
          {risk.kev && <Pill className="text-error-primary">KEV</Pill>}
          {risk.epss > 0 && <span className="text-xs text-tertiary">EPSS <span className="font-mono tabular-nums text-secondary">{(risk.epss * 100).toFixed(1)}%</span></span>}
          {risk.reachability && <Pill>{risk.reachability}</Pill>}
          {risk.reasonCodes.length > 0 && <span className="flex flex-wrap gap-1">{risk.reasonCodes.map((c) => <Pill key={c} className="font-mono">{c}</Pill>)}</span>}
        </div>
      ) : (
        <p className="text-xs text-tertiary">No risk assessment recorded for this occurrence yet.</p>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-quaternary">Events</h4>
          {events.length === 0 ? (
            <p className="text-xs text-tertiary">No lifecycle events.</p>
          ) : (
            <ol className="space-y-1">
              {events.map((e) => (
                <li key={e.id} className="flex flex-wrap items-baseline gap-x-2 text-xs">
                  <span className="font-medium text-primary">{EVENT_LABEL[e.eventType] ?? e.eventType}</span>
                  {e.fromState && e.toState && <span className="text-tertiary">{e.fromState} → {e.toState}</span>}
                  <span className="ml-auto tabular-nums text-quaternary">{formatWhen(e.createdAt)}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
        <div>
          <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-quaternary">Risk history</h4>
          {history.length === 0 ? (
            <p className="text-xs text-tertiary">No prior assessments.</p>
          ) : (
            <ol className="space-y-1">
              {history.map((h) => (
                <li key={h.id} className="flex flex-wrap items-baseline gap-x-2 text-xs">
                  <span className="font-mono tabular-nums text-secondary">risk {h.riskScore.toFixed(1)}</span>
                  <span className="text-tertiary">priority {h.priority}</span>
                  <span className="ml-auto tabular-nums text-quaternary">{formatWhen(h.assessedAt)}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  )
}

function OccurrenceRow({ o, engagementId }: { o: VulnerabilityOccurrence; engagementId: string }) {
  const [open, setOpen] = useState(false)
  return (
    <li className="border-t border-secondary/60 first:border-t-0">
      <button type="button" className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 py-2 text-left" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <ChevronDown className={cn('size-3.5 shrink-0 text-quaternary transition-transform', open && 'rotate-180')} aria-hidden />
        <span className="font-mono text-xs font-semibold text-primary">{o.advisoryId}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-tertiary" title={`${o.packageName}@${o.componentVersion}`}>
          {o.packageName}
          {o.componentVersion ? `@${o.componentVersion}` : ''}
        </span>
        {o.ecosystem && <Pill>{o.ecosystem}</Pill>}
        {o.fixedVersion && <Pill className="text-success-primary">fix {o.fixedVersion}</Pill>}
        {o.reachability && o.reachability !== 'unknown' && <Pill className="text-error-primary">{o.reachability}</Pill>}
        <span className={cn('text-xs font-semibold', occStateTone(o.state))}>{o.state}</span>
      </button>
      {open && <div className="pb-3"><OccurrenceDetail engagementId={engagementId} occurrenceId={o.id} /></div>}
    </li>
  )
}

export function VulnPostureTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error } = useParallelFetch<[VulnerabilityAction[], VulnerabilityOccurrence[]]>(
    () => Promise.all([api.engagementVulnerabilityActions(engagementId), api.engagementVulnerabilityOccurrences(engagementId)]),
    { deps: [engagementId] },
  )

  const [actions, setActions] = useState<VulnerabilityAction[]>([])
  useEffect(() => {
    if (data) setActions(data[0])
  }, [data])

  const occurrences = data?.[1] ?? []
  const sortedActions = useMemo(
    () => [...actions].sort((a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)),
    [actions],
  )
  const openCount = actions.filter((a) => a.status === 'open').length

  const [pending, setPending] = useState<Set<string>>(() => new Set())
  const [mutErr, setMutErr] = useState('')

  async function move(action: VulnerabilityAction, kind: 'ack' | 'resolve') {
    // Track pending per action id so two concurrent mutations do not clear each other's busy state,
    // and both buttons on a row stay disabled until that action's own request settles.
    setPending((prev) => new Set(prev).add(action.id))
    setMutErr('')
    try {
      const updated =
        kind === 'ack'
          ? await api.acknowledgeVulnerabilityAction(engagementId, action.id)
          : await api.resolveVulnerabilityAction(engagementId, action.id)
      setActions((prev) => prev.map((x) => (x.id === updated.id ? updated : x)))
    } catch (e) {
      setMutErr(e instanceof Error ? e.message : 'action failed')
    } finally {
      setPending((prev) => {
        const next = new Set(prev)
        next.delete(action.id)
        return next
      })
    }
  }

  if (loading) return <Spinner label="Loading vulnerability posture…" />
  if (error) return <ErrorState message={error} />
  if (actions.length === 0 && occurrences.length === 0)
    return (
      <EmptyState
        icon={ShieldTick}
        title="No reconciled vulnerabilities yet"
        hint="Once vulnerability reconciliation matches advisories to this engagement's components, the occurrences and their governed action queue appear here."
      />
    )

  return (
    <div className="space-y-6">
      <Card
        title="Action queue"
        actions={<span className="text-xs text-tertiary">{openCount} open</span>}
      >
        <div aria-live="polite">{mutErr && <ErrorState message={mutErr} />}</div>
        {sortedActions.length === 0 ? (
          <div className="flex items-center gap-2 text-sm text-tertiary">
            <CheckCircle className="size-4 text-success-primary" aria-hidden />
            No vulnerability actions for this engagement.
          </div>
        ) : (
          <ul>
            {sortedActions.map((a) => (
              <ActionRow
                key={a.id}
                action={a}
                busy={pending.has(a.id)}
                onAck={() => move(a, 'ack')}
                onResolve={() => move(a, 'resolve')}
              />
            ))}
          </ul>
        )}
      </Card>

      <Card
        title="Reconciled occurrences"
        actions={<span className="inline-flex items-center gap-1.5 text-xs text-tertiary"><Package className="size-3.5" aria-hidden />{occurrences.length}</span>}
      >
        {occurrences.length === 0 ? (
          <p className="text-sm text-tertiary">No reconciled occurrences matched to this engagement.</p>
        ) : (
          <ul>
            {occurrences.map((o) => (
              <OccurrenceRow key={o.id} o={o} engagementId={engagementId} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
