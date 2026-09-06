import { useEffect, useMemo, useState } from 'react'
import { CheckCircle, Package, ShieldTick } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { VulnerabilityAction, VulnerabilityOccurrence } from '../../lib/types'

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

function OccurrenceRow({ o }: { o: VulnerabilityOccurrence }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-secondary/60 py-2 first:border-t-0">
      <span className="font-mono text-xs font-semibold text-primary">{o.advisoryId}</span>
      <span className="min-w-0 flex-1 truncate font-mono text-xs text-tertiary" title={`${o.packageName}@${o.componentVersion}`}>
        {o.packageName}
        {o.componentVersion ? `@${o.componentVersion}` : ''}
      </span>
      {o.ecosystem && <Pill>{o.ecosystem}</Pill>}
      {o.fixedVersion && <Pill className="text-success-primary">fix {o.fixedVersion}</Pill>}
      {o.reachability && o.reachability !== 'unknown' && <Pill className="text-error-primary">{o.reachability}</Pill>}
      <span className={cn('text-xs font-semibold', occStateTone(o.state))}>{o.state}</span>
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
              <OccurrenceRow key={o.id} o={o} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
