import {
  AlertTriangle,
  Calendar,
  CheckCircle,
  ChevronLeft,
  ChevronRight,
  Clock,
  RefreshCcw01,
  ShieldTick,
} from '@untitledui/icons'
import { useMemo, useState } from 'react'
import { Button, Card, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { ApiError, api } from '../../lib/api'
import type { Finding, SLARemediationStatus, SLAView } from '../../lib/types'

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
  low: 'bg-accent/15 text-accent ring-accent/30',
  exception: 'bg-secondary text-tertiary ring-primary',
}

const PAGE_SIZE = 12

function TablePagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
}: {
  page: number
  totalPages: number
  total: number
  pageSize: number
  onPageChange: (p: number) => void
}) {
  if (totalPages <= 1) return null
  const start = (page - 1) * pageSize
  const end = Math.min(start + pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-secondary px-4 py-3">
      <span className="text-xs text-tertiary">
        Showing {start + 1}–{end} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          aria-label="Previous page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronLeft className="size-4" aria-hidden="true" />
        </button>
        <span className="text-xs tabular-nums text-tertiary">
          Page {page} of {totalPages}
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages}
          aria-label="Next page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}

export function SLATab({ engagementId, findings }: { engagementId: string; findings: Finding[] | null }) {
  const [disabled, setDisabled] = useState(false)
  const [selected, setSelected] = useState<SLAView | null>(null)
  const [localItems, setLocalItems] = useState<SLAView[] | null>(null)
  const [page, setPage] = useState(1)

  const { data: fetchedItems, error, refetch } = useFetch<SLAView[]>(
    async () => {
      try {
        return await api.slas(engagementId)
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          setDisabled(true)
          return []
        }
        throw err
      }
    },
    { deps: [engagementId] },
  )

  const items = localItems ?? fetchedItems

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
    return (
      <EmptyState
        icon={Calendar}
        title="Remediation SLA is not enabled"
        hint="Set SYNAPSE_SLA_ENABLED=true to create governed, versioned deadlines for findings."
      />
    )
  }
  if (items.length === 0) {
    return (
      <EmptyState
        icon={CheckCircle}
        title="No SLA assessments yet"
        hint="Run a scan after enabling SLA governance. Existing findings are unchanged until explicitly reassessed."
      />
    )
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Overdue"
          value={stats.overdue}
          icon={AlertTriangle}
          tone={stats.overdue > 0 ? 'text-critical' : 'text-tertiary'}
        />
        <Stat
          label="Emergency"
          value={stats.emergency}
          icon={Clock}
          tone={stats.emergency > 0 ? 'text-critical' : 'text-tertiary'}
        />
        <Stat label="Accepted risk" value={stats.accepted} icon={ShieldTick} tone="text-medium" />
        <Stat label="Remediated" value={stats.remediated} icon={CheckCircle} tone="text-accent" />
      </div>

      <Card
        title="Risk-based remediation deadlines"
        actions={
          <Button variant="secondary" onClick={() => void refetch()} className="px-3 py-1.5">
            <RefreshCcw01 className="size-3.5" /> Refresh
          </Button>
        }
        bodyClass="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-secondary bg-secondary text-xs uppercase tracking-wide text-quaternary">
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
            <tbody className="divide-y divide-secondary">
              {items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((item) => {
                const finding = findingByID.get(item.assessment.findingId)
                return (
                  <tr
                    key={item.assessment.findingId}
                    className={cn('hover:bg-secondary/60', item.overdue && 'bg-critical/5')}
                  >
                    <td className="max-w-sm px-5 py-4">
                      <div className="truncate font-medium text-primary">
                        {finding?.title ?? item.assessment.findingId}
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-quaternary">{item.assessment.findingId}</div>
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={cn(
                          'inline-flex rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ring-inset',
                          TIER_STYLE[item.assessment.result.tier],
                        )}
                      >
                        {item.assessment.result.tier}
                      </span>
                      <span className="ml-2 font-mono tabular-nums text-tertiary">
                        {item.assessment.result.score.toFixed(1)}
                      </span>
                    </td>
                    <Deadline value={item.assessment.result.mitigateBy} />
                    <Deadline value={item.assessment.result.remediateBy} overdue={item.overdue} />
                    <td className="px-4 py-4">
                      <div className="font-medium text-primary">{STATUS_LABEL[item.effectiveState]}</div>
                      {item.acceptanceExpired && (
                        <div className="mt-1 text-xs font-semibold text-critical">Acceptance expired</div>
                      )}
                      <div className="mt-1 font-mono text-[11px] text-quaternary">v{item.lifecycle.version}</div>
                    </td>
                    <td className="px-4 py-4 font-mono text-xs text-tertiary">{item.assessment.result.configVersion}</td>
                    <td className="px-5 py-4 text-right">
                      <Button
                        variant="secondary"
                        className="px-3 py-1.5"
                        onClick={() => setSelected(item)}
                        disabled={item.effectiveState === 'remediated'}
                      >
                        Transition
                      </Button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <TablePagination
          page={page}
          totalPages={Math.max(1, Math.ceil(items.length / PAGE_SIZE))}
          total={items.length}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
        />
      </Card>

      {selected && (
        <TransitionPanel
          item={selected}
          findingTitle={findingByID.get(selected.assessment.findingId)?.title ?? selected.assessment.findingId}
          onClose={() => setSelected(null)}
          onSaved={(updated) => {
            setLocalItems((current) =>
              ((current ?? fetchedItems) ?? []).map((item) =>
                item.assessment.findingId === updated.assessment.findingId ? updated : item,
              ),
            )
            setSelected(null)
          }}
        />
      )}
    </div>
  )
}

function Stat({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string
  value: number
  icon: typeof AlertTriangle
  tone: string
}) {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-quaternary">
        <Icon className={cn('size-4', tone)} />
        {label}
      </div>
      <div className={cn('mt-2 font-mono text-2xl font-semibold tabular-nums', tone)}>{value}</div>
    </div>
  )
}

function Deadline({ value, overdue = false }: { value: string; overdue?: boolean }) {
  const date = value ? new Date(value) : null
  return (
    <td
      className={cn(
        'px-4 py-4 font-mono text-xs tabular-nums',
        overdue ? 'font-semibold text-critical' : 'text-tertiary',
      )}
    >
      {date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : '—'}
    </td>
  )
}

function TransitionPanel({
  item,
  findingTitle,
  onClose,
  onSaved,
}: {
  item: SLAView
  findingTitle: string
  onClose: () => void
  onSaved: (item: SLAView) => void
}) {
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
        <label className="text-sm text-tertiary">
          New state
          <select
            value={to}
            onChange={(event) => setTo(event.target.value as SLARemediationStatus)}
            className="mt-1 block w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-primary"
          >
            <option value="open">Open</option>
            <option value="mitigating">Mitigating</option>
            <option value="remediated">Remediated</option>
            <option value="accepted_risk">Accepted risk</option>
          </select>
        </label>
        <label className="text-sm text-tertiary">
          Reason
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Required audit rationale"
            className="mt-1 block w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-primary"
          />
        </label>
        {to === 'accepted_risk' && (
          <>
            <label className="text-sm text-tertiary">
              Compensating control
              <input
                value={control}
                onChange={(event) => setControl(event.target.value)}
                placeholder="Required control"
                className="mt-1 block w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-primary"
              />
            </label>
            <label className="text-sm text-tertiary">
              Acceptance expires
              <input
                type="datetime-local"
                value={expiry}
                onChange={(event) => setExpiry(event.target.value)}
                className="mt-1 block w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-primary"
              />
            </label>
          </>
        )}
      </div>
      {error && (
        <div className="mt-4">
          <ErrorState message={error} />
        </div>
      )}
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          loading={saving}
          onClick={() => void save()}
          disabled={!reason.trim() || (to === 'accepted_risk' && (!control.trim() || !expiry))}
        >
          Save transition
        </Button>
      </div>
    </Card>
  )
}
