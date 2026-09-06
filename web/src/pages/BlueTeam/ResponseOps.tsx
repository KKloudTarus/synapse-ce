import { Play, RefreshCw01, ShieldTick, Zap } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ApiError, type ResponseKind, type ResponsePlan, type ResponseRecord } from '../../lib/api'
import type { Engagement } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'

const KINDS: { value: ResponseKind; label: string }[] = [
  { value: 'isolate_host', label: 'Isolate host' },
  { value: 'quarantine_file', label: 'Quarantine file' },
  { value: 'stop_process', label: 'Stop process' },
]

const STATE_TONE: Record<string, string> = {
  applied: 'text-success-primary',
  pending: 'text-warning-primary',
  reverted: 'text-tertiary',
  failed: 'text-error-primary',
  expired: 'text-tertiary',
}

/**
 * Blue-team governed response operations (#425). Plan (dry run) → apply through the admission gate + human
 * approval → verify → revert, all audited. The executor is a SIMULATION today (no host effect); the page states
 * that plainly so an operator never assumes containment happened. Also carries the fleet-wide offensive kill
 * switch. Routes register only when the fleet subsystem is enabled.
 */
export function ResponseOps() {
  const [records, setRecords] = useState<ResponseRecord[] | null | undefined>(undefined)
  const [unsupported, setUnsupported] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoadError(null)
    api
      .listResponses()
      .then((rs) => {
        if (rs === null) {
          setUnsupported(true)
          setRecords([])
        } else {
          setUnsupported(false)
          setRecords(rs)
        }
      })
      .catch((e) => setLoadError(e instanceof Error ? e.message : 'Failed to load responses'))
  }, [])

  useEffect(() => load(), [load])

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Response operations</h1>
          <p className="mt-1 max-w-3xl text-sm text-secondary">
            Plan, approve, apply, and revert a governed containment action. Every action passes the same admission
            gate and human approval as an offensive step and is sealed to the evidence ledger.
          </p>
        </div>
        <KillSwitch />
      </header>

      <div className="rounded-lg border border-warning-primary bg-warning-secondary px-4 py-3 text-sm text-warning-primary">
        <span className="font-semibold">Executor is simulation.</span> The governance workflow is real and audited,
        but the current executor makes no change on any host. Containment takes effect once a host executor is wired.
      </div>

      {unsupported ? (
        <EmptyState
          icon={ShieldTick}
          title="Governed response is not enabled on this deployment"
          hint="Enable the fleet subsystem (SYNAPSE_FLEET_ENABLED) to plan and apply responses."
        />
      ) : (
        <>
          <PlanApply onApplied={load} />
          <ResponseList records={records} loadError={loadError} onChanged={load} />
        </>
      )}
    </div>
  )
}

function KillSwitch() {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const halt = async () => {
    if (!window.confirm('Halt ALL offensive work fleet-wide? Running work orders and exploitation chains stop immediately.')) return
    setBusy(true)
    setResult(null)
    try {
      const r = await api.haltOffensive('operator halt from console')
      setResult(r.halted ? `Halted (${r.durationMs} ms)` : 'Halt reported incomplete')
    } catch (e) {
      setResult(e instanceof ApiError ? e.message : 'Halt failed')
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex flex-col items-end gap-1">
      <Button variant="secondary" onClick={halt} loading={busy} className="border-error text-error-primary hover:bg-error-primary">
        <Zap className="size-4" /> Halt offensive work
      </Button>
      {result && <span className="text-xs text-tertiary">{result}</span>}
    </div>
  )
}

function PlanApply({ onApplied }: { onApplied: () => void }) {
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [engagementId, setEngagementId] = useState('')
  const [kind, setKind] = useState<ResponseKind>('isolate_host')
  const [target, setTarget] = useState('')
  const [plan, setPlan] = useState<ResponsePlan | null>(null)
  const [busy, setBusy] = useState(false)
  const [applyResult, setApplyResult] = useState<{ record: ResponseRecord; pending: boolean } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.listEngagements().then((es) => {
      setEngagements(es)
      if (es.length && !engagementId) setEngagementId(es[0].id)
    }).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const canPlan = engagementId !== '' && target.trim() !== '' && !busy

  const doPlan = async () => {
    setBusy(true); setError(null); setApplyResult(null); setPlan(null)
    try {
      setPlan(await api.planResponse(engagementId, { kind, target: target.trim() }))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Plan failed')
    } finally { setBusy(false) }
  }

  const doApply = async () => {
    setBusy(true); setError(null)
    try {
      const { record, pending } = await api.applyResponse(engagementId, { kind, target: target.trim() })
      setApplyResult({ record, pending })
      setPlan(null)
      onApplied()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Apply failed')
    } finally { setBusy(false) }
  }

  return (
    <Card title="Plan a response">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="Engagement" htmlFor="ro-eng">
          <Select id="ro-eng" value={engagementId} onValueChange={setEngagementId} ariaLabel="Engagement"
            options={engagements.map((e) => ({ value: e.id, label: e.name || e.id }))} placeholder="Select an engagement" />
        </Field>
        <Field label="Action" htmlFor="ro-kind">
          <Select id="ro-kind" value={kind} onValueChange={(v) => setKind(v as ResponseKind)} ariaLabel="Response action"
            options={KINDS} />
        </Field>
        <Field label="Target" htmlFor="ro-target" hint="An asset id in the engagement scope.">
          <Input id="ro-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="asset-id or host" spellCheck={false} />
        </Field>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <Button variant="secondary" onClick={doPlan} disabled={!canPlan}>
          <RefreshCw01 className="size-4" /> Plan (dry run)
        </Button>
        {plan && (
          <Button onClick={doApply} loading={busy}>
            <Play className="size-4" /> Apply through the gate
          </Button>
        )}
      </div>
      {error && <div className="mt-3"><ErrorState message={error} /></div>}
      {applyResult && (
        <div className={cn('mt-4 rounded-lg border p-4 text-sm',
          applyResult.pending ? 'border-warning-primary bg-warning-secondary' : 'border-utility-green-300 bg-success-secondary')}>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className={cn('font-semibold', applyResult.pending ? 'text-warning-primary' : 'text-success-primary')}>
              {applyResult.pending ? 'Recorded — awaiting a second human approval' : 'Applied through the admission gate'}
            </span>
            <span className="font-mono text-xs text-tertiary">action {applyResult.record.id}</span>
            {applyResult.record.evidenceId && <span className="font-mono text-xs text-tertiary">evidence {applyResult.record.evidenceId}</span>}
          </div>
          <p className="mt-1 text-xs text-tertiary">
            {applyResult.pending
              ? 'A reviewer approves it from the actions ledger below; the kill switch can cancel a pending action.'
              : 'The executor is simulation, so no host changed. It is reversible from the ledger below.'}
          </p>
        </div>
      )}
      {plan && (
        <div className="mt-4 rounded-lg border border-secondary bg-secondary/30 p-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-tertiary">Plan (executes nothing)</p>
          <ol className="space-y-2">
            {plan.steps.map((s, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="mt-0.5 font-mono text-xs text-quaternary">{i + 1}</span>
                <div className="min-w-0">
                  <div className="text-primary">{s.label} <Pill className="ml-1">{s.blastRadius}</Pill></div>
                  <div className="truncate font-mono text-xs text-tertiary" title={s.argv.join(' ')}>{s.argv.join(' ')}</div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </Card>
  )
}

function ResponseList({ records, loadError, onChanged }: { records: ResponseRecord[] | null | undefined; loadError: string | null; onChanged: () => void }) {
  const [filter, setFilter] = useState<string>('all')
  const states = useMemo(() => ['all', 'pending', 'applied', 'reverted', 'failed'], [])
  const visible = (records ?? []).filter((r) => filter === 'all' || r.state === filter)

  return (
    <Card
      title="Response actions"
      actions={
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by state">
          {states.map((s) => (
            <button key={s} type="button" aria-pressed={filter === s} onClick={() => setFilter(s)}
              className={cn('rounded-md px-2.5 py-1 text-xs font-semibold capitalize transition-colors',
                filter === s ? 'bg-secondary text-primary ring-1 ring-inset ring-border' : 'text-tertiary hover:bg-secondary')}>
              {s}
            </button>
          ))}
        </div>
      }
      bodyClass="p-0"
    >
      {loadError && <div className="p-4"><ErrorState message={loadError} /></div>}
      {records === undefined && <div className="p-6"><Spinner label="Loading responses…" /></div>}
      {records && visible.length === 0 && !loadError && (
        <div className="p-6"><EmptyState icon={ShieldTick} title="No response actions" hint="Plan and apply one above." /></div>
      )}
      {records && visible.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <thead className="border-b border-secondary text-[11px] font-semibold uppercase tracking-wider text-tertiary">
              <tr>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-3 py-2.5">Target</th>
                <th className="px-3 py-2.5">State</th>
                <th className="px-3 py-2.5">Verification</th>
                <th className="px-3 py-2.5">Approver</th>
                <th className="px-3 py-2.5">Evidence</th>
                <th className="px-4 py-2.5 text-right">&nbsp;</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {visible.map((r) => (
                <tr key={r.id} className="hover:bg-secondary/40">
                  <td className="px-4 py-2.5 font-medium text-primary">{r.kind.replaceAll('_', ' ')}</td>
                  <td className="truncate px-3 py-2.5 font-mono text-xs text-tertiary" title={r.target}>{r.target}</td>
                  <td className={cn('px-3 py-2.5 text-xs font-semibold capitalize', STATE_TONE[r.state] ?? 'text-tertiary')}>{r.state}</td>
                  <td className="px-3 py-2.5 text-xs text-tertiary">{r.verification || '—'}</td>
                  <td className="truncate px-3 py-2.5 text-xs text-tertiary">{r.approver || '—'}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-tertiary" title={r.evidenceId}>{r.evidenceId || '—'}</td>
                  <td className="px-4 py-2.5 text-right">
                    {r.state === 'applied' && <RevertButton record={r} onDone={onChanged} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function RevertButton({ record, onDone }: { record: ResponseRecord; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const revert = async () => {
    if (!window.confirm(`Revert ${record.kind} on ${record.target}? The reversal is itself an audited, approved action.`)) return
    setBusy(true)
    try {
      await api.revertResponse(record.id, { target: record.target })
      onDone()
    } catch (e) {
      window.alert(e instanceof Error ? e.message : 'Revert failed')
      setBusy(false)
    }
  }
  return (
    <Button variant="secondary" onClick={revert} loading={busy} className="text-xs">
      <RefreshCw01 className="size-3.5" /> Revert
    </Button>
  )
}

export default ResponseOps
