import { Play, RefreshCw01, ShieldTick, Zap } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError, type ResponseKind, type ResponsePlan, type ResponseRecord, type ResponseFingerprint } from '../../lib/api'
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
  violation: 'text-error-primary',
  cancelled: 'text-tertiary',
}

export function ResponseOps() {
  const [records, setRecords] = useState<ResponseRecord[] | null | undefined>(undefined)
  const [unsupported, setUnsupported] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const loadGeneration = useRef(0)
  const mounted = useRef(false)

  const load = useCallback(async () => {
    if (!mounted.current) return
    const generation = ++loadGeneration.current
    try {
      const lists = await Promise.all((['pending', 'applied', 'reverted', 'cancelled', 'violation'] as const).map((state) => api.listResponses(state)))
      if (generation !== loadGeneration.current) return
      setLoadError(null)
      if (lists.every((rs) => rs === null)) {
        setUnsupported(true)
        setRecords([])
      } else {
        setUnsupported(false)
        setRecords(Array.from(new Map(lists.flatMap((rs) => rs ?? []).map((record) => [record.id, record])).values()))
      }
    } catch (e) {
      if (generation === loadGeneration.current) setLoadError(e instanceof Error ? e.message : 'Failed to load responses')
    }
  }, [])

  useEffect(() => { mounted.current = true; void load(); return () => { mounted.current = false; loadGeneration.current++ } }, [load])

  const hasOutstanding = records?.some((record) =>
    record.state === 'pending' || record.approvalState === 'pending' || record.verification === 'pending' ||
    (record.state === 'applied' && (!record.verification || (record.reversalRequestedBy &&
      (record.approvalState === 'approved' || record.approvalState === 'consumed')))),
  ) ?? false
  useEffect(() => {
    if (!hasOutstanding) return
    let stopped = false
    let timer: ReturnType<typeof setTimeout>
    const schedule = () => { timer = setTimeout(async () => { await load(); if (!stopped) schedule() }, 10000) }
    schedule()
    return () => { stopped = true; clearTimeout(timer) }
  }, [hasOutstanding, load])

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
        <div className="flex flex-wrap items-center gap-2"><Button variant="secondary" onClick={() => void load()}><RefreshCw01 className="size-4" /> Refresh responses</Button><KillSwitch /></div>
      </header>

      <div className="rounded-lg border border-utility-orange-300 bg-warning-primary px-4 py-3 text-sm text-warning-primary">
        Host effects depend on the configured executor. Check verification before treating an action as effective.
        Reverting a stopped process attempts a best-effort restart; it cannot restore the original process state.
      </div>

      {unsupported && loadError && <ErrorState message={loadError} />}
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
  const [asset, setAsset] = useState('')
  const [plan, setPlan] = useState<{ result: ResponsePlan; engagementId: string; body: { kind: ResponseKind; target: string; target_kind?: string; fingerprint?: ResponseFingerprint } } | null>(null)
  const generation = useRef(0)
  const [busy, setBusy] = useState(false)
  const [applyResult, setApplyResult] = useState<{ record: ResponseRecord; pending: boolean } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [engagementError, setEngagementError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    api.listEngagements().then((es) => {
      if (!live) return
      setEngagements(es)
      if (es.length) setEngagementId((current) => current || es[0].id)
    }).catch((e) => { if (live) setEngagementError(e instanceof Error ? e.message : 'Failed to load engagements') })
    return () => { live = false }
  }, [])

  const validProcess = /^pe_[0-9a-f]{32}$/.test(target) && asset.trim() !== '' && asset === asset.trim()
  const canPlan = engagementId !== '' && target.trim() !== '' && (kind !== 'stop_process' || validProcess) && !busy
  const invalidate = () => { generation.current++; setPlan(null); setApplyResult(null); setError(null) }
  useEffect(() => () => { generation.current++ }, [])

  const doPlan = async () => {
    if (!canPlan) return
    const current = ++generation.current
    const body = kind === 'stop_process'
      ? { kind, target, target_kind: 'process', fingerprint: { kind: 'process', process_asset_id: asset, process_entity_id: target } }
      : { kind, target: target.trim() }
    const selectedEngagement = engagementId
    setBusy(true); setError(null); setApplyResult(null); setPlan(null)
    try {
      const result = await api.planResponse(selectedEngagement, body)
      if (current === generation.current) setPlan({ result, engagementId: selectedEngagement, body })
    } catch (e) {
      if (current === generation.current) setError(e instanceof Error ? e.message : 'Plan failed')
    } finally { setBusy(false) }
  }

  const doApply = async () => {
    if (!plan || busy) return
    const current = generation.current
    setBusy(true); setError(null)
    try {
      const { record, pending } = await api.applyResponse(plan.engagementId, plan.body)
      if (current === generation.current) { setApplyResult({ record, pending }); setPlan(null) }
      onApplied()
    } catch (e) {
      if (current === generation.current) setError(e instanceof Error ? e.message : 'Apply failed')
    } finally { setBusy(false) }
  }

  return (
    <Card title="Plan a response">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="Engagement" htmlFor="ro-eng">
          <Select id="ro-eng" value={engagementId} onValueChange={(v) => { invalidate(); setEngagementId(v) }} ariaLabel="Engagement"
            options={engagements.map((e) => ({ value: e.id, label: e.name || e.id }))} placeholder="Select an engagement" />
        </Field>
        <Field label="Action" htmlFor="ro-kind">
          <Select id="ro-kind" value={kind} onValueChange={(v) => { invalidate(); setKind(v as ResponseKind) }} ariaLabel="Response action"
            options={KINDS} />
        </Field>
        <Field label={kind === 'stop_process' ? 'Process entity ID' : 'Target'} htmlFor="ro-target" hint={kind === 'stop_process' ? 'Exact pe_ ID followed by 32 lowercase hexadecimal characters.' : 'A target in the engagement scope.'}>
        <Input id="ro-target" aria-describedby="ro-target-hint" value={target} onChange={(e) => { invalidate(); setTarget(e.target.value) }} placeholder={kind === 'stop_process' ? 'pe_…' : 'asset-id or host'} spellCheck={false} />
        </Field>
        {kind === 'stop_process' && <Field label="Process asset ID" htmlFor="ro-asset" hint="The asset reporting this process."><Input id="ro-asset" aria-describedby="ro-asset-hint" value={asset} onChange={(e) => { invalidate(); setAsset(e.target.value) }} spellCheck={false} /></Field>}
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
      {engagementError && <div className="mt-3"><ErrorState message={engagementError} /></div>}
      {error && <div className="mt-3"><ErrorState message={error} /></div>}
      {applyResult && (
        <div className={cn('mt-4 rounded-lg border p-4 text-sm',
          applyResult.pending ? 'border-warning-primary bg-warning-secondary' : 'border-utility-green-300 bg-success-secondary')}>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className={cn('font-semibold', applyResult.pending ? 'text-warning-primary' : 'text-success-primary')}>
              {applyResult.record.verification === 'pending' ? 'Applied, awaiting verification' : applyResult.pending ? 'Recorded, awaiting a second human approval' : 'Action recorded; check approval and verification'}
            </span>
            <span className="font-mono text-xs text-tertiary">action {applyResult.record.id}</span>
            {applyResult.record.evidenceId && <span className="font-mono text-xs text-tertiary">evidence {applyResult.record.evidenceId}</span>}
          </div>
          <p className="mt-1 text-xs text-tertiary">
            {applyResult.pending
              ? 'A reviewer approves it from the actions ledger below; the kill switch can cancel a pending action.'
              : 'Check the verification result in the actions ledger.'}
          </p>
        </div>
      )}
      {plan && (
        <div className="mt-4 rounded-lg border border-secondary bg-secondary/30 p-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-tertiary">Plan (executes nothing and does not authorize the target)</p>
          {plan.body.fingerprint?.process_asset_id && <p className="mb-2 text-xs text-secondary">Process {plan.body.target} on asset {plan.body.fingerprint.process_asset_id}; scope kind process.</p>}
          <ol className="space-y-2">
            {plan.result.steps.map((s, i) => (
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
  const states = useMemo(() => ['all', 'pending', 'applied', 'reverted', 'cancelled', 'violation'], [])
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
                  <td className="px-3 py-2.5 font-mono text-xs text-tertiary"><div title={r.target}>{r.target}</div><div>Scope: {r.targetKind || 'unavailable'}</div>{r.fingerprint?.process_asset_id && <div>Asset: {r.fingerprint.process_asset_id}</div>}</td>
                  <td className={cn('px-3 py-2.5 text-xs font-semibold capitalize', STATE_TONE[r.state] ?? 'text-tertiary')}>{r.state}{r.reversalRequestedBy && <div>Reversal requested by {r.reversalRequestedBy}</div>}<div>{r.reversalRequestedBy ? 'Reversal approval' : 'Approval'}: {r.approvalState || 'unavailable'}</div></td>
                  <td className="px-3 py-2.5 text-xs text-tertiary">{r.verification || (r.state === 'applied' ? 'Not yet verified' : '—')}</td>
                  <td className="px-3 py-2.5 text-xs text-tertiary">{r.approver || '—'}{r.submittedBy && <div>Submitted by {r.submittedBy}</div>}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-tertiary" title={r.evidenceId}>{r.evidenceId || '—'}</td>
                  <td className="px-4 py-2.5 text-right">
                    {r.approvalState === 'pending' && (r.state === 'pending' && !r.reversalRequestedBy || r.state === 'applied' && r.reversalRequestedBy) && <DecisionControls record={r} onDone={onChanged} />}
                    {r.state === 'applied' && !r.reversalRequestedBy && <RevertButton record={r} onDone={onChanged} />}
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
  const [error, setError] = useState<string | null>(null)
  const fingerprint = record.fingerprint
  const validBinding = Boolean(record.targetKind && fingerprint && (
    record.kind === 'stop_process' ? record.targetKind === 'process' && fingerprint.kind === 'process' && fingerprint.process_asset_id && fingerprint.process_entity_id === record.target && /^pe_[0-9a-f]{32}$/.test(record.target)
      : record.kind === 'isolate_host' ? fingerprint.kind === 'host' && fingerprint.host_id === record.target && Number.isSafeInteger(fingerprint.netpol_generation) && (fingerprint.netpol_generation ?? 0) > 0
        : record.kind === 'quarantine_file' && fingerprint.kind === 'file' && fingerprint.file_path === record.target &&
          (Boolean(fingerprint.file_hash) || (Number.isSafeInteger(fingerprint.file_device) && (fingerprint.file_device ?? 0) > 0 && Number.isSafeInteger(fingerprint.file_inode) && (fingerprint.file_inode ?? 0) > 0)) &&
          (fingerprint.file_device === undefined || Number.isSafeInteger(fingerprint.file_device)) && (fingerprint.file_inode === undefined || Number.isSafeInteger(fingerprint.file_inode))
  ))
  const revert = async () => {
    if (!validBinding || !fingerprint || !record.targetKind || busy) return
    if (!window.confirm(`Revert ${record.kind} on ${record.target}? The reversal is itself an audited, approved action.`)) return
    setBusy(true); setError(null)
    try {
      await api.revertResponse(record.id, { target: record.target, target_kind: record.targetKind, fingerprint })
      onDone()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Revert failed')
    } finally { setBusy(false) }
  }
  return (
    <div><Button variant="secondary" onClick={revert} loading={busy} disabled={!validBinding} className="text-xs">
      <RefreshCw01 className="size-3.5" /> Revert
    </Button>{!validBinding && <p className="text-xs text-error-primary">Target binding unavailable; cannot revert.</p>}{error && <p role="alert" className="text-xs text-error-primary">{error}</p>}</div>
  )
}

function DecisionControls({ record, onDone }: { record: ResponseRecord; onDone: () => void }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function decide(approve: boolean) {
    if (busy) return
    setBusy(true); setError(null)
    try {
      await api.decideResponse(record.id, { approve, reason: reason.trim() })
      onDone()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Decision failed')
    } finally { setBusy(false) }
  }
  return <div className="space-y-1"><Input aria-label={`Decision reason for ${record.id}`} placeholder="Decision reason" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} /><div className="flex gap-1"><Button variant="secondary" disabled={busy} onClick={() => decide(true)}>Approve</Button><Button variant="secondary" disabled={busy} onClick={() => decide(false)}>Deny</Button></div>{error && <p role="alert" className="text-xs text-error-primary">{error}</p>}</div>
}

export default ResponseOps
