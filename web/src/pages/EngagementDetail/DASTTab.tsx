import { useState } from 'react'
import { Play, ShieldZap, Target04 } from '@untitledui/icons'
import { Button, Card, ErrorState, Field, InfoNote, Input, Pill, Select, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { DastProposal, DastScanInput, DastScanResult, RuntimeVerifyInput, RuntimeVerifyOutcome } from '../../lib/api'
import type { Judgment } from '../../lib/types'

// Judgment capabilities whose exploitability claim a live probe can confirm or refute.
const PROBEABLE = new Set(['sast', 'dast', 'reachability'])

function decisionTone(state: string): string {
  switch (state) {
    case 'approved':
      return 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25'
    case 'denied':
    case 'timeout':
      return 'bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25'
    case 'consumed':
      return 'bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25'
    default:
      return 'bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25'
  }
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col">
      <span className="text-lg font-semibold tabular-nums text-primary">{value.toLocaleString()}</span>
      <span className="text-[11px] uppercase tracking-wide text-quaternary">{label}</span>
    </div>
  )
}

/** Propose, approve, and run a live runtime-verification probe against a specific judgment's claim. */
function RuntimeVerifyCard({ engagementId, canOperate, canReview }: { engagementId: string; canOperate: boolean; canReview: boolean }) {
  const { data: judgments } = useFetch<Judgment[]>(() => api.judgments(engagementId), { deps: [engagementId] })
  const probeable = (judgments ?? []).filter((j) => PROBEABLE.has(j.capability))
  const { notify } = useToast()

  const [judgmentId, setJudgmentId] = useState('')
  const [input, setInput] = useState<RuntimeVerifyInput>({ url: '', method: 'GET', expectedStatus: 200, expectedBodyContains: '', scoreIfConfirmed: 90, scoreIfRefuted: 10, version: 0, rationale: '' })
  const [proposal, setProposal] = useState<DastProposal | null>(null)
  const [outcome, setOutcome] = useState<RuntimeVerifyOutcome | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [reason, setReason] = useState('')

  const selected = probeable.find((j) => j.id === judgmentId) ?? null

  function patch(p: Partial<RuntimeVerifyInput>) {
    setInput((cur) => ({ ...cur, ...p }))
  }

  async function propose() {
    if (!selected) return
    setBusy(true)
    setErr('')
    setOutcome(null)
    try {
      const p = await api.proposeRuntimeVerification(engagementId, selected.id, { ...input, version: selected.version })
      setProposal(p)
      notify('Runtime verification proposed.', 'success')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'Could not propose the probe'
      setErr(m); notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function decide(approve: boolean) {
    if (!proposal) return
    setBusy(true); setErr('')
    try {
      const d = await api.decideDastApproval(engagementId, proposal.actionId, approve, reason.trim())
      setProposal({ ...proposal, decisionState: d.state, decidedBy: d.decidedBy, decisionReason: d.reason })
      setReason('')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'Could not record the decision'
      setErr(m); notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function run() {
    if (!proposal || !selected) return
    setBusy(true); setErr('')
    try {
      const o = await api.runRuntimeVerification(engagementId, selected.id, proposal.actionId, { ...input, version: selected.version })
      setOutcome(o)
      notify('Runtime verification ran.', 'success')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'The probe failed to run'
      setErr(m); notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Runtime verification"
      titleClassName="flex items-center gap-2"
      actions={
        <InfoNote label="What is this">
          A live HTTP probe that confirms or refutes a specific judgment's exploitability claim. It is
          proposed against the judgment, approved under separation of duties, then run; the verdict adjusts
          the judgment's score.
        </InfoNote>
      }
    >
      {probeable.length === 0 ? (
        <p className="text-sm text-tertiary">No probeable judgments (SAST, DAST, or reachability) are available for this engagement yet.</p>
      ) : (
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Judgment">
              <Select ariaLabel="Judgment to verify" value={judgmentId} onValueChange={setJudgmentId} placeholder="select a judgment" options={probeable.map((j) => ({ value: j.id, label: `${j.capability} · ${j.id.slice(0, 8)}` }))} />
            </Field>
            <Field label="Probe URL">
              <Input value={input.url} onChange={(e) => patch({ url: e.target.value })} placeholder="https://target/path" className="font-mono" aria-label="Probe URL" />
            </Field>
            <Field label="Method">
              <Select ariaLabel="Probe method" value={input.method} onValueChange={(v) => patch({ method: v })} options={[{ value: 'GET', label: 'GET' }, { value: 'HEAD', label: 'HEAD' }]} />
            </Field>
            <Field label="Expected status">
              <Input type="number" value={input.expectedStatus} onChange={(e) => patch({ expectedStatus: Number(e.target.value) || 0 })} aria-label="Expected status" />
            </Field>
            <Field label="Body contains (optional)">
              <Input value={input.expectedBodyContains} onChange={(e) => patch({ expectedBodyContains: e.target.value })} className="font-mono" aria-label="Expected body contains" />
            </Field>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="primary" loading={busy} disabled={busy || !canOperate || !selected || !input.url.trim()} onClick={propose}>
              <Target04 className="size-4" /> Propose probe
            </Button>
            {!canOperate && <span className="text-xs text-tertiary">Proposing a probe needs the operator role.</span>}
          </div>

          {proposal && (
            <div className="space-y-2 rounded-lg border border-secondary bg-secondary/30 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', decisionTone(proposal.decisionState))}>{proposal.decisionState}</span>
                <span className="font-mono text-[11px] text-quaternary">approval {proposal.actionId}</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {proposal.decisionState === 'pending' && canReview && (
                  <>
                    <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="decision reason" className="w-48" aria-label="Probe decision reason" />
                    <Button variant="primary" loading={busy} disabled={busy} onClick={() => decide(true)}>Approve</Button>
                    <Button variant="secondary" loading={busy} disabled={busy} onClick={() => decide(false)}>Deny</Button>
                  </>
                )}
                {proposal.decisionState === 'pending' && !canReview && <span className="text-xs text-tertiary">Awaiting a reviewer's decision.</span>}
                {(proposal.decisionState === 'approved' || proposal.decisionState === 'consumed') && canOperate && (
                  <Button variant="primary" loading={busy} disabled={busy} onClick={run}><Play className="size-4" /> Run probe</Button>
                )}
              </div>
            </div>
          )}

          {outcome && (
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-secondary p-3 text-sm">
              {outcome.durable && outcome.run ? (
                <>
                  <Pill className="capitalize">{outcome.run.status}</Pill>
                  {outcome.run.verdict && <span className="text-tertiary">verdict {outcome.run.verdict}</span>}
                  <span className="ml-auto font-mono text-[11px] text-quaternary">run {outcome.run.id}</span>
                </>
              ) : (
                <>
                  <Pill className={outcome.proof === 'runtime_confirmed' ? 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25' : outcome.proof === 'runtime_refuted' ? 'bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25' : ''}>{outcome.proof || 'no proof'}</Pill>
                  {outcome.status > 0 && <span className="text-tertiary">HTTP {outcome.status}</span>}
                  {outcome.evidenceId && <span className="ml-auto font-mono text-[11px] text-quaternary">evidence {outcome.evidenceId}</span>}
                </>
              )}
            </div>
          )}
          {err && <ErrorState message={err} />}
        </div>
      )}
    </Card>
  )
}

export function DASTTab({ engagementId }: { engagementId: string }) {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canOperate = me?.role === 'admin' || me?.role === 'consultant' || me?.role === 'member'
  const canReview = me?.role === 'admin' || me?.role === 'reviewer'
  const { notify } = useToast()

  const [input, setInput] = useState<DastScanInput>({ target: '', maxPages: 50, maxRequests: 200, ratePerSec: 2, wallClock: '30s' })
  const [proposal, setProposal] = useState<DastProposal | null>(null)
  const [result, setResult] = useState<DastScanResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [reason, setReason] = useState('')

  function patch(p: Partial<DastScanInput>) {
    setInput((cur) => ({ ...cur, ...p }))
  }

  async function propose() {
    setBusy(true)
    setErr('')
    setResult(null)
    try {
      const p = await api.proposeDastScan(engagementId, input)
      setProposal(p)
      notify('Scan proposed. It needs an approval before it runs.', 'success')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'Could not propose the scan'
      setErr(m)
      notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function decide(approve: boolean) {
    if (!proposal) return
    setBusy(true)
    setErr('')
    try {
      const d = await api.decideDastApproval(engagementId, proposal.actionId, approve, reason.trim())
      setProposal({ ...proposal, decisionState: d.state, decidedBy: d.decidedBy, decisionReason: d.reason })
      setReason('')
      notify(approve ? 'Scan approved.' : 'Scan denied.', 'success')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'Could not record the decision'
      setErr(m)
      notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function run() {
    if (!proposal) return
    setBusy(true)
    setErr('')
    try {
      const r = await api.runDastScan(engagementId, proposal.actionId, input)
      setResult(r)
      notify('Scan complete.', 'success')
    } catch (e) {
      const m = e instanceof Error ? e.message : 'The scan failed to run'
      setErr(m)
      notify(m, 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Card
        title="Authenticated DAST scan"
        titleClassName="flex items-center gap-2"
        actions={
          <InfoNote label="How this works">
            A crawl-and-probe scan of a running target. Every scan is proposed first with an egress preview,
            approved by a reviewer under separation of duties, and only then run. Credentials are referenced
            from the vault, never entered here.
          </InfoNote>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Target URL">
            <Input value={input.target} onChange={(e) => patch({ target: e.target.value })} placeholder="https://staging.example.internal" className="font-mono" aria-label="DAST target URL" />
          </Field>
          <Field label="Max pages">
            <Input type="number" min={1} value={input.maxPages} onChange={(e) => patch({ maxPages: Number(e.target.value) || 1 })} aria-label="Max pages" />
          </Field>
          <Field label="Max requests">
            <Input type="number" min={1} value={input.maxRequests} onChange={(e) => patch({ maxRequests: Number(e.target.value) || 1 })} aria-label="Max requests" />
          </Field>
          <Field label="Rate (req/s)">
            <Input type="number" min={1} value={input.ratePerSec} onChange={(e) => patch({ ratePerSec: Number(e.target.value) || 1 })} aria-label="Rate per second" />
          </Field>
          <Field label="Wall clock">
            <Input value={input.wallClock} onChange={(e) => patch({ wallClock: e.target.value })} placeholder="30s" className="font-mono" aria-label="Wall clock" />
          </Field>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" className="px-3 py-2" loading={busy} disabled={busy || !canOperate || !input.target.trim()} onClick={propose}>
            <Target04 className="size-4" /> Propose scan
          </Button>
          {!canOperate && <span className="text-xs text-tertiary">Proposing a scan needs the operator role.</span>}
        </div>
        {err && <div className="mt-3"><ErrorState message={err} /></div>}
      </Card>

      {proposal && (
        <Card title="Proposal" titleClassName="flex items-center gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', decisionTone(proposal.decisionState))}>{proposal.decisionState}</span>
            {proposal.risk && <Pill className="capitalize">risk: {proposal.risk}</Pill>}
            {proposal.tool && <span className="font-mono text-xs text-tertiary">{proposal.tool}{proposal.action ? ` · ${proposal.action}` : ''}</span>}
          </div>
          {(proposal.targetValue || proposal.egressPreview) && (
            <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
              {proposal.targetValue && <div><dt className="text-[11px] uppercase tracking-wide text-quaternary">Target</dt><dd className="font-mono text-secondary">{proposal.targetKind ? `${proposal.targetKind}: ` : ''}{proposal.targetValue}</dd></div>}
              {proposal.egressPreview && <div><dt className="text-[11px] uppercase tracking-wide text-quaternary">Egress preview</dt><dd className="font-mono text-secondary">{proposal.egressPreview}</dd></div>}
            </dl>
          )}
          {proposal.rationale && <p className="mt-2 text-sm text-tertiary">{proposal.rationale}</p>}
          {proposal.decisionReason && <p className="mt-1 text-xs text-quaternary">decision: {proposal.decisionReason}{proposal.decidedBy ? ` — ${proposal.decidedBy}` : ''}</p>}

          <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-secondary pt-3">
            {proposal.decisionState === 'pending' && canReview && (
              <>
                <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="decision reason" className="w-56" aria-label="Decision reason" />
                <Button variant="primary" loading={busy} disabled={busy} onClick={() => decide(true)}>Approve</Button>
                <Button variant="secondary" loading={busy} disabled={busy} onClick={() => decide(false)}>Deny</Button>
              </>
            )}
            {proposal.decisionState === 'pending' && !canReview && <span className="text-xs text-tertiary">Awaiting a reviewer's decision (separation of duties).</span>}
            {(proposal.decisionState === 'approved' || proposal.decisionState === 'consumed') && canOperate && (
              <Button variant="primary" loading={busy} disabled={busy} onClick={run}><Play className="size-4" /> Run scan</Button>
            )}
          </div>
          <p className="mt-3 font-mono text-[11px] text-quaternary">approval {proposal.actionId}</p>
        </Card>
      )}

      {result && (
        <Card title="Scan result" titleClassName="flex items-center gap-2">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <Stat label="Requests" value={result.requestCount} />
            <Stat label="Coverage entries" value={result.coverageCount} />
            <Stat label="Proofs" value={result.proofs.length} />
            {result.incomplete && <Pill className="bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25">incomplete{result.reason ? `: ${result.reason}` : ''}</Pill>}
          </div>
          {result.proofs.length > 0 && (
            <ul className="mt-3 divide-y divide-secondary">
              {result.proofs.map((p, i) => (
                <li key={`${p.checkId}-${i}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                  <ShieldZap className="size-4 shrink-0 text-brand-secondary" aria-hidden />
                  <span className="text-sm font-medium text-primary">{p.checkId}</span>
                  {p.normalizedEndpoint && <span className="font-mono text-xs text-tertiary">{p.normalizedEndpoint}</span>}
                  {p.hash && <span className="ml-auto font-mono text-[11px] text-quaternary" title={p.hash}>{p.hash.slice(0, 16)}…</span>}
                </li>
              ))}
            </ul>
          )}
          {result.digest && <p className="mt-3 font-mono text-[11px] text-quaternary" title={result.digest}>config {result.digest.slice(0, 16)}…</p>}
        </Card>
      )}

      <RuntimeVerifyCard engagementId={engagementId} canOperate={canOperate} canReview={canReview} />
    </div>
  )
}

export default DASTTab
