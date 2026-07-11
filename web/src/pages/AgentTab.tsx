import { Bot, CheckCircle2, Eye, ListChecks, ListTree, Loader2, Network, Play, ShieldAlert, X, Zap, type LucideIcon } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Button, Card, cn, EmptyState, ErrorState, Spinner } from '../components/ui'
import { api, streamAgentSession } from '../lib/api'
import type { AgentDecision, AgentMessage, AgentPlan, AgentReadiness, AgentSession, PendingApproval } from '../lib/types'

// keep at most this many transcript messages in the DOM (bound a long run's growth).
const MAX_TRANSCRIPT = 300

// riskClass / riskIcon map an agent RiskClass to severity tokens + a non-color cue (so risk is
// never conveyed by color alone): read=passive, active=touches hosts, intrusive=exploitation.
const riskClass: Record<string, string> = {
  read: 'bg-low/10 text-low ring-low/25',
  active: 'bg-high/10 text-high ring-high/25',
  intrusive: 'bg-critical/10 text-critical ring-critical/25',
}
const riskIcon: Record<string, LucideIcon> = { read: Eye, active: Zap, intrusive: ShieldAlert }

function statusTone(status: string): string {
  switch (status) {
    case 'succeeded':
      return 'text-accent'
    case 'failed':
    case 'cancelled':
      return 'text-critical'
    case 'awaiting_approval':
      return 'text-medium'
    default:
      return 'text-info'
  }
}

const terminal = (s: string) => s === 'succeeded' || s === 'failed' || s === 'cancelled'

export function AgentTab({ engagementId }: { engagementId: string }) {
  const [sessions, setSessions] = useState<AgentSession[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [goal, setGoal] = useState('')
  const [starting, setStarting] = useState(false)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [approvals, setApprovals] = useState<PendingApproval[]>([])
  const [readiness, setReadiness] = useState<AgentReadiness | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [ss, ap, rd] = await Promise.all([
        api.agentSessions(engagementId),
        api.agentApprovals(engagementId),
        api.agentReadiness(engagementId),
      ])
      setSessions(ss)
      setApprovals(ap)
      setReadiness(rd)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load agent sessions')
    }
  }, [engagementId])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 3000) // approvals + session status appear asynchronously
    return () => clearInterval(t)
  }, [refresh])

  async function startAgent() {
    if (!goal.trim()) return
    setStarting(true)
    try {
      const sess = await api.startAgentSession(engagementId, goal.trim())
      setGoal('')
      setActiveId(sess.id)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start the agent')
    } finally {
      setStarting(false)
    }
  }

  async function decide(actionId: string, approve: boolean) {
    try {
      await api.decideAgentApproval(engagementId, actionId, approve, approve ? 'approved by operator' : 'denied by operator')
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to record the decision')
    }
  }

  if (error) return <ErrorState message={error} />
  if (sessions === null) return <Spinner label="Loading agent sessions…" />

  return (
    <div className="space-y-6">
      <Card title={<span className="flex items-center gap-2"><Bot className="size-4" /> Run an AI agent</span>}>
        <p className="mb-3 text-sm text-mutedfg">
          The agent proposes AppSec workflows – recon, SCA/SAST triage, DAST planning, and attack-path hypotheses.
          Every action is still checked against scope + the authorization window and (per policy) approved before
          anything runs. Tool output is untrusted and every step is sealed into the evidence chain.
        </p>
        {readiness && <ReadinessPanel readiness={readiness} onUseGoal={setGoal} />}
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !e.nativeEvent.isComposing && !starting && startAgent()}
            placeholder="Goal, e.g. “enumerate subdomains of app.example.com and summarize”"
            aria-label="Agent goal"
            className="flex-1 rounded-lg border border-border bg-elevated px-3 py-2 text-sm text-foreground placeholder:text-mutedfg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
          />
          <Button loading={starting} disabled={!goal.trim()} onClick={startAgent} className="px-3 py-2">
            <Play className="size-4" /> Start agent
          </Button>
        </div>
      </Card>

      {approvals.length > 0 && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-medium" /> Approvals required ({approvals.length})
            </span>
          }
        >
          <div className="space-y-3">
            {approvals.map((a) => (
              <ApprovalCard key={a.id} approval={a} onDecide={decide} />
            ))}
          </div>
        </Card>
      )}

      {sessions.length === 0 ? (
        <EmptyState icon={Bot} title="No agent sessions yet" hint="Start one above to begin." />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card title="Sessions" className="lg:col-span-1">
            <ul className="space-y-1">
              {sessions.map((s) => (
                <li key={s.id}>
                  <button
                    onClick={() => setActiveId(s.id)}
                    className={cn(
                      'w-full rounded-md px-3 py-2 text-left text-sm transition-colors',
                      activeId === s.id ? 'bg-raised text-foreground' : 'text-mutedfg hover:bg-muted hover:text-foreground',
                    )}
                  >
                    <div className="truncate font-medium">{s.goal || '(no goal)'}</div>
                    <div className={cn('mt-0.5 text-xs', statusTone(s.status))}>
                      {s.status} · <span className="font-mono tabular-nums">{s.steps}</span> steps
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          <div className="lg:col-span-2">
            {activeId ? (
              <SessionTranscript key={activeId} engagementId={engagementId} sessionId={activeId} onChanged={refresh} />
            ) : (
              <Card title="Transcript">
                <p className="text-sm text-mutedfg">Select a session to view its transcript.</p>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function ReadinessPanel({ readiness, onUseGoal }: { readiness: AgentReadiness; onUseGoal: (goal: string) => void }) {
  const tone =
    readiness.overall === 'ready'
      ? 'border-low/30 bg-low/5 text-low'
      : readiness.overall === 'blocked'
        ? 'border-critical/30 bg-critical/5 text-critical'
        : 'border-medium/30 bg-medium/5 text-medium'
  return (
    <div className="mb-3 rounded-lg border border-border bg-bg p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-sm font-medium text-foreground">
          <ListChecks className="size-4" /> Workflow readiness
        </span>
        <span className={cn('rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 ring-inset', tone)}>
          {readiness.overall}
        </span>
      </div>
      <div className="mb-3 grid gap-2 md:grid-cols-2">
        {readiness.workflows.map((wf) => (
          <button
            key={wf.id}
            type="button"
            onClick={() => onUseGoal(wf.suggested_goal)}
            className={cn(
              'rounded-md border p-2 text-left transition-colors',
              wf.ready ? 'border-low/25 bg-low/5 hover:bg-low/10' : 'border-border bg-elevated hover:bg-muted',
            )}
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-foreground">{wf.label}</span>
              <span className={cn('font-mono text-[10px]', wf.ready ? 'text-low' : 'text-medium')}>
                {wf.ready ? 'ready' : 'needs setup'}
              </span>
            </div>
            <p className="text-xs text-mutedfg">{wf.description}</p>
            {!wf.ready && wf.blockers && wf.blockers.length > 0 && (
              <p className="mt-1 text-[11px] text-subtlefg">Missing: {wf.blockers.slice(0, 2).join('; ')}</p>
            )}
          </button>
        ))}
      </div>
      <details className="text-xs text-mutedfg">
        <summary className="cursor-pointer select-none">Preflight details</summary>
        <ul className="mt-2 space-y-1">
          {readiness.items.map((it) => (
            <li key={it.id} className="flex items-start gap-2">
              {it.ok ? <CheckCircle2 className="mt-0.5 size-3.5 text-low" /> : <X className="mt-0.5 size-3.5 text-medium" />}
              <span>
                <span className="text-foreground">{it.label}:</span> {it.detail}
                {!it.ok && it.action && <span className="block text-subtlefg">{it.action}</span>}
              </span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  )
}

function ApprovalCard({ approval, onDecide }: { approval: PendingApproval; onDecide: (id: string, approve: boolean) => void }) {
  const [busy, setBusy] = useState(false)
  async function act(approve: boolean) {
    setBusy(true)
    try {
      await onDecide(approval.id, approve)
    } finally {
      setBusy(false)
    }
  }
  const RiskIcon = riskIcon[approval.risk] ?? ShieldAlert
  return (
    <div className="rounded-lg border border-border bg-bg p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="font-mono text-sm text-foreground">{approval.action}</span>
        <span
          className={cn(
            'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 ring-inset',
            riskClass[approval.risk] ?? 'bg-infosev/15 text-mutedfg ring-infosev/25',
          )}
        >
          <RiskIcon className="size-3" /> {approval.risk}
        </span>
      </div>
      <div className="mb-1 text-xs text-mutedfg">
        Target: <span className="font-mono text-foreground">{approval.target}</span>
      </div>
      <div className="mb-2 overflow-x-auto rounded-md border border-border bg-elevated p-2 font-mono text-xs text-foreground">
        {approval.argv.join(' ')}
      </div>
      {approval.rationale && <p className="mb-2 text-xs italic text-subtlefg">“{approval.rationale}”</p>}
      <div className="flex justify-end gap-2">
        <Button variant="secondary" disabled={busy} onClick={() => act(false)} className="px-2.5 py-1">
          <X className="size-4" /> Deny
        </Button>
        <Button loading={busy} onClick={() => act(true)} className="px-2.5 py-1">
          <CheckCircle2 className="size-4" /> Approve
        </Button>
      </div>
    </div>
  )
}

function SessionTranscript({
  engagementId,
  sessionId,
  onChanged,
}: {
  engagementId: string
  sessionId: string
  onChanged: () => void
}) {
  const [messages, setMessages] = useState<AgentMessage[]>([])
  const [status, setStatus] = useState<string>('running')
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setMessages([])
    setStatus('running')
    const ctrl = new AbortController()
    let lastId = 0
    let stopped = false

    async function pump() {
      // Seed from the persisted transcript, then tail via SSE.
      try {
        const got = await api.agentSession(engagementId, sessionId)
        if (!stopped) {
          setMessages(got.transcript)
          setStatus(got.session.status)
          lastId = got.transcript.length
          if (terminal(got.session.status)) return
        }
      } catch {
        /* fall through to the stream */
      }
      while (!stopped) {
        try {
          await streamAgentSession(engagementId, sessionId, {
            lastEventId: lastId,
            signal: ctrl.signal,
            onEvent: (e) => {
              if (e.done) {
                stopped = true
                if (e.status) setStatus(e.status)
                onChanged()
                return
              }
              if (e.id) lastId = e.id
              if (e.message) setMessages((prev) => [...prev, e.message as AgentMessage].slice(-MAX_TRANSCRIPT))
            },
          })
        } catch {
          if (ctrl.signal.aborted) return
        }
        if (stopped || ctrl.signal.aborted) return
        await new Promise((r) => setTimeout(r, 1000)) // brief pause, then reconnect-replay
      }
    }
    pump()
    return () => {
      stopped = true
      ctrl.abort()
    }
  }, [engagementId, sessionId, onChanged])

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight })
  }, [messages])

  return (
    <Card
      title="Transcript"
      actions={
        <span className={cn('flex items-center gap-1.5 text-xs', statusTone(status))}>
          {!terminal(status) && <Loader2 className="size-3.5 animate-spin" />}
          {status}
        </span>
      }
    >
      <div
        ref={boxRef}
        role="log"
        aria-live="polite"
        aria-relevant="additions"
        className="max-h-[28rem] space-y-2 overflow-auto"
      >
        {messages.length === 0 ? (
          <span className="text-sm text-mutedfg">Waiting for the agent…</span>
        ) : (
          messages.map((m, i) => <MessageRow key={i} m={m} />)
        )}
      </div>
      <PlanGraph engagementId={engagementId} sessionId={sessionId} status={status} />
      <DecisionLog engagementId={engagementId} sessionId={sessionId} status={status} />
    </Card>
  )
}

// PlanGraph renders the agent's execution plan DAG: each node's tool → target, its
// dependencies, and its settled status. Null for a reactive (single-step) run. Refetches as the
// status advances so nodes fill in as the plan executes.
function PlanGraph({ engagementId, sessionId, status }: { engagementId: string; sessionId: string; status: string }) {
  const [plan, setPlan] = useState<AgentPlan | null>(null)
  useEffect(() => {
    let live = true
    api
      .agentPlan(engagementId, sessionId)
      .then((p) => live && setPlan(p))
      .catch(() => {})
    return () => {
      live = false
    }
  }, [engagementId, sessionId, status])

  if (!plan || plan.nodes.length === 0) return null
  const keyOf = (id: string) => plan.nodes.findIndex((n) => n.id === id) + 1 // stable short label
  return (
    <div className="mt-3 border-t border-border pt-3">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-mutedfg">
        <Network className="size-3.5" /> Plan ·{' '}
        <span className={cn('font-mono', planStatusTone(plan.status))}>{plan.status}</span>
        <span className="text-mutedfg">
          ({plan.nodes.filter((n) => n.status === 'done').length}/{plan.nodes.length} done)
        </span>
      </h4>
      <ul className="space-y-1.5">
        {plan.nodes.map((n, i) => (
          <li key={n.id} className="flex items-start gap-2 text-xs">
            <span className="font-mono tabular-nums text-mutedfg">{i + 1}</span>
            <span className="flex-1">
              <span className="font-mono">{n.tool}</span>
              <span className="text-mutedfg"> · {n.target}</span>
              {n.depends_on && n.depends_on.length > 0 && (
                <span className="text-mutedfg"> · after {n.depends_on.map(keyOf).join(',')}</span>
              )}
              <span className={cn('ml-1.5 font-mono', nodeStatusTone(n.status))}>{n.status}</span>
              {n.risk === 'intrusive' && <ShieldAlert className="ml-1 inline size-3 text-critical" aria-label="intrusive" />}
              {n.failure && <span className="block text-mutedfg">{n.failure}</span>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function nodeStatusTone(s: string): string {
  switch (s) {
    case 'done':
      return 'text-low'
    case 'denied':
    case 'failed':
      return 'text-critical'
    case 'skipped':
      return 'text-medium'
    case 'running':
    case 'awaiting':
      return 'text-high'
    default:
      return 'text-mutedfg'
  }
}

function planStatusTone(s: string): string {
  switch (s) {
    case 'complete':
      return 'text-low'
    case 'failed':
      return 'text-critical'
    default:
      return 'text-high'
  }
}

// DecisionLog renders the structured decision log: why each tool/target was chosen, the
// outcome, and why the run stopped – read from stored data, not the transcript. Refetches as the
// status advances so it fills in as the run progresses.
function DecisionLog({ engagementId, sessionId, status }: { engagementId: string; sessionId: string; status: string }) {
  const [decisions, setDecisions] = useState<AgentDecision[]>([])
  useEffect(() => {
    let live = true
    api
      .agentDecisions(engagementId, sessionId)
      .then((d) => live && setDecisions(d))
      .catch(() => {})
    return () => {
      live = false
    }
  }, [engagementId, sessionId, status])

  if (decisions.length === 0) return null
  return (
    <div className="mt-3 border-t border-border pt-3">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-mutedfg">
        <ListTree className="size-3.5" /> Decision log
      </h4>
      <ul className="space-y-1.5">
        {decisions.map((d) => (
          <li key={d.seq} className="flex items-start gap-2 text-xs">
            <span className="font-mono tabular-nums text-mutedfg">{d.seq}</span>
            {d.kind === 'stop' ? (
              <span className="text-mutedfg">
                stopped: <span className="font-mono">{d.stop_reason}</span>
              </span>
            ) : (
              <span className="flex-1">
                <span className={cn('font-mono', outcomeTone(d.outcome))}>{d.outcome}</span>{' '}
                <span className="font-mono">{d.tool}</span>
                {d.target && <span className="text-mutedfg"> · {d.target}</span>}
                {d.reason?.why_tool && <span className="block text-mutedfg">{d.reason.why_tool}</span>}
                {d.refs?.step_hash && (
                  <span className="block font-mono text-[10px] text-mutedfg">step {d.refs.step_hash.slice(0, 12)}…</span>
                )}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

function outcomeTone(outcome?: string): string {
  switch (outcome) {
    case 'executed':
      return 'text-low'
    case 'denied':
      return 'text-critical'
    case 'error':
      return 'text-medium'
    default:
      return 'text-mutedfg'
  }
}

function MessageRow({ m }: { m: AgentMessage }) {
  if (m.role === 'system') return null // the system prompt is not operator-facing
  const label = m.role === 'tool' ? 'tool result' : m.role
  const tone =
    m.role === 'assistant' ? 'border-brand/30 bg-brand/5' : m.role === 'tool' ? 'border-border bg-elevated' : 'border-border bg-bg'
  return (
    <div className={cn('rounded-md border p-2', tone)}>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-mutedfg">{label}</div>
      {m.toolCalls.length > 0 && (
        <div className="mb-1 font-mono text-xs text-branddim">
          → {m.toolCalls.map((c) => c.name).join(', ')}
        </div>
      )}
      {m.content && <div className="whitespace-pre-wrap break-words font-mono text-xs text-foreground">{m.content}</div>}
    </div>
  )
}
