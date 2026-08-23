import { AlertTriangle, Dataflow03, Loading01, Play, Share07 } from '@untitledui/icons'
import { useEffect, useRef, useState } from 'react'
import { Markdown } from '../../components/synapse/Markdown'
import { Button, Card, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, streamAgentSession } from '../../lib/api'
import type { AgentMessage } from '../../lib/types'

const MAX_TRANSCRIPT = 300

const terminal = (s: string) => s === 'succeeded' || s === 'failed' || s === 'cancelled'

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

export function SessionTranscript({
  engagementId,
  sessionId,
  onChanged,
  onFollowUp,
  followUpBusy,
}: {
  engagementId: string
  sessionId: string
  onChanged: () => void
  onFollowUp: (goal: string) => void
  followUpBusy: boolean
}) {
  const [messages, setMessages] = useState<AgentMessage[]>([])
  const [status, setStatus] = useState<string>('running')
  const [followUp, setFollowUp] = useState('')
  const boxRef = useRef<HTMLDivElement>(null)

  // SSE streaming effect - kept as-is (cannot be replaced by useFetch)
  useEffect(() => {
    setMessages([])
    setStatus('running')
    const ctrl = new AbortController()
    let lastId = 0
    let stopped = false

    async function pump() {
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
        await new Promise((r) => setTimeout(r, 1000))
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
          {!terminal(status) && <Loading01 className="size-3.5 animate-spin" />}
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
          <span className="text-sm text-tertiary">Waiting for the agent…</span>
        ) : (
          messages.map((m, i) => <MessageRow key={i} m={m} />)
        )}
      </div>
      <PlanGraph engagementId={engagementId} sessionId={sessionId} status={status} />
      <DecisionLog engagementId={engagementId} sessionId={sessionId} status={status} />
      {terminal(status) && (
        <div className="mt-3 border-t border-secondary pt-3">
          <p className="mb-1.5 text-xs text-tertiary">
            This run is {status}. The agent runs one goal per session — start a follow-up run to continue this
            line of work (it opens a fresh session).
          </p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              value={followUp}
              onChange={(e) => setFollowUp(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.nativeEvent.isComposing && followUp.trim() && !followUpBusy) {
                  onFollowUp(followUp)
                  setFollowUp('')
                }
              }}
              placeholder={`Follow-up goal, e.g. \u201cnow triage the SQLi candidates one by one\u201d`}
              aria-label="Follow-up goal"
              className="flex-1 rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
            />
            <Button
              loading={followUpBusy}
              disabled={!followUp.trim()}
              onClick={() => {
                onFollowUp(followUp)
                setFollowUp('')
              }}
              color="secondary"
              className="px-3 py-2"
            >
              <Play className="size-4" /> Follow up
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}

// --- PlanGraph ---

function nodeStatusTone(s: string): string {
  switch (s) {
    case 'done':
      return 'text-accent'
    case 'denied':
    case 'failed':
      return 'text-critical'
    case 'skipped':
      return 'text-medium'
    case 'running':
    case 'awaiting':
      return 'text-high'
    default:
      return 'text-tertiary'
  }
}

function planStatusTone(s: string): string {
  switch (s) {
    case 'complete':
      return 'text-accent'
    case 'failed':
      return 'text-critical'
    default:
      return 'text-high'
  }
}

function PlanGraph({ engagementId, sessionId, status }: { engagementId: string; sessionId: string; status: string }) {
  const { data: plan } = useFetch(
    () => api.agentPlan(engagementId, sessionId),
    { deps: [engagementId, sessionId, status] },
  )

  if (!plan || plan.nodes.length === 0) return null
  const keyOf = (id: string) => plan.nodes.findIndex((n) => n.id === id) + 1
  return (
    <div className="mt-3 border-t border-secondary pt-3">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-tertiary">
        <Share07 className="size-3.5" /> Plan ·{' '}
        <span className={cn('font-mono', planStatusTone(plan.status))}>{plan.status}</span>
        <span className="text-tertiary">
          ({plan.nodes.filter((n) => n.status === 'done').length}/{plan.nodes.length} done)
        </span>
      </h4>
      <ul className="space-y-1.5">
        {plan.nodes.map((n, i) => (
          <li key={n.id} className="flex items-start gap-2 text-xs">
            <span className="font-mono tabular-nums text-tertiary">{i + 1}</span>
            <span className="flex-1">
              <span className="font-mono">{n.tool}</span>
              <span className="text-tertiary"> · {n.target}</span>
              {n.depends_on && n.depends_on.length > 0 && (
                <span className="text-tertiary"> · after {n.depends_on.map(keyOf).join(',')}</span>
              )}
              <span className={cn('ml-1.5 font-mono', nodeStatusTone(n.status))}>{n.status}</span>
              {n.risk === 'intrusive' && <AlertTriangle className="ml-1 inline size-3 text-critical" aria-label="intrusive" />}
              {n.failure && <span className="block text-tertiary">{n.failure}</span>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// --- DecisionLog ---

function outcomeTone(outcome?: string): string {
  switch (outcome) {
    case 'executed':
      return 'text-accent'
    case 'denied':
      return 'text-critical'
    case 'error':
      return 'text-medium'
    default:
      return 'text-tertiary'
  }
}

function DecisionLog({ engagementId, sessionId, status }: { engagementId: string; sessionId: string; status: string }) {
  const { data: decisions } = useFetch(
    () => api.agentDecisions(engagementId, sessionId),
    { deps: [engagementId, sessionId, status] },
  )

  if (!decisions || decisions.length === 0) return null
  return (
    <div className="mt-3 border-t border-secondary pt-3">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-tertiary">
        <Dataflow03 className="size-3.5" /> Decision log
      </h4>
      <ul className="space-y-1.5">
        {decisions.map((d) => (
          <li key={d.seq} className="flex items-start gap-2 text-xs">
            <span className="font-mono tabular-nums text-tertiary">{d.seq}</span>
            {d.kind === 'stop' ? (
              <span className="text-tertiary">
                stopped: <span className="font-mono">{d.stop_reason}</span>
              </span>
            ) : (
              <span className="flex-1">
                <span className={cn('font-mono', outcomeTone(d.outcome))}>{d.outcome}</span>{' '}
                <span className="font-mono">{d.tool}</span>
                {d.target && <span className="text-tertiary"> · {d.target}</span>}
                {d.reason?.why_tool && <span className="block text-tertiary">{d.reason.why_tool}</span>}
                {d.refs?.step_hash && (
                  <span className="block font-mono text-[10px] text-tertiary">step {d.refs.step_hash.slice(0, 12)}…</span>
                )}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

// --- MessageRow + ToolResult ---

function MessageRow({ m }: { m: AgentMessage }) {
  if (m.role === 'system') return null
  const label = m.role === 'tool' ? 'tool result' : m.role
  const tone =
    m.role === 'assistant' ? 'border-brand/30 bg-brand/5' : m.role === 'tool' ? 'border-secondary bg-secondary' : 'border-secondary bg-primary'
  return (
    <div className={cn('rounded-md border p-2', tone)}>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-tertiary">{label}</div>
      {m.toolCalls.length > 0 && (
        <div className="mb-1 font-mono text-xs text-brand-secondary">
          → {m.toolCalls.map((c) => c.name).join(', ')}
        </div>
      )}
      {m.content &&
        (m.role === 'tool' ? (
          <ToolResult content={m.content} />
        ) : m.role === 'assistant' ? (
          <Markdown className="text-xs">{m.content}</Markdown>
        ) : (
          <div className="whitespace-pre-wrap break-words text-xs text-primary">{m.content}</div>
        ))}
    </div>
  )
}

function ToolResult({ content }: { content: string }) {
  const parsed = safeParse(content)
  const pretty = parsed !== undefined ? JSON.stringify(parsed, null, 2) : null
  return (
    <details className="text-xs">
      <summary className="cursor-pointer select-none rounded text-tertiary marker:text-tertiary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40">
        {toolSummary(parsed, content)}
      </summary>
      <pre className="mt-1 max-h-64 overflow-auto rounded-md border border-secondary bg-primary p-2 font-mono text-[11px] leading-relaxed text-tertiary">
        {pretty ?? content}
      </pre>
    </details>
  )
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s)
  } catch {
    return undefined
  }
}

function toolSummary(parsed: unknown, raw: string): string {
  const suffix = ' — click to expand'
  if (Array.isArray(parsed)) return `${parsed.length} item${parsed.length === 1 ? '' : 's'}${suffix}`
  if (parsed && typeof parsed === 'object') {
    const o = parsed as Record<string, unknown>
    for (const k of ['note', 'summary', 'state', 'status', 'verdict', 'message']) {
      const v = o[k]
      if (typeof v === 'string' && v.trim()) return clipText(v.trim(), 120) + suffix
    }
    const n = Object.keys(o).length
    return `result (${n} field${n === 1 ? '' : 's'})${suffix}`
  }
  const t = raw.trim()
  return (t ? clipText(t, 120) : 'result') + suffix
}

function clipText(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + '…'
}
