import { AlertTriangle, CheckCircle, CpuChip01, List, Play, XClose } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import type { AgentReadiness } from '../../lib/types'
import { ApprovalCard } from './ApprovalCard'
import { SessionTranscript } from './SessionTranscript'
import { useAgentSessions } from './useAgentSessions'

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

export function AgentTab({ engagementId }: { engagementId: string }) {
  const {
    sessions,
    error,
    goal,
    setGoal,
    starting,
    activeId,
    setActiveId,
    approvals,
    readiness,
    refresh,
    startWithGoal,
    startAgent,
    decide,
  } = useAgentSessions(engagementId)

  if (error) return <ErrorState message={error} />
  if (sessions === null) return <Spinner label="Loading agent sessions…" />

  return (
    <div className="space-y-6">
      <Card title={<span className="flex items-center gap-2"><CpuChip01 className="size-4" /> Run an AI agent</span>}>
        <p className="mb-3 text-sm text-tertiary">
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
            placeholder={`Goal, e.g. \u201cenumerate subdomains of app.example.com and summarize\u201d`}
            aria-label="Agent goal"
            className="flex-1 rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
          />
          <Button loading={starting} disabled={!goal.trim()} onClick={startAgent} color="secondary" className="px-3 py-2">
            <Play className="size-4" /> Start agent
          </Button>
        </div>
      </Card>

      {approvals.length > 0 && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <AlertTriangle className="size-4 text-medium" /> Approvals required ({approvals.length})
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
        <EmptyState icon={CpuChip01} title="No agent sessions yet" hint="Start one above to begin." />
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
                      activeId === s.id ? 'bg-secondary text-primary' : 'text-tertiary hover:bg-secondary/60 hover:text-primary',
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
              <SessionTranscript
                key={activeId}
                engagementId={engagementId}
                sessionId={activeId}
                onChanged={refresh}
                onFollowUp={startWithGoal}
                followUpBusy={starting}
              />
            ) : (
              <Card title="Transcript">
                <p className="text-sm text-tertiary">Select a session to view its transcript.</p>
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
      ? 'border-accent/30 bg-accent/5 text-accent'
      : readiness.overall === 'blocked'
        ? 'border-critical/30 bg-critical/5 text-critical'
        : 'border-medium/30 bg-medium/5 text-medium'
  return (
    <div className="mb-3 rounded-lg border border-secondary bg-primary p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-sm font-medium text-primary">
          <List className="size-4" /> Workflow readiness
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
              wf.ready ? 'border-accent/25 bg-accent/5 hover:bg-accent/10' : 'border-secondary bg-secondary hover:bg-secondary/80',
            )}
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary">{wf.label}</span>
              <span className={cn('font-mono text-[10px]', wf.ready ? 'text-accent' : 'text-medium')}>
                {wf.ready ? 'ready' : 'needs setup'}
              </span>
            </div>
            <p className="text-xs text-tertiary">{wf.description}</p>
            {!wf.ready && wf.blockers && wf.blockers.length > 0 && (
              <p className="mt-1 text-[11px] text-quaternary">Missing: {wf.blockers.slice(0, 2).join('; ')}</p>
            )}
          </button>
        ))}
      </div>
      <details className="text-xs text-tertiary">
        <summary className="cursor-pointer select-none">Preflight details</summary>
        <ul className="mt-2 space-y-1">
          {readiness.items.map((it) => (
            <li key={it.id} className="flex items-start gap-2">
              {it.ok ? <CheckCircle className="mt-0.5 size-3.5 text-accent" /> : <XClose className="mt-0.5 size-3.5 text-medium" />}
              <span>
                <span className="text-primary">{it.label}:</span> {it.detail}
                {!it.ok && it.action && <span className="block text-quaternary">{it.action}</span>}
              </span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  )
}
