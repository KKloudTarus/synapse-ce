import { ChevronRight, Stars01 } from '@untitledui/icons'
import { cn } from '../../../components/ui'
import { useFetch } from '../../../hooks'
import { api } from '../../../lib/api'
import type {
  CritiqueClaim,
  EvidenceItem,
  InvestigationClaim,
  Judgment,
  ReachabilityClaim,
  RiskNarrativeClaim,
} from '../../../lib/types'

export function JudgmentStateBadge({ state }: { state: string }) {
  const tone =
    state === 'confirmed'
      ? 'text-success-primary border-utility-green-300 bg-success-primary'
      : state === 'refuted'
        ? 'text-warning-primary border-utility-orange-300 bg-warning-primary'
        : 'text-tertiary border-secondary bg-secondary'
  return (
    <span className={cn('rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase tracking-wide', tone)}>
      {state}
    </span>
  )
}

export function RiskNarrative({ j }: { j: Judgment }) {
  const c = j.claim as Partial<RiskNarrativeClaim>
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Risk narrative</span>
        <JudgmentStateBadge state={j.state} />
        {typeof c.priority === 'number' && (
          <span className="font-mono text-xs font-bold tabular-nums text-secondary">priority {c.priority}/5</span>
        )}
      </div>
      {(c.drivers?.length ?? 0) > 0 && (
        <div className="flex flex-wrap gap-1">
          {c.drivers!.map((d) => (
            <span
              key={d}
              className="rounded border border-secondary bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-secondary"
            >
              {d}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function Critique({ j }: { j: Judgment }) {
  const c = j.claim as Partial<CritiqueClaim>
  const verdictTone =
    c.verdict === 'refuted'
      ? 'text-warning-primary'
      : c.verdict === 'sound'
        ? 'text-success-primary'
        : 'text-secondary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Critique</span>
        <JudgmentStateBadge state={j.state} />
        {c.verdict && <span className={cn('text-xs font-bold', verdictTone)}>{c.verdict}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {c.driver && <span className="font-mono text-[11px] text-tertiary">{c.driver}</span>}
    </div>
  )
}

export function Reachability({ j }: { j: Judgment }) {
  const c = j.claim as Partial<ReachabilityClaim>
  const tone =
    c.reachable === 'reachable'
      ? 'text-error-primary border-error bg-error-primary'
      : c.reachable === 'not_reachable'
        ? 'text-success-primary border-utility-green-300 bg-success-primary'
        : 'text-tertiary border-secondary bg-secondary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Reachability</span>
        <JudgmentStateBadge state={j.state} />
        {c.reachable && (
          <span className={cn('rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase tracking-wide', tone)}>
            {c.reachable.replace('_', ' ')}
          </span>
        )}
        {c.tier && <span className="font-mono text-[11px] font-bold tabular-nums text-secondary">{c.tier}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {(c.path?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1 font-mono text-[11px] tabular-nums text-secondary">
          {c.path!.map((sym, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 && <ChevronRight aria-hidden className="size-3 text-fg-quaternary" />}
              <span>{sym}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function InvestigationHypothesis({ j }: { j: Judgment }) {
  const c = j.claim as Partial<InvestigationClaim>
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">AI investigation hypothesis</span>
        <JudgmentStateBadge state={j.state} />
        {c.tactic && (
          <span className="rounded border border-brand-secondary bg-brand-primary px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand-secondary">
            {c.tactic.replaceAll('_', ' ')}
          </span>
        )}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {c.incident_id && (
        <p className="text-xs text-tertiary">
          Incident <span className="break-all font-mono text-primary">{c.incident_id}</span>
        </p>
      )}
      {(c.drivers?.length ?? 0) > 0 && (
        <div className="flex flex-wrap gap-1" aria-label="Hypothesis drivers">
          {c.drivers!.map((driver) => (
            <span key={driver} className="rounded border border-secondary bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-secondary">
              {driver}
            </span>
          ))}
        </div>
      )}
      {(c.relevant_event_ids?.length ?? 0) > 0 && (
        <p className="text-xs text-tertiary">
          Relevant events:{' '}
          <span className="font-mono text-primary">{c.relevant_event_ids!.join(', ')}</span>
        </p>
      )}
      {c.suggested_next_step && (
        <p className="text-xs text-tertiary">
          Suggested next step:{' '}
          <span className="font-medium text-primary">{c.suggested_next_step.replaceAll('_', ' ')}</span>
        </p>
      )}
      <p className="text-xs text-warning-primary">
        Unverified AI suggestion — only a distinct reviewer's sealed verdict can confirm it. It cannot change incident facts, risk, disposition, or response actions.
      </p>
    </div>
  )
}

export function ExplainJudgments({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const { data: judgments } = useFetch(
    () => api.judgments(engagementId).catch(() => [] as Judgment[]),
    { deps: [engagementId] },
  )

  const relevant = (judgments ?? []).filter(
    (j) =>
      j.subjectId === findingId &&
      (j.capability === 'risk_narrative' || j.capability === 'critique' || j.capability === 'reachability'),
  )
  if (relevant.length === 0) return null

  return (
    <div className="space-y-2 rounded-lg border border-secondary bg-primary p-3 shadow-2xs">
      <div className="flex items-center gap-1.5">
        <Stars01 aria-hidden className="size-3.5 text-brand-secondary" />
        <span className="text-[11px] font-bold uppercase tracking-wide text-secondary">AI Triage &amp; Analysis</span>
      </div>
      <ul className="space-y-2.5" role="list">
        {relevant.map((j) => (
          <li key={j.id}>
            {j.capability === 'reachability' ? (
              <Reachability j={j} />
            ) : j.capability === 'critique' ? (
              <Critique j={j} />
            ) : (
              <RiskNarrative j={j} />
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

export const GATED_JUDGMENT_CAPABILITIES = new Set(['reachability', 'sast', 'critique', 'threat', 'vex_justification', 'investigation'])

export function JudgmentClaim({ judgment }: { judgment: Judgment }) {
  if (judgment.capability === 'investigation') return <InvestigationHypothesis j={judgment} />
  if (judgment.capability === 'reachability') return <Reachability j={judgment} />
  if (judgment.capability === 'critique') return <Critique j={judgment} />
  if (judgment.capability === 'risk_narrative') return <RiskNarrative j={judgment} />

  return (
    <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
      {Object.entries(judgment.claim).map(([key, value]) => (
        <div key={key} className="rounded-md border border-secondary bg-secondary px-2.5 py-2">
          <dt className="text-[11px] font-bold uppercase tracking-wide text-tertiary">{key.replaceAll('_', ' ')}</dt>
          <dd className="mt-0.5 break-words font-mono text-primary">
            {Array.isArray(value) ? value.join(', ') : String(value ?? 'None')}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function sealedJudgmentId(item: EvidenceItem): string {
  if (item.kind !== 'judgment_proposed' || !item.contentBase64) return ''
  try {
    const bytes = Uint8Array.from(atob(item.contentBase64), (c) => c.charCodeAt(0))
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as unknown
    if (payload && typeof payload === 'object' && 'judgment_id' in payload) {
      const id = (payload as { judgment_id?: unknown }).judgment_id
      return typeof id === 'string' ? id : ''
    }
  } catch {
    // A malformed ledger item must not hide the rest of the review queue.
  }
  return ''
}

export const EVIDENCE_BAR = 75
