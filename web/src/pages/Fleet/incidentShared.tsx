import { cn } from '../../components/ui'
import type { IncidentDisposition, IncidentState } from '../../lib/types'

interface BadgeStyle {
  label: string
  soft: string
  dot: string
}

// Incident lifecycle states. Open/new/reopened read as "needs attention" (warm), the working states
// as info/progress, and the terminal states as muted — never green-by-default, mirroring the fleet
// coverage rule that an unresolved estate must not look calm.
const STATE_STYLE: Record<IncidentState, BadgeStyle> = {
  new: { label: 'New', soft: 'bg-high/10 text-high ring-high/30', dot: 'bg-high' },
  open: { label: 'Open', soft: 'bg-high/10 text-high ring-high/30', dot: 'bg-high' },
  reopened: { label: 'Reopened', soft: 'bg-high/10 text-high ring-high/30', dot: 'bg-high' },
  triaged: { label: 'Triaged', soft: 'bg-info/10 text-info ring-info/30', dot: 'bg-info' },
  investigating: { label: 'Investigating', soft: 'bg-info/10 text-info ring-info/30', dot: 'bg-info' },
  contained: { label: 'Contained', soft: 'bg-medium/10 text-medium ring-medium/30', dot: 'bg-medium' },
  remediated: { label: 'Remediated', soft: 'bg-medium/10 text-medium ring-medium/30', dot: 'bg-medium' },
  resolved: { label: 'Resolved', soft: 'bg-accent/10 text-accent ring-accent/30', dot: 'bg-accent' },
  closed: { label: 'Closed', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' },
}

// Analyst verdict. true_positive = confirmed real (critical hue); false_positive/benign/duplicate/test
// = not a real threat (muted); unknown = undecided.
const DISPOSITION_STYLE: Record<IncidentDisposition, BadgeStyle> = {
  unknown: { label: 'Undecided', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' },
  true_positive: { label: 'True positive', soft: 'bg-critical/10 text-critical ring-critical/30', dot: 'bg-critical' },
  benign_positive: { label: 'Benign', soft: 'bg-info/10 text-info ring-info/30', dot: 'bg-info' },
  false_positive: { label: 'False positive', soft: 'bg-accent/10 text-accent ring-accent/30', dot: 'bg-accent' },
  duplicate: { label: 'Duplicate', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' },
  test: { label: 'Test', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' },
}

const FALLBACK: BadgeStyle = { label: 'Unknown', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' }

function Badge({ style, raw }: { style: BadgeStyle | undefined; raw: string }) {
  const s = style ?? { ...FALLBACK, label: raw || FALLBACK.label }
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset',
        s.soft,
      )}
    >
      <span className={cn('size-1.5 rounded-full', s.dot)} />
      {s.label}
    </span>
  )
}

export function IncidentStateBadge({ state }: { state: IncidentState }) {
  return <Badge style={STATE_STYLE[state]} raw={state} />
}

export function IncidentDispositionBadge({ disposition }: { disposition: IncidentDisposition }) {
  return <Badge style={DISPOSITION_STYLE[disposition]} raw={disposition} />
}

export function incidentStateLabel(state: IncidentState): string {
  return STATE_STYLE[state]?.label ?? state
}

export function incidentDispositionLabel(d: IncidentDisposition): string {
  return DISPOSITION_STYLE[d]?.label ?? d
}

// Selectable option lists for the analyst controls, in the order an analyst walks a case.
export const INCIDENT_STATE_OPTIONS: IncidentState[] = [
  'new',
  'open',
  'triaged',
  'investigating',
  'contained',
  'remediated',
  'resolved',
  'closed',
  'reopened',
]

export const INCIDENT_DISPOSITION_OPTIONS: IncidentDisposition[] = [
  'unknown',
  'true_positive',
  'benign_positive',
  'false_positive',
  'duplicate',
  'test',
]

// A 0..100 tri-score axis rendered as a labelled bar. Risk is the escalation axis (warm), while
// Confidence and Coverage are neutral — a low Coverage must read as "we saw less", not "less risk".
export function ScoreBar({
  label,
  value,
  tone = 'neutral',
  hint,
}: {
  label: string
  value: number
  tone?: 'risk' | 'neutral'
  hint?: string
}) {
  const pct = Math.max(0, Math.min(100, value))
  const barColor =
    tone === 'risk'
      ? pct >= 75
        ? 'bg-critical'
        : pct >= 50
          ? 'bg-high'
          : pct >= 25
            ? 'bg-medium'
            : 'bg-accent'
      : 'bg-brand-solid'
  return (
    <div title={hint}>
      <div className="flex items-baseline justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-tertiary">{label}</span>
        <span className="font-mono text-sm font-semibold tabular-nums text-primary">{pct}</span>
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
        {/* Grow via scaleX (a transform), not width, so the animation stays on the compositor and
            honours prefers-reduced-motion like the rest of the app's bars. */}
        <div
          className={cn('h-full w-full origin-left rounded-full transition-transform', barColor)}
          style={{ transform: `scaleX(${pct / 100})` }}
        />
      </div>
    </div>
  )
}
