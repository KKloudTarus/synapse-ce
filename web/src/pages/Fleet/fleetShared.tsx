import { cn } from '../../components/ui'
import type { FleetAgentHealth, FleetVerdict } from '../../lib/types'

// The order the read model resolves verdicts (worst first). Kept here so the UI legend and any
// client-side ordering agree with the domain, and so "covered" is never the visual default.
export const FLEET_VERDICT_ORDER: FleetVerdict[] = [
  'unauthorized',
  'agent_missing',
  'refused',
  'never',
  'stale',
  'partial',
  'covered',
]

interface BadgeStyle {
  label: string
  soft: string
  dot: string
}

// Only `covered` is green. Every other state is visually distinct and non-green, because a green
// dashboard over an unassessed estate is the exact failure this view exists to prevent (#413).
const VERDICT_STYLE: Record<FleetVerdict, BadgeStyle> = {
  covered: { label: 'Covered', soft: 'bg-accent/10 text-accent ring-accent/30', dot: 'bg-accent' },
  partial: { label: 'Partial', soft: 'bg-medium/10 text-medium ring-medium/30', dot: 'bg-medium' },
  // `stale` must NOT be green: the `low` token is the same hex as `accent`, so it would read as
  // covered. `info` (cyan) is the distinct "outdated, needs attention, not a failure" hue.
  stale: { label: 'Stale', soft: 'bg-info/10 text-info ring-info/30', dot: 'bg-info' },
  never: { label: 'Never', soft: 'bg-secondary text-tertiary ring-secondary', dot: 'bg-quaternary' },
  refused: { label: 'Refused', soft: 'bg-high/10 text-high ring-high/30', dot: 'bg-high' },
  agent_missing: { label: 'Agent missing', soft: 'bg-critical/10 text-critical ring-critical/30', dot: 'bg-critical' },
  unauthorized: { label: 'Unauthorized', soft: 'bg-critical/10 text-critical ring-critical/30', dot: 'bg-critical' },
}

const STATE_STYLE: Record<FleetAgentHealth, BadgeStyle> = {
  healthy: { label: 'Healthy', soft: 'bg-accent/10 text-accent ring-accent/30', dot: 'bg-accent' },
  // `stale` uses `info` (cyan), not `low`/`accent` green — a stale agent must never look healthy.
  stale: { label: 'Stale', soft: 'bg-info/10 text-info ring-info/30', dot: 'bg-info' },
  revoked: { label: 'Revoked', soft: 'bg-critical/10 text-critical ring-critical/30', dot: 'bg-critical' },
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

export function FleetVerdictBadge({ verdict }: { verdict: FleetVerdict }) {
  return <Badge style={VERDICT_STYLE[verdict]} raw={verdict} />
}

export function verdictLabel(verdict: FleetVerdict): string {
  return VERDICT_STYLE[verdict]?.label ?? verdict
}

export function FleetStateBadge({ state }: { state: FleetAgentHealth }) {
  return <Badge style={STATE_STYLE[state]} raw={state} />
}

// formatFleetTime renders an ISO timestamp, treating an empty value or the Go zero time
// ("0001-01-01T00:00:00Z") as "never assessed" rather than a misleading year-1 date.
export function formatFleetTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso)
  if (Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1) return '—'
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
