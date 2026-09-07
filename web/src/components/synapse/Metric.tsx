import type { ReactNode } from 'react'
import { cn, InfoNote } from '../ui'

export type MetricTone = 'muted' | 'brand' | 'critical' | 'high' | 'medium' | 'low' | 'accent' | 'info' | 'warning' | 'default'

const VALUE_TONE: Record<MetricTone, string> = {
  muted: 'text-primary',
  default: 'text-primary',
  brand: 'text-brand-secondary',
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
  accent: 'text-success-primary',
  info: 'text-primary',
  warning: 'text-warning-primary',
}

/**
 * One operational figure: a small uppercase label over a tabular number. The optional hint is a
 * definition of the figure, not part of the readout, so it lives behind an info tooltip on the label
 * rather than as a second line of small print under the value. That keeps every metric the same height
 * (so a row of them stays aligned) and stops fine print from cluttering the strip.
 */
export function Metric({
  label,
  value,
  hint,
  tone = 'muted',
  className,
}: {
  label: string
  value: number | string
  hint?: string
  tone?: MetricTone
  className?: string
}) {
  const shown = typeof value === 'number' ? value.toLocaleString() : value
  const zero = value === 0 || value === '0'
  const long = typeof shown === 'string' && shown.length > 6
  return (
    <div aria-label={`${label}: ${shown}`} className={cn('min-w-0', className)}>
      <div className="flex items-center gap-1">
        <span className="truncate text-[11px] font-semibold uppercase tracking-wide text-quaternary">{label}</span>
        {hint && <InfoNote label={label}>{hint}</InfoNote>}
      </div>
      <div
        className={cn(
          'mt-1.5 truncate font-mono font-semibold tabular-nums leading-none',
          long ? 'text-lg' : 'text-2xl',
          zero ? 'text-tertiary' : VALUE_TONE[tone],
        )}
        title={typeof shown === 'string' ? shown : undefined}
      >
        {shown}
      </div>
    </div>
  )
}

/**
 * A row of metrics under a page title, in place of a row of cards. Uses an even auto-fit grid so any
 * number of metrics spreads across the full width in equal columns instead of clustering to the left
 * with ragged trailing space.
 */
export function MetricStrip({ children, className, ariaLabel }: { children: ReactNode; className?: string; ariaLabel?: string }) {
  return (
    <section
      aria-label={ariaLabel}
      className={cn(
        'grid grid-cols-[repeat(auto-fit,minmax(8.5rem,1fr))] gap-x-6 gap-y-5 border-b border-secondary pb-4',
        className,
      )}
    >
      {children}
    </section>
  )
}
