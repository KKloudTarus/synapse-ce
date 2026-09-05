import type { ReactNode } from 'react'
import { cn } from '../ui'

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
 * One operational figure: a small uppercase label over a tabular number, with an optional one-line
 * hint. It has no frame and no icon; several of them sit in a MetricStrip. The tone colours the value
 * only when the figure is a risk signal (critical, high), so colour keeps meaning "attention" rather
 * than decorating every number.
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
  return (
    <div aria-label={`${label}: ${shown}`} className={cn('min-w-0', className)}>
      <div className="truncate text-[11px] font-semibold uppercase tracking-wide text-quaternary">{label}</div>
      <div className={cn('mt-1 font-mono text-2xl font-semibold tabular-nums leading-none', zero ? 'text-tertiary' : VALUE_TONE[tone])}>{shown}</div>
      {hint && <div className="mt-1 truncate text-xs text-tertiary" title={hint}>{hint}</div>}
    </div>
  )
}

/** A single row of metrics that sits under a page title in place of a row of cards. */
export function MetricStrip({ children, className, ariaLabel }: { children: ReactNode; className?: string; ariaLabel?: string }) {
  return (
    <section
      aria-label={ariaLabel}
      className={cn('flex flex-wrap items-end gap-x-10 gap-y-4 border-b border-secondary pb-4', className)}
    >
      {children}
    </section>
  )
}
