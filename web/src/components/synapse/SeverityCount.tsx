import { cn } from '../ui'

export type SeverityCountTone = 'critical' | 'high' | 'medium' | 'low'

const SHORT: Record<SeverityCountTone, string> = { critical: 'crit', high: 'high', medium: 'med', low: 'low' }

/** A severity bucket as a coloured tabular number; zero is muted so colour only marks real exposure. */
export function SeverityCount({ count, tone }: { count: number; tone: SeverityCountTone }) {
  const color = { critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low' }[tone]
  return (
    <span className={cn('font-mono text-sm tabular-nums', count > 0 ? cn(color, 'font-semibold') : 'text-quaternary')}>
      {count}
    </span>
  )
}

/**
 * The four buckets in one line ("0 crit 4 high 205 med 44 low"), optionally led by the total. Every
 * table that reports findings by severity uses this so the encoding is the same on every page.
 */
export function SeverityBuckets({
  counts,
  total,
  className,
}: {
  counts: Record<SeverityCountTone, number>
  total?: number
  className?: string
}) {
  const buckets: SeverityCountTone[] = ['critical', 'high', 'medium', 'low']
  const unrated = total === undefined ? 0 : Math.max(0, total - buckets.reduce((n, b) => n + counts[b], 0))
  return (
    <span
      className={cn('inline-flex items-baseline gap-2.5 whitespace-nowrap tabular-nums', className)}
      title={`${total ?? buckets.reduce((n, b) => n + counts[b], 0)} open: ${buckets.map((b) => `${counts[b]} ${b}`).join(', ')}${unrated ? `, ${unrated} unrated` : ''}`}
    >
      {total !== undefined && <span className={cn('font-mono text-sm font-semibold', total ? 'text-primary' : 'text-quaternary')}>{total}</span>}
      {buckets.map((b) => (
        <span key={b} className="inline-flex items-baseline gap-1">
          <SeverityCount count={counts[b]} tone={b} />
          <span className="text-[10px] uppercase text-quaternary">{SHORT[b]}</span>
        </span>
      ))}
      {unrated > 0 && (
        <span className="inline-flex items-baseline gap-1">
          <span className="font-mono text-sm text-tertiary">{unrated}</span>
          <span className="text-[10px] uppercase text-quaternary">unrated</span>
        </span>
      )}
    </span>
  )
}
