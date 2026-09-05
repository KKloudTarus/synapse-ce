import type { ReactNode } from 'react'
import { AlertTriangle, InfoCircle } from '@untitledui/icons'
import { Button, cn } from '../ui'

/**
 * A framed, left-aligned state for a table or list that has nothing to show. It names the state, its
 * cause and when it was observed, and offers the next action, so an operator reads a fact, not a
 * decoration. Use it inside the table's frame in place of the rows; keep the toolbar above it.
 */
export function OperationalState({
  tone = 'neutral',
  title,
  detail,
  meta,
  action,
  onRetry,
  className,
}: {
  tone?: 'neutral' | 'error' | 'success'
  title: string
  /** The cause or condition, as a sentence. */
  detail?: ReactNode
  /** Small facts: a timestamp, a source, a request id. */
  meta?: string[]
  action?: ReactNode
  onRetry?: () => void
  className?: string
}) {
  const Icon = tone === 'error' ? AlertTriangle : InfoCircle
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={cn(
        'flex items-start gap-3 border-t border-secondary px-5 py-5',
        tone === 'error' && 'border-l-2 border-l-error-solid',
        tone === 'success' && 'border-l-2 border-l-success-solid',
        className,
      )}
    >
      <Icon className={cn('mt-0.5 size-4 shrink-0', tone === 'error' ? 'text-error-primary' : tone === 'success' ? 'text-success-primary' : 'text-tertiary')} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-primary">{title}</p>
        {detail && <p className="mt-1 max-w-3xl text-sm text-tertiary">{detail}</p>}
        {meta && meta.length > 0 && (
          <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-quaternary">
            {meta.map((m) => <span key={m}>{m}</span>)}
          </p>
        )}
        {(action || onRetry) && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {onRetry && <Button variant="secondary" onClick={onRetry}>Retry</Button>}
            {action}
          </div>
        )}
      </div>
    </div>
  )
}

/** Grey placeholder rows shown while a table loads, so the frame keeps its shape. */
export function TableSkeleton({ rows = 6, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading" className="divide-y divide-secondary">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-4 px-4 py-3">
          {Array.from({ length: columns }, (_, j) => (
            <div key={j} className={cn('h-3 animate-pulse rounded bg-secondary motion-reduce:animate-none', j === 0 ? 'w-48' : 'w-20')} />
          ))}
        </div>
      ))}
    </div>
  )
}
