import type { FC } from 'react'
import { Link } from 'react-router-dom'
import { OperationalState } from '../../../components/synapse/OperationalState'
import { Button, cn } from '../../../components/ui'
import { ageLabel, dueLabel, type AttentionItem } from '../hooks/attentionQueue'

const DUE_TONE: Record<'critical' | 'warning' | 'muted', string> = {
  critical: 'font-semibold text-critical',
  warning: 'text-warning-primary',
  muted: 'text-tertiary',
}

const PRIORITY_CLASS: Record<AttentionItem['priority'], string> = {
  1: 'bg-error-primary text-error-primary',
  2: 'bg-warning-primary text-warning-primary',
  3: 'bg-secondary text-secondary',
}

/**
 * The dashboard's main table: what an operator acts on today, one row per condition, newest state
 * of the loaded data. Rows link to the page where the action happens.
 */
export const NeedsAttentionTable: FC<{ items: AttentionItem[]; loaded: boolean; onClear?: () => void }> = ({ items, loaded, onClear }) => {
  if (items.length === 0) {
    // A cleared filter leaves the queue empty for a reason the operator chose; say so and offer to clear.
    if (onClear) {
      return (
        <OperationalState
          title="No items in this filter"
          detail="Nothing in the queue matches the selected filter."
          action={<Button variant="secondary" onClick={onClear}>Show all</Button>}
        />
      )
    }
    return (
      <OperationalState
        tone="success"
        title="Nothing needs attention"
        detail={loaded ? 'No critical or high-risk asset, no failed scan, no fleet coverage gap, and every active engagement has been scanned.' : 'Loading the assets, engagements and fleet coverage this queue is built from.'}
      />
    )
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[56rem] border-collapse text-left text-sm" aria-label="Needs attention">
        <thead>
          <tr className="border-b border-secondary text-[11px] font-semibold uppercase tracking-wide text-quaternary">
            <th scope="col" className="w-14 px-4 py-2.5">Prio</th>
            <th scope="col" className="w-28 px-3 py-2.5">Type</th>
            <th scope="col" className="w-[16rem] px-3 py-2.5">Asset / engagement</th>
            <th scope="col" className="px-3 py-2.5">Issue</th>
            <th scope="col" className="w-36 px-3 py-2.5">Owner</th>
            <th scope="col" className="w-14 px-3 py-2.5 text-right">Age</th>
            <th scope="col" className="w-24 px-3 py-2.5 text-right">Due</th>
            <th scope="col" className="w-32 px-4 py-2.5 text-right">Next action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-secondary">
          {items.map((item) => (
            <tr key={item.key} className="hover:bg-primary_hover">
              <td className="px-4 py-2.5">
                <span className={cn('inline-flex rounded px-1.5 text-[10px] font-semibold uppercase', PRIORITY_CLASS[item.priority])} title={`Priority ${item.priority}`}>
                  P{item.priority}
                </span>
              </td>
              <td className="truncate px-3 py-2.5 text-xs text-secondary" title={item.type}>{item.type}</td>
              <td className="truncate px-3 py-2.5 font-medium text-primary" title={item.subject}>{item.subject}</td>
              <td className="px-3 py-2.5 text-xs leading-5 text-tertiary"><span className="line-clamp-2" title={item.issue}>{item.issue}</span></td>
              <td className="truncate px-3 py-2.5 text-xs text-tertiary" title={item.owner}>{item.owner}</td>
              <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-tertiary" title={item.since ?? undefined}>
                {isNew(item.since) ? <span className="rounded bg-brand-primary px-1 text-[10px] font-semibold uppercase text-brand-secondary">new</span> : (ageLabel(item.since) || '—')}
              </td>
              <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums" title={item.dueAt ?? undefined}>
                {(() => { const d = dueLabel(item.dueAt); return d.text ? <span className={DUE_TONE[d.tone]}>{d.text}</span> : <span className="text-quaternary">—</span> })()}
              </td>
              <td className="px-4 py-2.5 text-right">
                <Link to={item.to} className="whitespace-nowrap text-xs font-semibold text-brand-secondary hover:text-brand-primary">{item.action}</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// isNew marks a condition that arose in the last hour, so an operator sees fresh work at a glance rather
// than reading a small "0m"/"12m" age. Derived from the condition's start; unknown starts are not new.
function isNew(iso: string | null): boolean {
  if (!iso) return false
  const ms = Date.parse(iso)
  return !Number.isNaN(ms) && Date.now() - ms < 60 * 60 * 1000
}
