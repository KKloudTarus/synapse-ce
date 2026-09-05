import type { FC } from 'react'
import { Link } from 'react-router-dom'
import { OperationalState } from '../../../components/synapse/OperationalState'
import { cn } from '../../../components/ui'
import { ageLabel, type AttentionItem } from '../hooks/attentionQueue'

const PRIORITY_CLASS: Record<AttentionItem['priority'], string> = {
  1: 'bg-error-primary text-error-primary',
  2: 'bg-warning-primary text-warning-primary',
  3: 'bg-secondary text-secondary',
}

/**
 * The dashboard's main table: what an operator acts on today, one row per condition, newest state
 * of the loaded data. Rows link to the page where the action happens.
 */
export const NeedsAttentionTable: FC<{ items: AttentionItem[]; loaded: boolean }> = ({ items, loaded }) => {
  if (items.length === 0) {
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
            <th scope="col" className="w-36 px-4 py-2.5 text-right">Next action</th>
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
              <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-tertiary" title={item.since ?? undefined}>{ageLabel(item.since) || '—'}</td>
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
