import {
  BarChart01,
  Calendar,
  CpuChip01,
  Dataflow03,
  LayoutGrid01,
  Package,
  Route,
  Scale01,
  Shield01,
  ShieldTick,
  ShieldZap,
  Sliders04,
  Target04,
} from '@untitledui/icons'
import { cn } from '../../../components/ui'
import type { Tab } from '../index'

export interface TabCounts {
  findings: number
  components: number
  vulns: number
  licenses: number
}

export const TABS: { id: Tab; label: string; icon: typeof LayoutGrid01; countKey?: keyof TabCounts }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid01 },
  { id: 'findings', label: 'Findings', icon: ShieldZap, countKey: 'findings' },
  { id: 'sla', label: 'Remediation SLA', icon: Calendar },
  { id: 'components', label: 'Packages', icon: Package, countKey: 'components' },
  { id: 'vulns', label: 'Vulnerabilities', icon: ShieldZap, countKey: 'vulns' },
  { id: 'licenses', label: 'Licenses', icon: Scale01, countKey: 'licenses' },
  { id: 'graph', label: 'Graph', icon: Dataflow03 },
  { id: 'threats', label: 'Threat Model', icon: Route },
  { id: 'quality', label: 'Code Quality', icon: BarChart01 },
  { id: 'recon', label: 'Recon', icon: Target04 },
  { id: 'agent', label: 'Agent', icon: CpuChip01 },
  { id: 'reviews', label: 'Awaiting review', icon: Shield01 },
  { id: 'evidence', label: 'Evidence', icon: ShieldTick },
  { id: 'settings', label: 'Settings', icon: Sliders04 },
]

export function TabBar({ tab, setTab, counts }: { tab: Tab; setTab: (t: Tab) => void; counts: TabCounts }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-secondary">
      {TABS.map(({ id, label, icon: Icon, countKey }) => {
        const active = tab === id
        const count = countKey ? counts[countKey] : undefined
        return (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap rounded-t-md border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-solid',
              active ? 'border-brand-solid text-brand-secondary' : 'border-transparent text-tertiary hover:text-primary',
            )}
          >
            <Icon className="size-4" />
            <span>{label}</span>
            {count !== undefined && count > 0 && (
              <span className="rounded-full bg-brand-primary px-1.5 py-0.2 text-xs font-bold tabular-nums text-brand-secondary">
                {count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
