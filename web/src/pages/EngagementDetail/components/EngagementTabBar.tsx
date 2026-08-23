import type { FC, ElementType } from 'react'
import {
  LayoutAlt01,
  Shield01,
  CalendarCheck01,
  LayersThree01,
  AlertCircle,
  Scale01,
  GitBranch01,
  Target01,
  Speedometer01,
  Scan,
  CpuChip01,
  HelpCircle,
  FileCheck02,
  Sliders01,
} from '@untitledui/icons'
import { cx } from '@/utils/cx'
import type { Tab } from '../index'

export interface TabCounts {
  findings?: number
  components?: number
  vulns?: number
  licenses?: number
}

export interface TabDefinition {
  id: Tab
  label: string
  icon: ElementType
  countKey?: keyof TabCounts
}

export const ENGAGEMENT_TABS: TabDefinition[] = [
  { id: 'overview', label: 'Overview', icon: LayoutAlt01 },
  { id: 'findings', label: 'Findings', icon: Shield01, countKey: 'findings' },
  { id: 'sla', label: 'Remediation SLA', icon: CalendarCheck01 },
  { id: 'components', label: 'Packages', icon: LayersThree01, countKey: 'components' },
  { id: 'vulns', label: 'Vulnerabilities', icon: AlertCircle, countKey: 'vulns' },
  { id: 'licenses', label: 'Licenses', icon: Scale01, countKey: 'licenses' },
  { id: 'graph', label: 'Graph', icon: GitBranch01 },
  { id: 'threats', label: 'Threat Model', icon: Target01 },
  { id: 'quality', label: 'Code Quality', icon: Speedometer01 },
  { id: 'recon', label: 'Recon', icon: Scan },
  { id: 'agent', label: 'Agent', icon: CpuChip01 },
  { id: 'reviews', label: 'Awaiting review', icon: HelpCircle },
  { id: 'evidence', label: 'Evidence', icon: FileCheck02 },
  { id: 'settings', label: 'Settings', icon: Sliders01 },
]

export interface EngagementTabBarProps {
  activeTab: Tab
  onTabChange: (tab: Tab) => void
  counts: TabCounts
}

export const EngagementTabBar: FC<EngagementTabBarProps> = ({
  activeTab,
  onTabChange,
  counts,
}) => {
  return (
    <div
      role="tablist"
      aria-label="Engagement Views"
      className="flex gap-1 overflow-x-auto border-b border-secondary scrollbar-none"
    >
      {ENGAGEMENT_TABS.map(({ id, label, icon: Icon, countKey }) => {
        const active = activeTab === id
        const count = countKey ? counts[countKey] : undefined

        return (
          <button
            key={id}
            role="tab"
            aria-selected={active}
            aria-controls={`panel-${id}`}
            id={`tab-${id}`}
            tabIndex={active ? 0 : -1}
            onClick={() => onTabChange(id)}
            className={cx(
              '-mb-px inline-flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-xs font-semibold transition-colors outline-none focus-visible:ring-2 focus-visible:ring-brand/40 focus-visible:ring-offset-2',
              active
                ? 'border-brand text-brand-secondary'
                : 'border-transparent text-tertiary hover:border-secondary hover:text-primary',
            )}
          >
            <Icon
              className={cx(
                'size-4 shrink-0 transition-colors',
                active ? 'text-brand-secondary' : 'text-quaternary group-hover:text-tertiary',
              )}
              aria-hidden="true"
            />
            <span>{label}</span>
            {count !== undefined && count > 0 && (
              <span
                className={cx(
                  'rounded-full px-1.5 py-0.5 text-[10px] font-bold tabular-nums',
                  active
                    ? 'bg-brand-primary/15 text-brand-secondary'
                    : 'bg-secondary text-tertiary',
                )}
              >
                {count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
