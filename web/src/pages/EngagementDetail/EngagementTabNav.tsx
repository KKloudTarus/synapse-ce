import { useRef } from 'react'
import { cn } from '../../components/ui'
import { TAB_GROUPS, type Tab, type TabGroupDefinition } from './tabs'

export type TabCounts = Record<'findings' | 'components' | 'vulns' | 'licenses', number | undefined>

/**
 * The two-tier tab bar: a tablist of groups and the sub-navigation pills of the active group.
 *
 * Owns only navigation. A count of `undefined` means the number is not known, and no badge is
 * rendered, so a failing request never shows up as a zero the reader would take for a clean
 * result.
 */
export function EngagementTabNav({
  tab,
  activeGroup,
  counts,
  onSelectTab,
}: {
  tab: Tab
  activeGroup: TabGroupDefinition
  counts: TabCounts
  onSelectTab: (next: Tab) => void
}) {
  const tablistRef = useRef<HTMLDivElement>(null)

  function selectGroup(group: TabGroupDefinition) {
    if (group.sub && group.sub.length > 0) {
      if (activeGroup.id !== group.id) onSelectTab(group.sub[0].id)
      return
    }
    onSelectTab(group.id as Tab)
  }

  // WAI-ARIA tabs pattern: Left/Right move between tabs, Home/End jump to the ends, and the newly
  // selected tab takes focus.
  function onTablistKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End']
    if (!keys.includes(event.key)) return
    const current = TAB_GROUPS.findIndex((g) => g.id === activeGroup.id)
    if (current < 0) return
    event.preventDefault()
    const last = TAB_GROUPS.length - 1
    const nextIndex =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? last
          : event.key === 'ArrowLeft'
            ? (current - 1 + TAB_GROUPS.length) % TAB_GROUPS.length
            : (current + 1) % TAB_GROUPS.length
    const target = TAB_GROUPS[nextIndex]
    selectGroup(target)
    tablistRef.current?.querySelector<HTMLButtonElement>(`#tab-${target.id}`)?.focus()
  }

  // Sticky so a tab switch does not leave the reader hunting for the content below a tall hero.
  return (
    <div className="sticky top-0 z-20 -mx-4 space-y-2.5 bg-secondary-subtle px-4 pt-2 sm:-mx-6 sm:px-6 xl:-mx-8 xl:px-8">
    {/* Level 1: Main Tabs */}
    <div
      ref={tablistRef}
      role="tablist"
      aria-label="Engagement Views"
      onKeyDown={onTablistKeyDown}
      className="flex gap-2 overflow-x-auto border-b border-secondary"
    >
      {TAB_GROUPS.map((group) => {
        const isGroupActive = activeGroup.id === group.id
        const Icon = group.icon

        // Count for top-level badge if applicable
        let groupCount: number | undefined
        if (group.id === 'findings') groupCount = counts.findings
        else if (group.id === 'supply-chain') {
          // Summing a partly-unknown set would present a smaller total as if it were complete.
          const parts = [counts.components, counts.vulns, counts.licenses]
          groupCount = parts.some((part) => part === undefined)
            ? undefined
            : parts.reduce((total, part) => total! + part!, 0)
        }

        return (
          <button
            key={group.id}
            role="tab"
            id={`tab-${group.id}`}
            aria-selected={isGroupActive}
            aria-controls="engagement-tabpanel"
            // Roving tabindex: one stop for the whole tablist, arrows move within it.
            tabIndex={isGroupActive ? 0 : -1}
            onClick={() => selectGroup(group)}
            className={cn(
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
              isGroupActive
                ? 'border-brand-solid text-brand-secondary'
                : 'border-transparent text-tertiary hover:border-secondary hover:text-primary',
            )}
          >
            <Icon className={cn('size-4', isGroupActive ? 'text-brand-secondary' : 'text-quaternary')} />
            <span>{group.label}</span>
            {groupCount !== undefined && groupCount > 0 && (
              <span
                className={cn(
                  'rounded-full px-1.5 py-0.5 text-xs font-bold tabular-nums',
                  isGroupActive ? 'bg-brand-primary text-brand-secondary' : 'bg-secondary text-tertiary',
                )}
              >
                {groupCount}
              </span>
            )}
          </button>
        )
      })}
    </div>

    {/* Level 2: Sub-Navigation Pills (fixed height container to prevent layout shifts) */}
    {activeGroup.sub && activeGroup.sub.length > 0 && (
      <div className="flex flex-wrap items-center gap-1.5 border-b border-secondary pb-2.5 pt-0.5">
        {activeGroup.sub.map((sub) => {
          const isSubActive = tab === sub.id
          const count = sub.countKey ? counts[sub.countKey] : undefined
          return (
            <button
              key={sub.id}
              onClick={() => onSelectTab(sub.id)}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
                isSubActive
                  ? 'bg-brand-solid text-primary_on-brand shadow-xs'
                  : 'text-secondary hover:bg-secondary hover:text-primary',
              )}
            >
              <span>{sub.label}</span>
              {count !== undefined && count > 0 && (
                <span
                  className={cn(
                    'rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums',
                    isSubActive ? 'bg-primary/20 text-primary_on-brand' : 'bg-secondary text-tertiary',
                  )}
                >
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>
    )}
    </div>
  )
}
