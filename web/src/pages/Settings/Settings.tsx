import { NavLink, Outlet } from 'react-router-dom'
import { cn } from '../../components/ui'

const TABS = [
  { label: 'Audit', to: '/settings', end: true },
  { label: 'Team', to: '/settings/team' },
  { label: 'Relationships', to: '/settings/relationships' },
  { label: 'Config', to: '/settings/config' },
]

export function Settings() {
  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Settings</h1>
        <p className="mt-1 text-sm text-secondary">
          Audit trail, team management, assessment relationships, and platform configuration
        </p>
      </header>

      {/* Sub-section navigation. These are route links, not ARIA tabs — a
          role="tablist" whose children are plain anchors is an incomplete pattern. */}
      <nav
        aria-label="Settings sections"
        className="flex flex-wrap gap-1.5 rounded-xl border border-secondary bg-secondary/40 p-1.5"
      >
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              cn(
                'rounded-lg px-3 py-2 text-sm font-semibold transition-colors',
                isActive
                  ? 'bg-primary text-brand-secondary shadow-xs ring-1 ring-secondary'
                  : 'text-tertiary hover:bg-secondary hover:text-primary',
              )
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </div>
  )
}

export default Settings
