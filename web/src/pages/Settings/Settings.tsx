import { Link, matchPath, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { cn, Select } from '../../components/ui'
import { useOptionalAuth } from '../../auth/AuthContext'

const TABS = [
  { label: 'Audit', to: '/settings' },
  { label: 'Team', to: '/settings/team' },
  { label: 'Finding ownership', to: '/settings/ownership' },
  { label: 'Assignee review', to: '/settings/assignee-review' },
  { label: 'Integrations', to: '/settings/integrations' },
  { label: 'Connections', to: '/settings/integrations/ci' },
  { label: 'Jira', to: '/settings/integrations/jira' },
  { label: 'Tickets', to: '/settings/integrations/tickets' },
  { label: 'Connectors', to: '/settings/connectors' },
  { label: 'SLA policy', to: '/settings/sla' },
  { label: 'Offensive policy', to: '/settings/offensive-policy' },
  { label: 'Alerting', to: '/settings/alerting' },
  { label: 'Email delivery', to: '/settings/email' },
  { label: 'Templates', to: '/settings/templates' },
  { label: 'SIEM', to: '/settings/siem' },
  { label: 'Language & time zone', to: '/settings/regional' },
  { label: 'Telemetry Privacy', to: '/settings/privacy' },
  { label: 'Relationships', to: '/settings/relationships' },
  { label: 'Config', to: '/settings/config' },
]

export function Settings() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const identityEnabled = useOptionalAuth()?.currentUser?.features?.enterpriseIdentity === true
  const tabs = identityEnabled ? [...TABS, { label: 'Authentication', to: '/settings/authentication' }] : TABS
  const current = [...tabs].reverse().find(({ to }) => matchPath({ path: to, end: to === '/settings' }, pathname))?.to
  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Settings</h1>
        <p className="mt-1 text-sm text-secondary">
          Audit trail, team management, external integrations, assessment relationships, and platform configuration
        </p>
      </header>

      <nav aria-label="Settings sections">
        <Select
          ariaLabel="Settings section"
          value={current ?? ''}
          placeholder="Choose a settings section"
          onValueChange={(to) => void navigate(to)}
          options={tabs.map(({ label, to }) => ({ value: to, label }))}
          className="w-full sm:hidden"
        />
        <div className="hidden flex-wrap gap-1.5 rounded-xl border border-secondary bg-secondary/40 p-1.5 sm:flex">
          {tabs.map(({ label, to }) => (
            <Link
              key={to}
              to={to}
              aria-current={to === current ? 'page' : undefined}
              className={cn(
                'rounded-lg px-3 py-2 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand',
                to === current
                  ? 'bg-primary text-brand-secondary shadow-xs ring-1 ring-secondary'
                  : 'text-tertiary hover:bg-secondary hover:text-primary',
              )}
            >
              {label}
            </Link>
          ))}
        </div>
      </nav>

      <Outlet />
    </div>
  )
}

export default Settings
