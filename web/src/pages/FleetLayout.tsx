import { NavLink, Outlet } from 'react-router-dom'
import { cn } from '../components/ui'

function FleetTab({ to, end, children }: { to: string; end?: boolean; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        cn(
          'rounded-lg px-3 py-1.5 text-sm font-medium transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
          isActive ? 'bg-brand/10 text-branddim' : 'text-mutedfg hover:bg-elevated hover:text-foreground',
        )
      }
    >
      {children}
    </NavLink>
  )
}

export function FleetLayout() {
  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <header className="bg-hero mb-6 rounded-xl border border-border p-6">
        <h1 className="text-3xl font-bold tracking-tight">Fleet</h1>
        <p className="mt-1.5 max-w-2xl text-sm text-mutedfg">
          Agent health and per-asset coverage. Unknown, stale, refused and unauthorized are shown as distinct
          states — never counted as covered.
        </p>
        <nav className="mt-4 flex gap-1">
          <FleetTab to="/fleet" end>
            Coverage
          </FleetTab>
          <FleetTab to="/fleet/agents">Agents</FleetTab>
        </nav>
      </header>
      <Outlet />
    </div>
  )
}
