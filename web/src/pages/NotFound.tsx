import { ArrowLeft, SearchLg } from '@untitledui/icons'
import { Link, useLocation } from 'react-router-dom'
import { Button } from '../components/ui'

/** Sections a mistyped path is most likely to have been aiming at. */
const DESTINATIONS: { to: string; label: string; hint: string }[] = [
  { to: '/dashboard', label: 'Dashboard', hint: 'Security operations summary' },
  { to: '/engagements', label: 'Engagements', hint: 'Assessments, findings and scans' },
  { to: '/assets', label: 'Assets', hint: 'Business assets and their coverage' },
  { to: '/code-quality', label: 'Code quality', hint: 'Projects, issues, hotspots and measures' },
]

export function NotFound() {
  const { pathname } = useLocation()
  return (
    <div className="mx-auto max-w-2xl animate-fade-in py-10">
      <div className="flex flex-col items-center gap-4 text-center">
        <div className="flex size-12 items-center justify-center rounded-full bg-secondary text-tertiary">
          <SearchLg className="size-6" aria-hidden="true" />
        </div>
        <div className="space-y-1.5">
          <p className="font-mono text-xs font-bold uppercase tracking-wider text-tertiary">404</p>
          <h1 className="text-xl font-bold tracking-tight text-primary sm:text-display-xs">Page not found</h1>
          <p className="text-sm text-tertiary">
            Nothing is served at <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs text-primary">{pathname}</code>.
            Findings, issues, hotspots and measures live inside an engagement or a code-quality project, not at the top level.
          </p>
        </div>
        <Link to="/dashboard">
          <Button variant="primary">
            <ArrowLeft className="size-4" /> Back to dashboard
          </Button>
        </Link>
      </div>

      <ul className="mt-8 grid gap-3 sm:grid-cols-2">
        {DESTINATIONS.map((d) => (
          <li key={d.to}>
            <Link
              to={d.to}
              className="block rounded-xl border border-secondary bg-primary p-4 shadow-xs transition-colors hover:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
            >
              <span className="text-sm font-semibold text-primary">{d.label}</span>
              <span className="mt-0.5 block text-xs text-tertiary">{d.hint}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default NotFound
