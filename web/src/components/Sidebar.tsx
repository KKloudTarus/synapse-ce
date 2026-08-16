import {
  Activity,
  Boxes,
  ChevronLeft,
  ChevronRight,
  Gauge,
  LayoutDashboard,
  Library,
  Moon,
  Plus,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldQuestion,
  Sun,
  Target,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import logo from '../assets/logo.png'
import { cn } from './ui'

type NavItem = {
  icon: LucideIcon
  label: string
  to: string
  end?: boolean
}

const DASHBOARD: NavItem = { icon: LayoutDashboard, label: 'Dashboard', to: '/dashboard', end: true }

const NAV_GROUPS: Array<{
  label: string
  items: NavItem[]
}> = [
  {
    label: 'Security operations',
    items: [
      { icon: Target, label: 'Engagements', to: '/engagements' },
      { icon: ShieldQuestion, label: 'Review queue', to: '/ai-triage/reviews' },
    ],
  },
  {
    label: 'Exposure management',
    items: [
      { icon: Boxes, label: 'Assets', to: '/assets' },
      { icon: ShieldAlert, label: 'Vulnerability intelligence', to: '/vulnerability-intelligence' },
    ],
  },
  {
    label: 'Security engineering',
    items: [
      { icon: Gauge, label: 'Code Quality', to: '/code-quality' },
      { icon: Library, label: 'Rules', to: '/rules' },
    ],
  },
  {
    label: 'Runtime security',
    items: [
      { icon: Server, label: 'Fleet', to: '/fleet' },
      { icon: Activity, label: 'Automation observability', to: '/ai-triage/observability' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { icon: ScrollText, label: 'Audit log', to: '/audit' },
      { icon: Users, label: 'Team', to: '/team' },
    ],
  },
]

type Theme = 'light' | 'dark'

function storageGet(key: string) {
  try {
    return typeof globalThis.localStorage?.getItem === 'function' ? globalThis.localStorage.getItem(key) : null
  } catch {
    return null
  }
}

function storageSet(key: string, value: string) {
  try {
    if (typeof globalThis.localStorage?.setItem === 'function') globalThis.localStorage.setItem(key, value)
  } catch {}
}

function currentTheme(): Theme {
  return storageGet('synapse-theme') === 'dark' ? 'dark' : 'light'
}

function SidebarNav({ collapsed = false, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const [theme, setTheme] = useState<Theme>(currentTheme)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    storageSet('synapse-theme', theme)
  }, [theme])

  useEffect(() => {
    const synchronize = (event: Event) => setTheme((event as CustomEvent<Theme>).detail)
    window.addEventListener('synapse-theme-change', synchronize)
    return () => window.removeEventListener('synapse-theme-change', synchronize)
  }, [])

  function toggleTheme() {
    const next = theme === 'light' ? 'dark' : 'light'
    window.dispatchEvent(new CustomEvent<Theme>('synapse-theme-change', { detail: next }))
    setTheme(next)
  }

  function renderItems(items: NavItem[]) {
    return items.map(({ icon: Icon, label, to, end }) => (
      <NavLink
        key={to}
        to={to}
        end={end}
        title={collapsed ? label : undefined}
        aria-label={collapsed ? label : undefined}
        onClick={onNavigate}
        className={({ isActive }) => cn(
          'relative flex min-h-10 items-center rounded-lg text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/70',
          collapsed ? 'justify-center px-2' : 'gap-3 px-3',
          isActive
            ? 'bg-navactive font-semibold text-white'
            : 'text-navmuted hover:bg-navhover hover:text-navfg',
        )}
      >
        {({ isActive }) => (
          <>
            <Icon className="size-[18px] shrink-0" aria-hidden="true" />
            <span className={collapsed ? 'sr-only' : undefined}>{label}</span>
            {isActive && <span className="absolute inset-y-2 left-0 w-0.5 rounded-r-full bg-brand" />}
          </>
        )}
      </NavLink>
    ))
  }

  return (
    <>
      <div className={cn('flex h-16 items-center border-b border-navborder', collapsed ? 'justify-center px-3' : 'gap-3 px-5')}>
        <img src={logo} alt="" className="size-7 shrink-0" />
        <div className={cn('min-w-0', collapsed && 'sr-only')}>
          <div className="text-base font-bold tracking-tight text-navfg">Synapse</div>
          <div className="text-[10px] font-medium uppercase tracking-[0.18em] text-navmuted">Security workspace</div>
        </div>
      </div>

      <div className="border-b border-navborder p-3">
        <Link
          to="/engagements/new"
          title={collapsed ? 'New Engagement' : undefined}
          aria-label={collapsed ? 'New Engagement' : undefined}
          onClick={onNavigate}
          className={cn(
            'btn-primary flex min-h-10 items-center justify-center rounded-lg text-sm font-semibold text-brandfg transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/70 focus-visible:ring-offset-2 focus-visible:ring-offset-nav',
            collapsed ? 'px-2' : 'gap-2 px-3',
          )}
        >
          <Plus className="size-[18px] shrink-0" aria-hidden="true" />
          <span className={collapsed ? 'sr-only' : undefined}>New Engagement</span>
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Primary navigation">
        <div className="space-y-1">{renderItems([DASHBOARD])}</div>
        {NAV_GROUPS.map((group) => (
          <section key={group.label} className="mt-4">
            <h2 className={cn('mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-navsubtle', collapsed && 'sr-only')}>
              {group.label}
            </h2>
            <div className="space-y-1">{renderItems(group.items)}</div>
          </section>
        ))}
      </nav>

      <div className="border-t border-navborder p-3">
        <button
          type="button"
          onClick={toggleTheme}
          title={collapsed ? `Use ${theme === 'light' ? 'dark' : 'light'} theme` : undefined}
          className={cn(
            'flex min-h-10 w-full items-center rounded-lg text-sm text-navmuted transition-colors hover:bg-navhover hover:text-navfg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/70',
            collapsed ? 'justify-center px-2' : 'gap-3 px-3',
          )}
        >
          {theme === 'light' ? <Moon className="size-[18px]" /> : <Sun className="size-[18px]" />}
          <span className={collapsed ? 'sr-only' : undefined}>{theme === 'light' ? 'Dark theme' : 'Light theme'}</span>
        </button>
        <div className={cn('mt-2 flex items-center text-xs text-navsubtle', collapsed ? 'justify-center' : 'gap-2 px-3')}>
          <span className="size-2 shrink-0 rounded-full bg-accent" />
          <span className={collapsed ? 'sr-only' : undefined}>self-host · single-tenant</span>
        </div>
      </div>
    </>
  )
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(() => storageGet('synapse-sidebar-collapsed') === 'true')

  function toggle() {
    setCollapsed((value) => {
      storageSet('synapse-sidebar-collapsed', String(!value))
      return !value
    })
  }

  return (
    <aside className={cn('relative hidden shrink-0 flex-col border-r border-navborder bg-nav transition-[width] duration-200 md:flex', collapsed ? 'w-20' : 'w-64')}>
      <SidebarNav collapsed={collapsed} />
      <button
        type="button"
        onClick={toggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="absolute -right-3 top-20 z-10 flex size-6 items-center justify-center rounded-full border border-navborder bg-nav text-navmuted shadow-sm transition-colors hover:text-navfg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/70"
      >
        {collapsed ? <ChevronRight className="size-3.5" /> : <ChevronLeft className="size-3.5" />}
      </button>
    </aside>
  )
}

export function MobileSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    if (!open) return
    const previous = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      previous?.focus?.()
    }
  }, [open, onClose])

  return (
    <div className={cn('fixed inset-0 z-40 md:hidden', !open && 'pointer-events-none')} aria-hidden={!open}>
      <button
        type="button"
        aria-label="Close menu"
        tabIndex={open ? undefined : -1}
        onClick={onClose}
        className={cn('absolute inset-0 bg-black/50 transition-opacity motion-reduce:transition-none', open ? 'opacity-100' : 'opacity-0')}
      />
      <aside
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation"
        className={cn(
          'absolute inset-y-0 left-0 flex w-72 flex-col border-r border-navborder bg-nav shadow-xl outline-none transition-transform duration-200 motion-reduce:transition-none',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close menu"
          className="absolute right-2 top-2 inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-navmuted transition-colors hover:bg-navhover hover:text-navfg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/70"
        >
          <X className="size-5" />
        </button>
        <SidebarNav onNavigate={onClose} />
      </aside>
    </div>
  )
}
