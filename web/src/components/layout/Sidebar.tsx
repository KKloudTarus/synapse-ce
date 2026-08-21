import {
  Activity,
  BarChartSquare02,
  BookClosed,
  CheckDone01,
  ChevronLeft,
  ChevronRight,
  Cube01,
  File06,
  LogOut01,
  Moon01,
  Plus,
  Server01,
  ShieldTick,
  ShieldZap,
  Sun,
  Target04,
  Users01,
  XClose,
} from '@untitledui/icons'
import { useEffect, useRef, useState, type ComponentType } from 'react'
import { Link, NavLink } from 'react-router-dom'
import logo from '../../assets/logo.png'
import { useAuth } from '../../auth/AuthContext'
import { cn } from '../ui'

type IconComponent = ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>

type NavItem = {
  icon: IconComponent
  label: string
  to: string
  end?: boolean
}

const DASHBOARD: NavItem = { icon: BarChartSquare02, label: 'Dashboard', to: '/dashboard', end: true }

const NAV_GROUPS: Array<{
  label: string
  items: NavItem[]
}> = [
  {
    label: 'Security operations',
    items: [
      { icon: Target04, label: 'Engagements', to: '/engagements' },
      { icon: ShieldTick, label: 'Review queue', to: '/ai-triage/reviews' },
    ],
  },
  {
    label: 'Exposure management',
    items: [
      { icon: Cube01, label: 'Assets', to: '/assets' },
      { icon: ShieldZap, label: 'Vulnerability intelligence', to: '/vulnerability-intelligence' },
    ],
  },
  {
    label: 'Security engineering',
    items: [
      { icon: CheckDone01, label: 'Code Quality', to: '/code-quality' },
      { icon: BookClosed, label: 'Rules', to: '/rules' },
    ],
  },
  {
    label: 'Runtime security',
    items: [
      { icon: Server01, label: 'Fleet', to: '/fleet' },
      { icon: Activity, label: 'Automation observability', to: '/ai-triage/observability' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { icon: File06, label: 'Audit log', to: '/audit' },
      { icon: Users01, label: 'Team', to: '/team' },
    ],
  },
]

type Theme = 'light' | 'dark'

function currentTheme(): Theme {
  return storageGet('synapse-theme') === 'dark' ? 'dark' : 'light'
}

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

function useOptionalAuth() {
  try {
    return useAuth()
  } catch {
    return { logout: () => {} }
  }
}

function SidebarNav({ collapsed = false, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const [theme, setTheme] = useState<Theme>(currentTheme)
  const { logout } = useOptionalAuth()

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    storageSet('synapse-theme', theme)
  }, [theme])

  useEffect(() => {
    const synchronize = (event: Event) => setTheme((event as CustomEvent<Theme>).detail)
    window.addEventListener('synapse-theme-change', synchronize)
    return () => window.removeEventListener('synapse-theme-change', synchronize)
  }, [])

  function setThemeValue(next: Theme) {
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
        className={({ isActive }) =>
          cn(
            'group relative flex h-10 items-center rounded-lg text-sm font-semibold select-none transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
            collapsed ? 'justify-center px-0' : 'gap-3 px-3 py-2',
            isActive
              ? 'bg-active text-primary'
              : 'text-secondary hover:bg-primary_hover hover:text-secondary_hover',
          )
        }
      >
        {({ isActive }) => (
          <>
            <Icon
              className={cn(
                'size-5 shrink-0 transition-colors duration-100',
                isActive ? 'text-fg-brand-primary' : 'text-fg-quaternary group-hover:text-fg-quaternary_hover',
              )}
              aria-hidden="true"
            />
            <span className={cn('truncate', collapsed ? 'sr-only' : 'inline')}>{label}</span>
            {isActive && <span className="absolute inset-y-2 left-0 w-0.5 rounded-r-full bg-brand-solid" />}
          </>
        )}
      </NavLink>
    ))
  }

  return (
    <>
      <div
        className={cn(
          'flex h-16 shrink-0 items-center border-b border-secondary',
          collapsed ? 'justify-center px-0' : 'gap-3 px-5',
        )}
      >
        <img
          src={logo}
          alt="Synapse"
          className="size-8 shrink-0 rounded-lg shadow-sm drop-shadow-xs"
        />
        <div className={cn('min-w-0 truncate', collapsed && 'sr-only')}>
          <div className="text-lg font-bold tracking-tight text-primary">Synapse</div>
        </div>
      </div>

      <div className="shrink-0 border-b border-secondary p-3">
        <Link
          to="/engagements/new"
          title={collapsed ? 'New Engagement' : undefined}
          aria-label={collapsed ? 'New Engagement' : undefined}
          onClick={onNavigate}
          className={cn(
            'group relative flex h-10 items-center justify-center rounded-lg bg-brand-solid text-sm font-semibold text-white shadow-xs-skeuomorphic ring-1 ring-transparent ring-inset select-none hover:bg-brand-solid_hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
            collapsed ? 'px-0' : 'gap-2 px-3.5 py-2.5',
          )}
        >
          <Plus className="size-5 shrink-0 text-white/80 group-hover:text-white" aria-hidden="true" />
          <span className={cn('truncate', collapsed && 'sr-only')}>New Engagement</span>
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Primary navigation">
        <div className="space-y-0.5">{renderItems([DASHBOARD])}</div>
        {NAV_GROUPS.map((group) => (
          <section key={group.label} className="mt-4">
            <h2
              className={cn(
                'mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-quaternary select-none',
                collapsed && 'sr-only',
              )}
            >
              {group.label}
            </h2>
            <div className="space-y-0.5">{renderItems(group.items)}</div>
          </section>
        ))}
      </nav>

      <div className="shrink-0 space-y-2.5 border-t border-secondary p-3">
        {/* Status text */}
        <div
          className={cn(
            'flex items-center text-xs font-medium text-quaternary select-none',
            collapsed ? 'justify-center' : 'gap-2 px-1',
          )}
        >
          <span className="size-2 shrink-0 rounded-full bg-success-solid" />
          <span className={cn('truncate', collapsed && 'sr-only')}>self-host · single-tenant</span>
        </div>

        {/* Theme toggle — dual icon style */}
        <div
          className={cn(
            'flex items-center rounded-lg border border-secondary p-0.5 bg-secondary',
            collapsed ? 'flex-col gap-1' : 'gap-0.5',
          )}
        >
          <button
            type="button"
            onClick={() => setThemeValue('light')}
            className={cn(
              'flex items-center justify-center rounded-md p-1.5 transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
              collapsed ? 'w-full' : 'flex-1',
              theme === 'light'
                ? 'bg-primary text-fg-primary shadow-xs'
                : 'text-fg-quaternary hover:text-fg-secondary',
            )}
            aria-label="Light theme"
          >
            <Sun className="size-4 shrink-0" />
          </button>
          <button
            type="button"
            onClick={() => setThemeValue('dark')}
            className={cn(
              'flex items-center justify-center rounded-md p-1.5 transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
              collapsed ? 'w-full' : 'flex-1',
              theme === 'dark'
                ? 'bg-primary text-fg-primary shadow-xs'
                : 'text-fg-quaternary hover:text-fg-secondary',
            )}
            aria-label="Dark theme"
          >
            <Moon01 className="size-4 shrink-0" />
          </button>
        </div>

        {/* Disconnect button */}
        <button
          type="button"
          onClick={logout}
          className={cn(
            'group flex h-10 w-full items-center rounded-lg text-sm font-semibold text-secondary transition-colors duration-100 hover:bg-primary_hover hover:text-error-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
            collapsed ? 'justify-center px-0' : 'gap-3 px-3 py-2',
          )}
          aria-label="Disconnect"
        >
          <LogOut01 className="size-5 shrink-0 text-fg-quaternary group-hover:text-fg-error-primary" />
          <span className={cn('truncate', collapsed && 'sr-only')}>Disconnect</span>
        </button>
      </div>
    </>
  )
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(() => storageGet('synapse-sidebar-collapsed') === 'true')

  function toggle() {
    setCollapsed((value) => {
      const next = !value
      storageSet('synapse-sidebar-collapsed', String(next))
      return next
    })
  }

  return (
    <aside
      className={cn(
        'relative hidden min-h-0 shrink-0 flex-col bg-primary md:flex',
        collapsed ? 'w-18' : 'w-64',
      )}
    >
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <SidebarNav collapsed={collapsed} />
      </div>
      <button
        type="button"
        onClick={toggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="absolute -right-3 top-1/2 z-10 flex size-6 -translate-y-1/2 items-center justify-center rounded-full border border-secondary bg-primary text-fg-quaternary shadow-xs transition-colors duration-100 hover:bg-primary_hover hover:text-fg-secondary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
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
        className={cn(
          'absolute inset-0 bg-black/50 backdrop-blur-xs transition-opacity duration-200 motion-reduce:transition-none',
          open ? 'opacity-100' : 'opacity-0',
        )}
      />
      <aside
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation"
        className={cn(
          'absolute inset-y-0 left-0 flex w-72 flex-col border-r border-secondary bg-primary shadow-xl outline-none transition-transform duration-200 motion-reduce:transition-none',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close menu"
          className="absolute right-2.5 top-2.5 inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-fg-quaternary transition duration-150 hover:bg-primary_hover hover:text-fg-secondary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
        >
          <XClose className="size-5" />
        </button>
        <SidebarNav onNavigate={onClose} />
      </aside>
    </div>
  )
}
