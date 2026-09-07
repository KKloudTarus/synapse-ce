import {
  Activity,
  AlertTriangle,
  BarChartSquare02,
  BookClosed,
  CheckDone01,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Cube01,
  LogOut01,
  Plus,
  Monitor01,
  Server01,
  Signal01,
  Settings01,
  ShieldTick,
  SlashCircle01,
  ShieldZap,
  Target04,
  XClose,
} from '@untitledui/icons'
import { useEffect, useRef, useState, type ComponentType } from 'react'
import { Link, NavLink, useLocation } from 'react-router-dom'
import logo from '../../assets/logo.png'
import { useOptionalAuth } from '../../auth/AuthContext'
import { capabilityHint, disabledCapability, useCapabilities } from '../../lib/capabilities'
import type { Capability } from '../../lib/types'
import { Tooltip, TooltipTrigger } from '../base/tooltip/tooltip'
import { cn } from '../ui'

type IconComponent = ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>

type NavItem = {
  icon?: IconComponent
  label: string
  to: string
  end?: boolean
  children?: Array<{ label: string; to: string }>
  /**
   * Key of the optional subsystem that serves this destination, from
   * internal/usecase/capabilities/service.go. When the deployment reports it disabled, the row
   * renders inert with the controlling switch in its tooltip instead of a link that 404s.
   * Omit it for destinations every deployment serves.
   */
  capability?: string
}

const DASHBOARD: NavItem = { icon: BarChartSquare02, label: 'Dashboard', to: '/dashboard', end: true }
const SETTINGS: NavItem = { icon: Settings01, label: 'Settings', to: '/settings' }

const NAV_GROUPS: Array<{
  label: string
  items: NavItem[]
}> = [
    {
      label: 'Security operations',
      items: [
        { icon: Target04, label: 'Engagements', to: '/engagements' },
        { icon: ShieldTick, label: 'Review Queue', to: '/ai-triage/reviews', capability: 'ai_triage' },
      ],
    },
    {
      label: 'Exposure management',
      items: [
        { icon: Cube01, label: 'Assets', to: '/assets' },
        { icon: ShieldZap, label: 'Vulnerability Intelligence', to: '/vulnerability-intelligence' },
      ],
    },
    {
      label: 'Security engineering',
      items: [
        {
          icon: CheckDone01,
          label: 'Code Quality',
          to: '/code-quality',
          children: [
            { label: 'Quality Profiles', to: '/code-quality/profiles' },
            { label: 'Quality Gates', to: '/code-quality/gates' },
          ],
        },
        { icon: BookClosed, label: 'Rules', to: '/rules' },
      ],
    },
    {
      label: 'Runtime security',
      items: [
        { icon: Server01, label: 'Fleet', to: '/fleet', capability: 'fleet' },
        { icon: Monitor01, label: 'Hosts', to: '/fleet/hosts', capability: 'fleet' },
        { icon: Signal01, label: 'Coverage Windows', to: '/fleet/coverage-windows', capability: 'fleet' },
        { icon: AlertTriangle, label: 'Incidents', to: '/fleet/incidents' },
        { icon: ShieldTick, label: 'Response', to: '/blueteam/response', capability: 'fleet' },
        { icon: Activity, label: 'Automation Observability', to: '/ai-triage/observability', capability: 'ai_triage' },
      ],
    },
  ]

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

/**
 * A nav destination whose subsystem the server reports as off. It stays visible so the product
 * still says what Synapse can do, but it is inert and names the switch: a live link here answers
 * 404, which reads as a broken build rather than a configuration choice.
 */
function renderDisabledItem({
  icon: Icon,
  label,
  to,
  capability,
  collapsed,
}: {
  icon?: IconComponent
  label: string
  to: string
  capability: Capability
  collapsed: boolean
}) {
  const hint = capabilityHint(capability)
  return (
    <div key={to} className="space-y-0.5">
      <Tooltip title={`${label} is not enabled`} description={hint} placement="right">
        <TooltipTrigger
          aria-label={`${label}. ${hint}`}
          aria-disabled="true"
          className={cn(
            'group relative flex h-10 w-full max-w-full cursor-not-allowed items-center rounded-lg text-sm font-semibold text-quaternary select-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
            collapsed ? 'justify-center px-0' : 'gap-3 px-3 py-2',
          )}
        >
          {Icon && <Icon className="size-5 shrink-0 text-fg-quaternary" aria-hidden="true" />}
          <span className={cn('truncate', collapsed ? 'sr-only' : 'inline')}>{label}</span>
          {!collapsed && <SlashCircle01 className="ml-auto size-4 shrink-0 text-fg-quaternary" aria-hidden="true" />}
        </TooltipTrigger>
      </Tooltip>
    </div>
  )
}

function SidebarNav({ collapsed = false, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const auth = useOptionalAuth()
  const [signingOut, setSigningOut] = useState(false)
  async function onSignOut() {
    if (!auth) return
    setSigningOut(true)
    try {
      await auth.logout()
    } finally {
      setSigningOut(false)
    }
  }
  const location = useLocation()
  const capabilities = useCapabilities()
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>(() => ({
    '/code-quality': storageGet('synapse-nav-expanded-/code-quality') !== 'false',
  }))

  function toggleExpanded(key: string) {
    setExpandedItems((prev) => {
      const next = !prev[key]
      storageSet(`synapse-nav-expanded-${key}`, String(next))
      return { ...prev, [key]: next }
    })
  }

  function renderItems(items: NavItem[]) {
    return items.map(({ icon: Icon, label, to, end, children, capability }) => {
      const offline = disabledCapability(capabilities, capability)
      if (offline) return renderDisabledItem({ icon: Icon, label, to, capability: offline, collapsed })
      const hasChildren = Boolean(children && children.length > 0)
      const isExpanded = Boolean(expandedItems[to])
      const isSubRouteActive = Boolean(
        hasChildren &&
        children?.some((child) => location.pathname === child.to || location.pathname.startsWith(`${child.to}/`)),
      )
      // A sibling whose route sits under this one (Fleet › Hosts, Fleet › Incidents) owns the
      // active state when it matches; the parent must not light up beside it.
      const shadowed = items.some(
        (other) =>
          other.to !== to &&
          other.to.startsWith(`${to}/`) &&
          (location.pathname === other.to || location.pathname.startsWith(`${other.to}/`)),
      )

      const panelId = hasChildren ? `nav-group-${to.replace(/\W+/g, '-')}` : undefined

      return (
        <div key={to} className="space-y-0.5">
          {/* The link and the expand toggle are siblings: HTML forbids interactive
              content inside an <a>. The toggle is overlaid on the row's right edge. */}
          <div className="relative">
          <NavLink
            to={to}
            end={end}
            title={collapsed ? label : undefined}
            aria-label={collapsed ? label : undefined}
            onClick={() => {
              if (hasChildren && !isExpanded) {
                toggleExpanded(to)
              }
              onNavigate?.()
            }}
            className={({ isActive: navActive }) => {
              const isActive = navActive && !isSubRouteActive && !shadowed

              return cn(
                'group relative flex h-10 items-center rounded-lg text-sm font-semibold select-none transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
                collapsed ? 'justify-center px-0' : 'gap-3 px-3 py-2',
                hasChildren && !collapsed && 'pr-10',
                isActive
                  ? 'bg-active text-primary'
                  : 'text-secondary hover:bg-primary_hover hover:text-secondary_hover',
              )
            }}
          >
            {({ isActive: navActive }) => {
              const isActive = navActive && !isSubRouteActive && !shadowed

              return (
                <>
                  {Icon && (
                    <Icon
                      className={cn(
                        'size-5 shrink-0 transition-colors duration-100',
                        isActive ? 'text-fg-brand-primary' : 'text-fg-quaternary group-hover:text-fg-quaternary_hover',
                      )}
                      aria-hidden="true"
                    />
                  )}
                  <span className={cn('truncate', collapsed ? 'sr-only' : 'inline')}>{label}</span>
                  {isActive && <span className="absolute inset-y-2 left-0 w-0.5 rounded-r-full bg-brand-solid" />}
                </>
              )
            }}
          </NavLink>
          {hasChildren && !collapsed && (
            <button
              type="button"
              aria-label={isExpanded ? `Collapse ${label}` : `Expand ${label}`}
              aria-expanded={isExpanded}
              aria-controls={panelId}
              onClick={() => toggleExpanded(to)}
              className="absolute right-2 top-1/2 flex size-6 -translate-y-1/2 items-center justify-center rounded-md text-fg-quaternary transition-colors duration-100 hover:bg-secondary hover:text-fg-secondary focus-visible:outline-2 focus-visible:outline-brand"
            >
              <ChevronDown
                className={cn('size-4 shrink-0 transition-transform duration-200', isExpanded && '-rotate-180')}
                aria-hidden="true"
              />
            </button>
          )}
          </div>

          {hasChildren && !collapsed && isExpanded && (
            <div id={panelId} className="space-y-0.5 pl-7 pr-1">
              {children?.map((child) => (
                <NavLink
                  key={child.to}
                  to={child.to}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      'group relative flex h-8 items-center rounded-lg px-3 text-xs select-none transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand',
                      isActive
                        ? 'bg-active text-primary font-semibold'
                        : 'text-secondary font-medium hover:bg-primary_hover hover:text-secondary_hover',
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <span className="truncate">{child.label}</span>
                      {isActive && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-r-full bg-brand-solid" />}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          )}
        </div>
      )
    })
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
          className="size-8 shrink-0 rounded-lg shadow-sm drop-shadow-xs dark:ring-1 dark:ring-white/50"
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

      <div className="shrink-0 border-t border-secondary p-3">
        <div className="space-y-0.5">{renderItems([SETTINGS])}</div>
        {auth && (
        <button
          type="button"
          onClick={onSignOut}
          disabled={signingOut}
          title={collapsed ? 'Sign out' : undefined}
          aria-label={collapsed ? 'Sign out' : undefined}
          className={cn(
            'group mt-0.5 flex w-full items-center rounded-lg py-2 text-sm font-medium text-secondary transition-colors hover:bg-primary_hover hover:text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand disabled:cursor-not-allowed disabled:opacity-60',
            collapsed ? 'justify-center px-0' : 'gap-3 px-3',
          )}
        >
          <LogOut01 className="size-5 shrink-0 text-tertiary group-hover:text-primary" aria-hidden="true" />
          <span className={cn('truncate', collapsed ? 'sr-only' : 'inline')}>{signingOut ? 'Signing out…' : 'Sign out'}</span>
        </button>
        )}
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

const FOCUSABLE_SELECTOR = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])'

export function MobileSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    if (!open) return
    const previous = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose()
        return
      }
      // `aria-modal` does not trap focus on its own — cycle Tab inside the panel.
      if (event.key !== 'Tab') return
      const panel = panelRef.current
      if (!panel) return
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null || el === panel,
      )
      if (focusable.length === 0) {
        event.preventDefault()
        panel.focus()
        return
      }
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement
      if (event.shiftKey && (active === first || active === panel || !panel.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && active === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      previous?.focus?.()
    }
  }, [open, onClose])

  return (
    // `inert` while closed keeps the off-screen nav links out of the tab order,
    // so no focusable content lives inside the aria-hidden subtree.
    <div
      className={cn('fixed inset-0 z-40 md:hidden', !open && 'pointer-events-none')}
      aria-hidden={!open}
      inert={!open}
    >
      <button
        type="button"
        aria-label="Close menu"
        tabIndex={open ? undefined : -1}
        onClick={onClose}
        className={cn(
          'absolute inset-0 bg-overlay/50 backdrop-blur-xs transition-opacity duration-200 motion-reduce:transition-none',
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
