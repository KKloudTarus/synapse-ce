import { Boxes, FileText, Gauge, Radar, ScrollText, Settings, Target, Users, X, Library, type LucideIcon } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { cn } from './ui'
import logo from '../assets/logo.png'

const SOON: { icon: LucideIcon; label: string }[] = [
  { icon: Radar, label: 'Recon' },
  { icon: Boxes, label: 'Inventory' },
  { icon: FileText, label: 'Reports' },
  { icon: Settings, label: 'Settings' },
]

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const location = useLocation()
  return (
    <>
      <div className="flex h-14 items-center gap-2 border-b border-border px-5">
        <img src={logo} alt="" className="size-6" />
        <span className="text-lg font-bold tracking-tight">Synapse</span>
      </div>
      <nav className="flex-1 space-y-1 p-3">
        <NavLink
          to="/engagements"
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              isActive
                ? 'bg-brand/10 font-semibold text-branddim before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-brand before:content-[""]'
                : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )
          }
        >
          <Target className="size-[18px]" />
          Engagements
        </NavLink>

        <NavLink
          to="/audit"
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              isActive
                ? 'bg-brand/10 font-semibold text-branddim before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-brand before:content-[""]'
                : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )
          }
        >
          <ScrollText className="size-[18px]" />
          Audit log
        </NavLink>

        <NavLink
          to="/rules"
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              isActive || location.pathname.startsWith('/rules')
                ? 'bg-brand/10 font-semibold text-branddim before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-brand before:content-[""]'
                : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )
          }
        >
          <Library className="size-[18px]" />
          Rules
        </NavLink>

        <NavLink
          to="/code-quality"
          onClick={onNavigate}
          className={() =>
            cn(
              'relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              location.pathname.startsWith('/code-quality')
                ? 'bg-brand/10 font-semibold text-branddim before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-brand before:content-[""]'
                : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )
          }
        >
          <Gauge className="size-[18px]" />
          Code Quality
        </NavLink>

        <NavLink
          to="/team"
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              isActive
                ? 'bg-brand/10 font-semibold text-branddim before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-brand before:content-[""]'
                : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )
          }
        >
          <Users className="size-[18px]" />
          Team
        </NavLink>

        <div className="px-3 pb-1 pt-5 text-[11px] font-medium uppercase tracking-wider text-subtlefg">
          Coming soon
        </div>
        {SOON.map(({ icon: Icon, label }) => (
          <span
            key={label}
            title="Coming soon"
            className="flex cursor-not-allowed items-center gap-3 rounded-lg px-3 py-2 text-sm text-mutedfg/40"
          >
            <Icon className="size-[18px]" />
            {label}
          </span>
        ))}
      </nav>
      <div className="border-t border-border p-3 text-xs text-mutedfg">
        <div className="flex items-center gap-2">
          <span className="size-2 rounded-full bg-accent" />
          self-host · single-tenant
        </div>
      </div>
    </>
  )
}

/** Desktop sidebar (>= md). */
export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-surface md:flex">
      <SidebarNav />
    </aside>
  )
}

/** Mobile slide-over drawer (< md): a modal surface with Escape-to-close +
 *  focus move-in/restore + reduced-motion guards. */
export function MobileSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const panelRef = useRef<HTMLElement>(null)
  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      prev?.focus?.()
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
          'absolute inset-0 bg-black/50 transition-opacity motion-reduce:transition-none',
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
          'absolute inset-y-0 left-0 flex w-64 flex-col border-r border-border bg-surface shadow-xl outline-none transition-transform duration-200 motion-reduce:transition-none',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <button
          onClick={onClose}
          aria-label="Close menu"
          className="absolute right-2 top-2 inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-mutedfg transition-colors hover:bg-elevated hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
        >
          <X className="size-5" />
        </button>
        <SidebarNav onNavigate={onClose} />
      </aside>
    </div>
  )
}
