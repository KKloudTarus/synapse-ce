import { LogOut, Menu, ShieldCheck } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { Button } from './ui'

export function Topbar({ onMenu }: { onMenu?: () => void }) {
  const { logout } = useAuth()
  return (
    <header className="flex h-16 shrink-0 items-center justify-between gap-2 border-b border-border bg-surface/90 px-4 backdrop-blur sm:px-6">
      <div className="flex items-center gap-2">
        {onMenu && (
          <button
            onClick={onMenu}
            aria-label="Open menu"
            className="inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-mutedfg transition-colors hover:bg-elevated hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg md:hidden"
          >
            <Menu className="size-5" />
          </button>
        )}
        <div className="flex items-center gap-2 text-sm text-mutedfg">
          <span className="flex size-8 items-center justify-center rounded-lg bg-accent/10 text-accent">
            <ShieldCheck className="size-4" />
          </span>
          <div>
            <div className="font-medium text-foreground">Security operations</div>
            <div className="hidden text-xs text-subtlefg sm:block">Authorized testing · scope enforced server-side</div>
          </div>
        </div>
      </div>
      <Button variant="ghost" onClick={logout} className="shrink-0 px-2.5 py-1.5" aria-label="Disconnect">
        <LogOut className="size-4" />
        <span className="hidden sm:inline">Disconnect</span>
      </Button>
    </header>
  )
}
