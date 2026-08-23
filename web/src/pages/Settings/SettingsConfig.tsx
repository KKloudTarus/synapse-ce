import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { LogOut01, Monitor01, Moon01, Server01, Sun } from '@untitledui/icons'
import { Button, Card, cn } from '../../components/ui'
import { useAuth } from '../../auth/AuthContext'

type Theme = 'light' | 'dark' | 'system'

function resolveTheme(pref: Theme): 'light' | 'dark' {
  if (pref === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return pref
}

function currentPref(): Theme {
  try {
    const stored = localStorage.getItem('synapse-theme')
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
    return 'light'
  } catch {
    return 'light'
  }
}

function useOptionalAuth() {
  try {
    return useAuth()
  } catch {
    return { logout: () => {} }
  }
}

export function SettingsConfig() {
  const [pref, setPref] = useState<Theme>(currentPref)
  const [showDisconnectModal, setShowDisconnectModal] = useState(false)
  const { logout } = useOptionalAuth()
  const navigate = useNavigate()

  useEffect(() => {
    const resolved = resolveTheme(pref)
    // System 1: index.css custom vars (:root[data-theme='dark'])
    document.documentElement.dataset.theme = resolved
    // System 2: UUI tokens (.dark-mode class) + Tailwind dark: variant
    if (resolved === 'dark') {
      document.documentElement.classList.add('dark-mode')
    } else {
      document.documentElement.classList.remove('dark-mode')
    }
    try { localStorage.setItem('synapse-theme', pref) } catch {}
  }, [pref])

  // Listen for system theme changes when pref is 'system'
  useEffect(() => {
    if (pref !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => {
      const resolved = mq.matches ? 'dark' : 'light'
      document.documentElement.dataset.theme = resolved
      if (resolved === 'dark') {
        document.documentElement.classList.add('dark-mode')
      } else {
        document.documentElement.classList.remove('dark-mode')
      }
    }
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [pref])

  useEffect(() => {
    const synchronize = (event: Event) => setPref((event as CustomEvent<Theme>).detail)
    window.addEventListener('synapse-theme-change', synchronize)
    return () => window.removeEventListener('synapse-theme-change', synchronize)
  }, [])

  function handleThemeChange(next: Theme) {
    window.dispatchEvent(new CustomEvent<Theme>('synapse-theme-change', { detail: next }))
    setPref(next)
  }

  function handleDisconnect() {
    logout()
    navigate('/connect', { replace: true })
  }

  const themeOptions: { value: Theme; label: string; desc: string; icon: typeof Sun }[] = [
    { value: 'light', label: 'Light', desc: 'Clean white surfaces', icon: Sun },
    { value: 'system', label: 'System', desc: 'Follow OS preference', icon: Monitor01 },
    { value: 'dark', label: 'Dark', desc: 'High contrast', icon: Moon01 },
  ]

  return (
    <div className="space-y-6">
      {/* Deployment & Environment */}
      <div className="relative overflow-hidden rounded-xl border border-secondary bg-primary">
        <div className="absolute inset-0 bg-gradient-to-r from-brand-solid/5 via-transparent to-transparent" />
        <div className="relative flex items-center gap-4 px-5 py-4">
          <div className="flex size-10 items-center justify-center rounded-lg bg-brand-solid/10">
            <Server01 className="size-5 text-brand-secondary" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-primary">Synapse CE</span>
              <span className="size-1.5 rounded-full bg-success-solid animate-pulse" />
              <span className="text-xs text-tertiary">running</span>
            </div>
            <p className="text-xs text-tertiary mt-0.5">Self-hosted · single-tenant · isolated storage</p>
          </div>
          <span className="rounded-md bg-secondary/60 px-2 py-0.5 text-[11px] font-mono text-tertiary ring-1 ring-inset ring-secondary">
            v0.9.4
          </span>
        </div>
      </div>

      {/* Appearance / Theme */}
      <Card title="Appearance">
        <p className="text-sm text-secondary mb-3">
          Customize how Synapse looks on your device.
        </p>
        <div className="grid gap-3 sm:grid-cols-3">
          {themeOptions.map(opt => (
            <button
              key={opt.value}
              type="button"
              onClick={() => handleThemeChange(opt.value)}
              aria-label={`${opt.label} theme`}
              className={cn(
                'flex items-center gap-3 rounded-xl border p-3.5 text-left transition-all',
                pref === opt.value
                  ? 'border-brand-solid bg-brand-primary/10 ring-2 ring-brand-solid/30 shadow-xs'
                  : 'border-secondary bg-primary hover:bg-secondary/40'
              )}
            >
              <div className={cn(
                'flex size-9 items-center justify-center rounded-lg border',
                pref === opt.value ? 'border-brand-solid bg-primary text-brand-secondary' : 'border-secondary bg-secondary text-tertiary'
              )}>
                <opt.icon className="size-4.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-primary">{opt.label}</div>
                <div className="text-xs text-tertiary">{opt.desc}</div>
              </div>
              {pref === opt.value && (
                <span className="size-2 rounded-full bg-brand-solid" />
              )}
            </button>
          ))}
        </div>
      </Card>

      {/* Session & Disconnect */}
      <Card title="Session & access">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <div className="text-sm font-semibold text-primary">Active connection</div>
            <p className="text-xs text-secondary">
              Disconnecting will clear your local session token and require re-authentication.
            </p>
          </div>
          <Button
            variant="secondary"
            onClick={() => setShowDisconnectModal(true)}
            aria-label="Disconnect"
            className="!border-critical/30 !text-critical hover:!bg-critical/10"
          >
            <LogOut01 className="size-4" />
            Disconnect
          </Button>
        </div>
      </Card>

      {/* Disconnect Confirmation Modal */}
      {showDisconnectModal && createPortal(
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setShowDisconnectModal(false)}
          />
          {/* Modal */}
          <div className="relative w-full max-w-[360px] rounded-xl border border-secondary bg-primary p-5 shadow-lg">
            <div className="flex flex-col items-center text-center">
              <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-critical/10">
                <LogOut01 className="size-4.5 text-critical" />
              </div>
              <h2 className="text-base font-semibold text-primary">Disconnect?</h2>
              <p className="mt-1.5 text-sm text-tertiary leading-relaxed">
                Your session token will be cleared. You'll need to re-authenticate to continue.
              </p>
            </div>
            <div className="mt-5 grid grid-cols-2 gap-2.5">
              <Button
                variant="secondary"
                onClick={() => setShowDisconnectModal(false)}
              >
                Cancel
              </Button>
              <Button
                variant="secondary"
                onClick={handleDisconnect}
                className="!border-critical/30 !text-critical hover:!bg-critical/10"
              >
                Disconnect
              </Button>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default SettingsConfig
