import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle, InfoCircle, XClose } from '@untitledui/icons'
import { cn } from '../ui'

export type ToastTone = 'success' | 'error' | 'info'

export interface ToastMessage {
  id: number
  message: string
  tone: ToastTone
}

export interface ToastApi {
  /** Announce a short outcome. Errors stay until dismissed; the rest auto-expire. */
  notify: (message: string, tone?: ToastTone) => void
  dismiss: (id: number) => void
  toasts: ToastMessage[]
}

const NOOP: ToastApi = { notify: () => undefined, dismiss: () => undefined, toasts: [] }

const ToastContext = createContext<ToastApi | null>(null)

export const TOAST_TTL_MS = 6000

const TONE_STYLE: Record<ToastTone, { ring: string; icon: typeof CheckCircle; iconClass: string }> = {
  success: { ring: 'ring-accent/30', icon: CheckCircle, iconClass: 'text-accent' },
  error: { ring: 'ring-critical/30', icon: AlertTriangle, iconClass: 'text-critical' },
  info: { ring: 'ring-brand/30', icon: InfoCircle, iconClass: 'text-brand-secondary' },
}

/**
 * Mounts a single polite live region plus the visible toast stack. Announcements
 * are the only feedback channel for actions that change server state without
 * navigating (status changes, member adds, lifecycle transitions).
 */
export function ToastProvider({ children, ttlMs = TOAST_TTL_MS }: { children: ReactNode; ttlMs?: number }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([])
  const nextId = useRef(1)
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>())

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timers.current.delete(id)
    }
    setToasts((current) => current.filter((t) => t.id !== id))
  }, [])

  const notify = useCallback(
    (message: string, tone: ToastTone = 'info') => {
      const text = message.trim()
      if (!text) return
      const id = nextId.current++
      setToasts((current) => [...current, { id, message: text, tone }])
      // An error is the one outcome a user may need to read twice, so it waits
      // for an explicit dismissal instead of disappearing on a timer.
      if (tone === 'error') return
      timers.current.set(
        id,
        setTimeout(() => {
          timers.current.delete(id)
          setToasts((current) => current.filter((t) => t.id !== id))
        }, ttlMs),
      )
    },
    [ttlMs],
  )

  useEffect(() => {
    const pending = timers.current
    return () => {
      pending.forEach((timer) => clearTimeout(timer))
      pending.clear()
    }
  }, [])

  const value = useMemo<ToastApi>(() => ({ notify, dismiss, toasts }), [notify, dismiss, toasts])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastRegion toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

export function ToastRegion({ toasts, onDismiss }: { toasts: ToastMessage[]; onDismiss: (id: number) => void }) {
  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
    >
      {toasts.map((toast) => {
        const tone = TONE_STYLE[toast.tone]
        const Icon = tone.icon
        return (
          <div
            key={toast.id}
            role={toast.tone === 'error' ? 'alert' : 'status'}
            className={cn(
              'pointer-events-auto flex items-start gap-2.5 rounded-lg border border-secondary bg-primary p-3 text-sm text-primary shadow-lg ring-1 ring-inset',
              tone.ring,
            )}
          >
            <Icon className={cn('mt-0.5 size-4 shrink-0', tone.iconClass)} aria-hidden="true" />
            <span className="min-w-0 flex-1 break-words">{toast.message}</span>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label={`Dismiss notification: ${toast.message}`}
              className="rounded p-0.5 text-quaternary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
            >
              <XClose className="size-3.5" />
            </button>
          </div>
        )
      })}
    </div>
  )
}

/**
 * Returns the toast API. Outside a `ToastProvider` it degrades to a no-op so a
 * component can still be rendered in isolation (tests, storybook-style views).
 */
export function useToast(): ToastApi {
  return useContext(ToastContext) ?? NOOP
}
