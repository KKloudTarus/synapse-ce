import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { BellRinging01 } from '@untitledui/icons'
import { ApiError, api } from '../../lib/api'

export function NotificationBell() {
  const [unread, setUnread] = useState<number | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const generation = useRef(0)

  useEffect(() => {
    if (unavailable) return
    let timer = 0
    let stopped = false
    const refresh = () => {
      if (stopped || document.visibilityState === 'hidden') return
      const current = ++generation.current
      const controller = new AbortController()
      void api.inboxUnread(controller.signal).then((page) => {
        if (current === generation.current) setUnread(Math.max(0, page.unread))
      }).catch((error: unknown) => {
        if (controller.signal.aborted || current !== generation.current) return
        if (error instanceof ApiError && error.status === 404) {
          stopped = true
          window.clearInterval(timer)
          setUnavailable(true)
        }
      })
      return controller
    }
    let active = refresh()
    const onVisible = () => {
      if (document.visibilityState === 'visible') active = refresh()
    }
    timer = window.setInterval(() => {
      active?.abort()
      active = refresh()
    }, 30000)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      stopped = true
      active?.abort()
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [unavailable])

  if (unavailable) return null
  const label = unread === null ? 'Notifications' : unread > 99 ? 'Notifications, more than 99 unread' : `Notifications, ${unread} unread`
  return (
    <Link to="/inbox" aria-label={label} className="relative inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-secondary hover:bg-primary_hover hover:text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand">
      <BellRinging01 className="size-5" />
      {unread !== null && unread > 0 && (
        <span className="absolute right-1 top-1 min-w-5 rounded-full bg-error-solid px-1 text-center text-[10px] font-semibold text-white" aria-live="polite">
          {unread > 99 ? '99+' : unread}
        </span>
      )}
    </Link>
  )
}
