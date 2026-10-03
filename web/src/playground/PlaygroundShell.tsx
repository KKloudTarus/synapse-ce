import { useEffect, useState } from 'react'
import { PlayCircle, RefreshCw01 } from '@untitledui/icons'

import { Button } from '@/components/base/buttons/button'
import { PlaygroundTour, hasSeenTour, usePlaygroundTour } from './PlaygroundTour'

// PlaygroundShell is mounted only in a VITE_PLAYGROUND build. It states plainly that the data is
// seeded, because a screenshot of this site is otherwise indistinguishable from a real install, and
// it offers the guided trip. It renders nothing in a normal build.
export function PlaygroundShell() {
  const { index, start, stop, setIndex } = usePlaygroundTour()
  const [dismissed, setDismissed] = useState(false)

  // Offer the trip once per browser, and only to a visitor who landed on the entry screen. The
  // tour navigates, so auto-starting on a deep link would pull someone off the screen they were
  // sent to, and it would hijack any automated sweep of the site.
  useEffect(() => {
    const entry = window.location.pathname
    if (hasSeenTour() || (entry !== '/' && entry !== '/dashboard')) return
    const timer = window.setTimeout(() => start(0), 1200)
    return () => window.clearTimeout(timer)
  }, [start])

  // The dashboard's root is `h-screen overflow-hidden`, so a fixed bar on top of it hides the app's
  // own header rather than pushing it down, and padding on body does nothing against a viewport
  // height. Shrink that element by the bar's height for as long as the bar is shown. It is the only
  // `h-screen` child of #root: main.tsx renders the bar, the tour and the app as siblings there.
  useEffect(() => {
    if (dismissed) return
    const style = document.createElement('style')
    style.dataset.playground = 'banner-offset'
    style.textContent =
      '#root > div.h-screen { height: calc(100dvh - var(--playground-banner, 2.25rem)); margin-top: var(--playground-banner, 2.25rem); }'
    document.head.append(style)
    return () => style.remove()
  }, [dismissed])

  const reset = () => {
    try {
      localStorage.clear()
      sessionStorage.clear()
    } catch {
      /* ignore */
    }
    window.location.assign('/dashboard')
  }

  return (
    <>
      {!dismissed && (
        <div className="fixed top-0 right-0 left-0 z-30 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 border-b border-secondary bg-secondary px-4 py-1.5 text-center">
          <p className="text-xs text-secondary">
            <span className="font-semibold text-primary">Playground.</span> Seeded data, no backend, nothing is
            scanned and nothing leaves your browser.
          </p>
          <span className="flex items-center gap-1.5">
            <Button size="sm" color="tertiary" iconLeading={PlayCircle} onClick={() => start(0)}>
              Take the tour
            </Button>
            <Button size="sm" color="tertiary" iconLeading={RefreshCw01} onClick={reset}>
              Reset
            </Button>
            <Button size="sm" color="tertiary" onClick={() => setDismissed(true)} aria-label="Hide the playground notice">
              Hide
            </Button>
          </span>
        </div>
      )}
      {index !== null && <PlaygroundTour index={index} setIndex={setIndex} stop={stop} />}
    </>
  )
}
