import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Flag05, X } from '@untitledui/icons'

import { Button } from '@/components/base/buttons/button'
import { GuideSpotlight, measureGuideBox, scrollGuideTarget } from './GuideSpotlight'
import type { GuideBox } from './guide-placement'
import { GuideToggle } from './GuideToggle'
import { TOUR_STEPS } from './tour-steps'

const SEEN_KEY = 'synapse.playground.tour.seen'
const STEP_KEY = 'synapse.playground.tour.step'

// localStorage throws in a private window and when site data is blocked, and the tour is a
// convenience: a failed read must leave the page working rather than take it down.
function readStore(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}
function writeStore(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* ignore */
  }
}

export function usePlaygroundTour() {
  const [index, setIndex] = useState<number | null>(null)
  const start = useCallback((at = 0) => setIndex(at), [])
  const stop = useCallback(() => {
    writeStore(SEEN_KEY, '1')
    setIndex(null)
  }, [])
  return { index, start, stop, setIndex }
}

export function PlaygroundTour({
  index,
  setIndex,
  stop,
  onComplete,
}: {
  index: number
  setIndex: (next: number) => void
  stop: () => void
  onComplete?: () => void
}) {
  const navigate = useNavigate()
  const location = useLocation()
  const step = TOUR_STEPS[index]
  const cardRef = useRef<HTMLDivElement>(null)
  const [box, setBox] = useState<GuideBox | null>(null)
  // The card waits for the screen it describes. Stepping fast otherwise showed the guidance while the
  // page was still loading, so the reader had nothing to look at.
  const [ready, setReady] = useState(false)
  const [minimized, setMinimized] = useState(false)

  // Navigate when the step asks for a different screen. Comparing against the current path keeps a
  // user who clicked around mid-tour from being yanked back on every render.
  useEffect(() => {
    if (step && location.pathname !== step.route) navigate(step.route)
  }, [step, location.pathname, navigate])

  useEffect(() => {
    writeStore(STEP_KEY, String(index))
    cardRef.current?.focus({ preventScroll: true })
  }, [index])

  // An optional anchor, measured after the route settles. A `text:` anchor matches visible text,
  // which survives a component being restructured better than a class name does; anything else is a
  // CSS selector. An anchor that no longer resolves is not an error, the step just shows its card.
  useEffect(() => {
    setBox(null)
    setReady(false)
    const anchor = step?.anchor
    if (!anchor) {
      // No anchor to wait for, so give the route one frame to paint rather than describing a screen
      // that is still a spinner.
      const t = window.setTimeout(() => setReady(true), 600)
      return () => window.clearTimeout(t)
    }
    let cancelled = false
    let target: HTMLElement | null = null
    const measure = () => { if (!cancelled && target) setBox(measureGuideBox(target)) }
    window.addEventListener('scroll', measure, true)
    window.addEventListener('resize', measure)
    const find = (): Element | null => {
      if (!anchor.startsWith('text:')) return document.querySelector(anchor)
      const wanted = anchor.slice(5).toLowerCase()
      const candidates = document.querySelectorAll('a, button, [role="tab"], h1, h2, h3')
      for (const el of candidates) {
        const text = (el.textContent ?? '').trim().toLowerCase()
        if (text === wanted || (text.length < 48 && text.includes(wanted))) return el
      }
      return null
    }
    // The screen fetches after it routes, so retry briefly rather than measuring an empty frame.
    let attempts = 0
    const tick = () => {
      if (cancelled) return
      const el = find()
      if (el) {
        target = el as HTMLElement
        target.setAttribute('data-demo-focus', '')
        scrollGuideTarget(target)
        window.setTimeout(() => {
          if (cancelled) return
          measure()
          setReady(true)
        }, 320)
        return
      }
      // Give up after about three seconds and show the card anyway: a step whose anchor never
      // resolves must not strand the reader with no way forward.
      if (attempts++ < 8) window.setTimeout(tick, 400)
      else setReady(true)
    }
    const timer = window.setTimeout(tick, 400)
    return () => {
      cancelled = true
      target?.removeAttribute('data-demo-focus')
      window.clearTimeout(timer)
      window.removeEventListener('scroll', measure, true)
      window.removeEventListener('resize', measure)
    }
  }, [step, location.pathname])

  const last = index >= TOUR_STEPS.length - 1
  const next = useCallback(() => {
    if (last) { onComplete?.(); stop() }
    else setIndex(index + 1)
  }, [last, stop, onComplete, setIndex, index])
  const back = useCallback(() => setIndex(Math.max(0, index - 1)), [setIndex, index])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') stop()
      if (e.key === 'ArrowRight') next()
      if (e.key === 'ArrowLeft') back()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stop, next, back])

  if (!step || !ready) return null

  // The card sits away from whatever is highlighted, so the thing being explained stays visible.
  const cardAtTop = box !== null && box.top > window.innerHeight * 0.55

  return (
    <>
      <GuideSpotlight box={box} minimized={minimized} layerClass="z-40" />
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="false"
        aria-labelledby="playground-tour-title"
        tabIndex={-1}
        className={`fixed left-1/2 z-50 flex max-h-[min(50dvh,28rem)] w-[min(32rem,calc(100vw-1rem))] flex-col -translate-x-1/2 overflow-hidden rounded-xl border border-secondary bg-primary p-4 shadow-xl outline-hidden focus-visible:ring-2 focus-visible:ring-brand-solid ${cardAtTop ? 'top-16' : 'bottom-4 md:bottom-6'}`}
      >
        <div className="flex min-h-0 items-start gap-3 overflow-y-auto overscroll-contain">
          <Flag05 className="mt-0.5 size-5 shrink-0 text-brand-secondary" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-tertiary">
              Step {index + 1} of {TOUR_STEPS.length}
            </p>
            <h2 id="playground-tour-title" className="mt-0.5 text-md font-semibold text-primary">
              {step.title}
            </h2>
            <div hidden={minimized}><p className="mt-1 text-sm leading-relaxed text-secondary">{step.body}</p>
            {step.task && (
              <div className="mt-3 rounded-lg border border-brand-solid/30 bg-brand-primary/5 p-2.5">
                <p className="text-sm text-primary">
                  <span className="font-semibold">Try it: </span>
                  {step.task.do}
                </p>
                <p className="mt-1 text-sm text-tertiary">
                  <span className="font-medium text-secondary">You should see: </span>
                  {step.task.expect}
                </p>
              </div>
            )}
            {step.why && (
              <p className="mt-2 border-l-2 border-brand-solid pl-2.5 text-sm text-tertiary">
                <span className="font-medium text-secondary">Why: </span>
                {step.why}
              </p>
            )}
          </div></div>
          <div className="flex shrink-0"><GuideToggle minimized={minimized} onToggle={() => setMinimized(v => !v)} /><Button size="sm" color="tertiary" iconLeading={X} aria-label="End the tour" onClick={stop} /></div>
        </div>
        <div className="mt-3 flex shrink-0 items-center justify-between gap-2">
          <div className="hidden gap-1 sm:flex" aria-hidden="true">
            {TOUR_STEPS.map((s, i) => (
              <span
                key={s.route + i}
                className={`h-1.5 w-1.5 rounded-full ${i === index ? 'bg-brand-solid' : 'bg-quaternary'}`}
              />
            ))}
          </div>
          <div className="flex gap-2">
            <Button size="sm" color="secondary" iconLeading={ArrowLeft} isDisabled={index === 0} onClick={back}>
              Back
            </Button>
            <Button size="sm" color="primary" iconTrailing={ArrowRight} onClick={next}>
              {last ? 'Finish' : 'Next'}
            </Button>
          </div>
        </div>
      </div>
    </>
  )
}

// hasSeenTour also answers true for ?tour=off, and records it, so a screenshot sweep or an embedded
// preview can suppress the tour for the whole browsing context by asking once.
export function hasSeenTour(): boolean {
  try {
    if (new URLSearchParams(window.location.search).get('tour') === 'off') {
      writeStore(SEEN_KEY, '1')
      return true
    }
  } catch {
    /* ignore */
  }
  return readStore(SEEN_KEY) === '1'
}
