import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { PlayCircle, RefreshCw01, XClose } from '@untitledui/icons'

import { Button } from '@/components/base/buttons/button'
import { PlaygroundTour, hasSeenTour, usePlaygroundTour } from './PlaygroundTour'
import { ScanWalkthrough } from './ScanWalkthrough'
import { scanStepRoute } from './scan-steps'
import { resetScenario, scenarioStore, updateScenario } from './scenario/store'
import { WorkflowWalkthrough } from './workflows/WorkflowWalkthrough'
import { chooseMode, isWorkflow, resetWorkflow, updateWorkflows, workflowStore } from './workflows/store'
import { workflowRoute } from './workflows/steps'
import { AdvancedWalkthrough } from './advanced/AdvancedWalkthrough'
import { advancedStore, isAdvanced, resetAdvanced, updateAdvanced } from './advanced/store'
import { advancedRoute } from './advanced/steps'

// PlaygroundShell is mounted only in a VITE_PLAYGROUND build. It states plainly that the data is
// seeded, because a screenshot of this site is otherwise indistinguishable from a real install, and
// it offers the guided trip. It renders nothing in a normal build.
export function PlaygroundShell() {
  const { index, start, stop, setIndex } = usePlaygroundTour()
  const [dismissed, setDismissed] = useState(false)
  const bannerRef = useRef<HTMLDivElement>(null)
  const scenario = useSyncExternalStore(scenarioStore.subscribe, scenarioStore.getSnapshot)
  const workflows = useSyncExternalStore(workflowStore.subscribe, workflowStore.getSnapshot)
  const mode = isWorkflow(workflows.mode) ? workflows.mode : null
  const advanced = useSyncExternalStore(advancedStore.subscribe, advancedStore.getSnapshot)
  const advancedMode = isAdvanced(workflows.mode) ? workflows.mode : null
  const navigate = useNavigate()
  const location = useLocation()
  const entryPage = location.pathname === '/demo'

  // Offer the trip once per browser, and only to a visitor who landed on the entry screen. The
  // tour navigates, so auto-starting on a deep link would pull someone off the screen they were
  // sent to, and it would hijack any automated sweep of the site.
  useEffect(() => {
    const entry = window.location.pathname
    if (workflowStore.getSnapshot().mode !== 'overview' || scenarioStore.getSnapshot().enabled || (entry !== '/' && entry !== '/dashboard')) return
    if (new URLSearchParams(window.location.search).get('tour') !== 'start' && hasSeenTour()) return
    const timer = window.setTimeout(() => start(0), 1200)
    return () => window.clearTimeout(timer)
  }, [start])

  // The dashboard's root is `h-screen overflow-hidden`, so a fixed bar on top of it hides the app's
  // own header rather than pushing it down, and padding on body does nothing against a viewport
  // height. Reserve space inside #root and shrink the app by the bar's measured height. Padding
  // avoids a collapsed top margin that would make the whole document scroll behind the banner.
  useEffect(() => {
    if (dismissed || entryPage) return
    const style = document.createElement('style')
    style.dataset.playground = 'banner-offset'
    style.textContent =
      '#root { height: 100dvh; box-sizing: border-box; padding-top: var(--playground-banner, 2.25rem); } #root > div.h-screen { height: calc(100dvh - var(--playground-banner, 2.25rem)); }'
    document.head.append(style)
    const measure = () => document.documentElement.style.setProperty('--playground-banner', `${bannerRef.current?.getBoundingClientRect().height ?? 36}px`)
    const observer = new ResizeObserver(measure)
    if (bannerRef.current) observer.observe(bannerRef.current)
    measure()
    return () => { observer.disconnect(); style.remove(); document.documentElement.style.removeProperty('--playground-banner') }
  }, [dismissed, entryPage])

  const reset = () => {
    if (advancedMode) { resetAdvanced(advancedMode); window.location.assign(advancedRoute(advancedMode, advancedStore.getSnapshot())); return }
    if (mode) { resetWorkflow(mode); window.location.assign(workflowRoute(mode, workflowStore.getSnapshot())); return }
    if (!scenario.enabled) try {
      updateWorkflows(d => { d.overviewComplete = false })
      localStorage.removeItem('synapse.playground.tour.seen')
      localStorage.removeItem('synapse.playground.tour.step')
    } catch {
      /* ignore */
    }
    if (scenario.enabled) {
      resetScenario()
      updateScenario(d => { d.enabled = true; d.open = true })
      window.location.assign('/assets')
    } else window.location.assign('/dashboard?tour=off')
  }

  const startScan = () => {
    stop()
    chooseMode('code')
    const wasEnabled = scenario.enabled
    updateScenario(d => { d.enabled = true; d.open = true; d.collapsed = false })
    updateScenario(d => { d.microStep = 0 })
    const path = scanStepRoute(scenarioStore.getSnapshot())
    // Switching datasets remounts the app so a page cannot retain its old fixture query cache.
    if (!wasEnabled) window.location.assign(path)
    else navigate(path)
  }
  const chooseDemo = () => {
    stop()
    updateScenario(d => { d.open = false })
    if (mode) updateWorkflows(d => { d[mode].open = false })
    if (advancedMode) updateAdvanced(d => { d[advancedMode].open = false })
    navigate('/demo')
  }
  const resumeWorkflow = () => {
    if (!mode) return
    stop(); updateWorkflows(d => { d[mode].open = true }); navigate(workflowRoute(mode, workflowStore.getSnapshot()))
  }
  const resumeAdvanced = () => { if (!advancedMode) return; stop(); updateAdvanced(d => { d[advancedMode].open = true }); navigate(advancedRoute(advancedMode, advancedStore.getSnapshot())) }

  if (entryPage) return null

  return (
    <>
      {!dismissed && (
        <div ref={bannerRef} className="fixed top-0 right-0 left-0 z-30 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 border-b border-secondary bg-secondary px-4 py-1.5 text-center">
          <p className="text-xs text-secondary">
            <span className="font-semibold text-primary">Playground.</span> Simulated data. Nothing leaves your browser.
          </p>
          <span className="flex max-w-full flex-wrap items-center justify-center gap-1.5">
            {advancedMode ? <Button size="sm" color="secondary" iconLeading={PlayCircle} aria-label="Resume walkthrough" onClick={resumeAdvanced}><span className="hidden sm:inline">{advanced[advancedMode].open ? 'Guide active' : 'Resume walkthrough'}</span></Button> : mode ? <Button size="sm" color="secondary" iconLeading={PlayCircle} aria-label="Resume walkthrough" onClick={resumeWorkflow}><span className="hidden sm:inline">{workflows[mode].open ? 'Guide active' : 'Resume walkthrough'}</span></Button> : scenario.enabled ? <Button size="sm" color="secondary" iconLeading={PlayCircle} aria-label="Resume walkthrough" onClick={startScan}>
              <span className="hidden sm:inline">{scenario.open ? 'Guide active' : 'Resume walkthrough'}</span>
            </Button> : <Button size="sm" color="tertiary" iconLeading={PlayCircle} onClick={() => start(0)}>Take the tour</Button>}
            <Button size="sm" color="tertiary" onClick={chooseDemo}>Learning journey</Button>
            <Button size="sm" color="tertiary" iconLeading={RefreshCw01} aria-label="Reset demo" onClick={reset}>
              <span className="hidden sm:inline">Reset</span>
            </Button>
            <Button size="sm" color="tertiary" iconLeading={XClose} onClick={() => setDismissed(true)} aria-label="Hide the playground notice">
              <span className="hidden sm:inline">Hide</span>
            </Button>
          </span>
        </div>
      )}
      {index !== null && <PlaygroundTour index={index} setIndex={setIndex} stop={stop} onComplete={() => { updateWorkflows(d => { d.overviewComplete = true }); navigate('/demo') }} />}
      <ScanWalkthrough />
      <WorkflowWalkthrough />
      <AdvancedWalkthrough />
      {dismissed && scenario.enabled && !scenario.open && <div className="fixed right-3 bottom-3 z-40"><Button size="sm" color="secondary" iconLeading={PlayCircle} onClick={startScan}>Resume walkthrough</Button></div>}
      {dismissed && mode && !workflows[mode].open && <div className="fixed right-3 bottom-3 z-40"><Button size="sm" color="secondary" iconLeading={PlayCircle} onClick={resumeWorkflow}>Resume walkthrough</Button></div>}
      {dismissed && advancedMode && !advanced[advancedMode].open && <div className="fixed right-3 bottom-3 z-40"><Button size="sm" color="secondary" iconLeading={PlayCircle} onClick={resumeAdvanced}>Resume walkthrough</Button></div>}
    </>
  )
}
