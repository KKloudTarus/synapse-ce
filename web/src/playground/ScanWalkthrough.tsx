import { GuideSpotlight, GuideProgress, scrollGuideTarget, measureGuideBox, findGuideContext } from './GuideSpotlight'
import { guidePlacement } from './guide-placement'
import { GuideToggle, guidePanelClass } from './GuideToggle'
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { createPortal } from 'react-dom'
import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, CheckCircle, Flag05, XClose } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { SCAN_STEPS } from './scan-steps'
import { canClickDemoControl, demoValue, fillDemoControl } from './demo-controls'
import { findGuideTarget, guidedActions } from './guided-actions'
import { publishDemoAdvisory, scenarioStore, settleScenario, updateScenario } from './scenario/store'
import { nextChapter, startDemoChapter } from './journey'

type Box = { top: number; left: number; width: number; height: number }
export function ScanWalkthrough() {
  const s = useSyncExternalStore(scenarioStore.subscribe, scenarioStore.getSnapshot)
  const navigate = useNavigate()
  const location = useLocation()
  const [minimized, setMinimized] = useState(false)
  const [host, setHost] = useState<HTMLElement>(document.body)
  const [box, setBox] = useState<Box | null>(null)
  const [observed, setObserved] = useState({ key: '', ready: false, canExecute: false })
  const execution = useRef<{ key: string; startedAt: number } | null>(null)
  const [executing, setExecuting] = useState<string | null>(null)
  const [retry, setRetry] = useState<string | null>(null)
  const [manual, setManual] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)
  const content = useRef<HTMLDivElement>(null)
  const step = SCAN_STEPS[s.step]
  const actions = useMemo(() => guidedActions(step), [step])
  const actionIndex = Math.min(s.microStep, actions.length - 1)
  const action = actions[actionIndex]
  const actionKey = `${s.step}:${actionIndex}`
  const ready = observed.key === actionKey && observed.ready
  const review = actionIndex === actions.length - 1
  const finished = s.completed.includes('finish')
  const active = s.enabled && s.open && location.pathname !== '/demo'
  const actionRoute = action.route ?? step.route(s)
  const atStep = location.pathname === actionRoute.split('?')[0]
  const advance = useCallback(() => {
    const current = scenarioStore.getSnapshot()
    if (current.step !== s.step || Math.min(current.microStep, actions.length - 1) !== actionIndex || !action.done(current, document) || step.read && !atStep) return
    if (actionIndex < actions.length - 1) updateScenario(d => { d.microStep = actionIndex + 1 })
    else {
      updateScenario(d => {
        if (!d.completed.includes(step.id)) d.completed.push(step.id)
        d.skipped = d.skipped.filter(id => id !== step.id)
        if (d.step < SCAN_STEPS.length - 1) { d.step += 1; d.microStep = 0 }
      })
      if (s.step < SCAN_STEPS.length - 1) navigate(SCAN_STEPS[s.step + 1].route(scenarioStore.getSnapshot()))
    }
    setManual(false)
  }, [actionIndex, actions.length, action, step.id, step.read, atStep, s.step, navigate])
  // Saved API checkpoints survive reload even when their forms no longer exist.
  useEffect(() => {
    if (active && !manual && !review && !step.read && !action.pipeline && step.ready(s) && (!step.focus || findGuideTarget({ kind: 'selector', name: step.focus }))) updateScenario(d => { if (d.step === s.step && d.microStep === s.microStep) d.microStep = actions.length - 1 })
  }, [active, manual, review, action.pipeline, step, s, actions.length])
  useEffect(() => {
    if (!active || step.id !== 'comparison' || !s.comparisonAt || new URLSearchParams(location.search).get('comparison_id')) return
    // Let the normal response select its comparison first. Reload/resume can then
    // recover the saved immutable pair instead of showing an empty configuration.
    const timer = window.setTimeout(() => navigate(step.route(scenarioStore.getSnapshot()), { replace: true }), 750)
    return () => window.clearTimeout(timer)
  }, [active, step, s.comparisonAt, location.search, navigate])
  useEffect(() => {
    if (!s.enabled) return
    const timer = window.setInterval(settleScenario, 1000)
    return () => window.clearInterval(timer)
  }, [s.enabled])
  useEffect(() => {
    if (!active) return
    let target: HTMLElement | null = null
    let filled: HTMLElement | null = null
    let raised: HTMLElement | null = null
    const observe = () => {
      const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(el => !el.closest('[data-guided-demo], [aria-hidden="true"], [inert], [hidden]') && el.getClientRects().length > 0)
      // Keep guide controls inside the active modal's focus scope.
      setHost(dialog ?? document.body)
      // The guide stays within the modal focus scope; lift its outer layer above the toast stack.
      let layer = dialog ?? null
      for (let parent = dialog?.parentElement; parent && parent !== document.body; parent = parent.parentElement) {
        if (getComputedStyle(parent).position === 'fixed') layer = parent
      }
      if (layer !== raised) { raised?.removeAttribute('data-demo-modal-layer'); raised = layer; raised?.setAttribute('data-demo-modal-layer', '') }
      if (step.id === 'comparison' && !manual && !review && scenarioStore.getSnapshot().comparisonAt && step.focus && findGuideTarget({ kind: 'selector', name: step.focus })) {
        updateScenario(d => { if (d.step === s.step && d.microStep === s.microStep) d.microStep = actions.length - 1 })
        return
      }
      if (action.pipeline) {
        const track = document.querySelector<HTMLDetailsElement>('[aria-label="Scan pipeline"]')
        if (track && !track.open) track.open = true
        const milestone = [...document.querySelectorAll<HTMLElement>('[data-scan-step]')].find(el => el.dataset.scanStep === action.pipeline)
        if (milestone && milestone.getAttribute('aria-pressed') !== 'true') milestone.click()
      }
      fillDemoControl(action, scenarioStore.getSnapshot())
      const found = findGuideTarget(action.target)
      if (action.example && found !== filled) { filled?.removeAttribute('data-demo-filled'); filled = found; filled?.setAttribute('data-demo-filled', '') }
      const spotlight = found ?? (!action.target && atStep ? findGuideContext(location.pathname) : null)
      if (spotlight !== target) {
        target?.removeAttribute('data-demo-focus')
        target = spotlight
        target?.setAttribute('data-demo-focus', '')
        scrollGuideTarget(target)
      }
      const next = measureGuideBox(target)
      setBox(prev => JSON.stringify(prev) === JSON.stringify(next) ? prev : next)
      const complete = action.done(scenarioStore.getSnapshot(), document)
      const onPage = (!step.read && (actionIndex > 0 || step.id === 'inbox') || atStep)
      const allDone = step.id !== 'finish' || SCAN_STEPS.slice(0, -1).every(x => scenarioStore.getSnapshot().completed.includes(x.id))
      const pending = scenarioStore.getSnapshot().assessments.some(a => a.scan && !a.scan.finishedAt) || scenarioStore.getSnapshot().syncs.some(r => !r.finishedAt)
      if (execution.current?.key === actionKey && (complete || !pending && Date.now() - execution.current.startedAt > 1500 && canClickDemoControl(found))) {
        if (!complete) setRetry(actionKey)
        execution.current = null; setExecuting(null)
      }
      const canExecute = Boolean(action.auto && onPage && canClickDemoControl(found) && !pending)
      setObserved(prev => { const ready = complete && onPage && allDone; return prev.key === actionKey && prev.ready === ready && prev.canExecute === canExecute ? prev : { key: actionKey, ready, canExecute } })
    }
    observe()
    // Poll after the form commits. Observing DOM mutations synchronously can repeatedly
    // activate a portal option before a query-string filter has rendered its new value.
    document.addEventListener('input', observe)
    document.addEventListener('change', observe)
    window.addEventListener('resize', observe)
    window.addEventListener('scroll', observe, true)
    const timer = window.setInterval(observe, 300)
    return () => {
      target?.removeAttribute('data-demo-focus')
      filled?.removeAttribute('data-demo-filled')
      raised?.removeAttribute('data-demo-modal-layer')
      window.clearInterval(timer)
      document.removeEventListener('input', observe); document.removeEventListener('change', observe)
      window.removeEventListener('resize', observe); window.removeEventListener('scroll', observe, true)
    }
  }, [active, action, actionKey, actionIndex, atStep, step, manual, review, s.step, s.microStep, actions.length, location.pathname])
  useEffect(() => { if (active) { if (content.current) content.current.scrollTop = 0; heading.current?.focus({ preventScroll: true }) } }, [active, s.step, actionIndex, host])
  useEffect(() => { if (active && ready && action.auto && !manual && !review && !step.ready(s)) advance() }, [active, ready, action.auto, manual, review, advance, step, s])
  useEffect(() => { execution.current = null; setExecuting(null); setRetry(null) }, [actionKey, active])
  if (!active) return null
  const onNext = () => {
    if (execution.current?.key === actionKey) return
    if (ready) { advance(); return }
    if (step.id === 'publish') { publishDemoAdvisory(); return }
    const target = findGuideTarget(action.target)
    if (action.auto && canClickDemoControl(target)) {
      execution.current = { key: actionKey, startedAt: Date.now() }; setExecuting(actionKey); setRetry(null)
      // Let the guide's press finish before activating another React Aria control.
      queueMicrotask(() => { if (execution.current?.key === actionKey && target!.isConnected) target!.click() })
    } else if (!atStep) {
      if (!review && !action.route) updateScenario(d => { d.microStep = 0 })
      navigate(actionRoute)
    }
  }

  const back = () => {
    setManual(true)
    if (actionIndex > 0) updateScenario(d => { d.completed = d.completed.filter(id => id !== 'finish'); d.microStep = actionIndex - 1 })
    else if (s.step > 0) {
      updateScenario(d => { d.completed = d.completed.filter(id => id !== 'finish'); d.step -= 1; d.microStep = guidedActions(SCAN_STEPS[d.step]).length - 1 })
      navigate(SCAN_STEPS[s.step - 1].route(scenarioStore.getSnapshot()))
    }
  }
  const closeComparison = document.querySelector<HTMLElement>('[aria-label="Close comparison configuration"]')
  const waiting = ['scan', 'retest-scan'].includes(step.id) && !action.pipeline && s.assessments.some(a => a.scan && !a.scan.finishedAt) || ['initial-sync', 'monitor-sync'].includes(step.id) && s.syncs.some(r => !r.finishedAt)
  const canNext = ready || observed.key === actionKey && observed.canExecute || step.id === 'publish' || !atStep
  const exampleValue = demoValue(action, s)
  const following = nextChapter('code')!
  return createPortal(<div data-guided-demo>
    <style>{'[data-demo-modal-layer] { z-index: 110 !important; } [data-demo-focus] { scroll-margin-top: 6rem; } [data-demo-filled] { background-color: var(--color-bg-brand-primary, #f9f5ff); transition: background-color 200ms ease; }'}</style>
    <GuideSpotlight box={box} minimized={minimized} />
    <aside role="region" aria-label="Code Security Walkthrough" className={guidePanelClass} style={guidePlacement(box)}>
      <div className="mb-3 flex shrink-0 items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-tertiary"><Flag05 className="size-4 text-fg-brand-primary" aria-hidden="true" /><span>Step {s.step + 1} of {SCAN_STEPS.length} · {step.chapter}</span></div>
        <div className="flex shrink-0 items-center"><GuideToggle minimized={minimized} onToggle={() => setMinimized(v => !v)} /><Button size="sm" color="tertiary" iconLeading={XClose} aria-label="Pause code security walkthrough" onClick={() => updateScenario(d => { d.open = false })} /></div>
      </div>
      {minimized && <p className="text-sm font-semibold text-primary">{finished ? 'Code security walkthrough complete' : action.title}</p>}
      <div ref={content} hidden={minimized} className="min-h-0 overflow-y-auto overscroll-contain">
      <p className="mb-1 text-xs font-medium text-brand-secondary">{review ? 'Review' : `Action ${actionIndex + 1} of ${actions.length - 1}`}</p>
      <h2 ref={heading} tabIndex={-1} className="text-md font-semibold text-primary outline-hidden">{finished ? 'Code security walkthrough complete' : action.title}</h2>
      <p className="mt-2 text-sm leading-relaxed text-secondary">{step.id === 'publish' && ready ? step.expected : action.body}</p>
      {action.example && <div className="mt-3 rounded-lg border border-brand-solid/30 bg-brand-primary px-3 py-2">
        <p className="text-xs font-medium text-brand-secondary">Filled automatically</p>
        <p className="mt-1 break-words font-mono text-sm font-medium text-primary">{exampleValue === '' ? 'No credential required' : exampleValue ?? (action.example.checked ? 'Selected' : 'Not selected')}</p>
      </div>}
      <p className="mt-3 border-l-2 border-brand-solid pl-3 text-sm leading-relaxed text-secondary"><span className="font-medium">Why: </span>{action.why}</p>
      {closeComparison && ['baseline', 'retest-snapshot'].includes(step.id) && <div className="mt-3"><Button size="sm" color="secondary" onClick={() => closeComparison.click()}>Close comparison dialog</Button></div>}
      {!atStep && (step.read || !review && !box) && <div className="mt-3"><Button size="sm" color="secondary" onClick={() => navigate(actionRoute)}>Go to this step</Button></div>}
      {!review && !box && !ready && !action.auto && <div className="mt-3"><Button size="sm" color="secondary" onClick={() => { updateScenario(d => { d.microStep = 0 }); navigate(step.route(s)) }}>Reopen this step</Button></div>}
      <p role="status" className={`mt-3 flex items-center gap-1.5 text-xs ${ready ? 'text-success-primary' : 'text-tertiary'}`}>
        {ready && <CheckCircle className="size-4" aria-hidden="true" />}
        {finished ? 'All steps complete. Your demo data remains available.' : ready ? review ? 'Review the result, then continue.' : 'Ready to continue.' : waiting ? 'Job in progress. Waiting for completion…' : step.id === 'publish' ? 'Select Next to publish the demo advisory.' : review ? 'Preparing this step…' : action.pipeline ? 'Waiting for this scan phase to complete…' : action.auto ? executing === actionKey ? 'Performing the highlighted action…' : 'Next performs the highlighted action for you.' : action.example ? 'Preparing the example value…' : 'Preparing the highlighted result…'}
      </p>
      {retry === actionKey && <p role="alert" className="mt-2 text-xs text-warning-primary">The action has not completed. Select Next to retry, or review the message on the page.</p>}
      {s.storageWarning && <p role="alert" className="mt-2 text-xs text-warning-primary">Progress is kept in this tab only. Browser storage is unavailable.</p>}
      {finished && <p className="mt-3 text-sm text-secondary">Continue your journey with {following.title}.</p>}
      </div>
      <div className="mt-3 flex shrink-0 justify-between gap-2">
        {!finished && <GuideProgress index={s.step} total={SCAN_STEPS.length} />}
        <div className="flex flex-wrap justify-end gap-2"><Button size="sm" color="secondary" iconLeading={ArrowLeft} isDisabled={s.step === 0 && actionIndex === 0} onClick={back}>Back</Button>
        {finished ? <div className="flex flex-wrap gap-2"><Button size="sm" color="secondary" onClick={() => updateScenario(d => { d.open = false })}>Explore results</Button><Button size="sm" color="primary" iconTrailing={ArrowRight} onClick={() => startDemoChapter(following.mode)}>Next chapter</Button></div> : <Button key={actionKey} size="sm" color="primary" iconTrailing={ArrowRight} isDisabled={!canNext || waiting || executing === actionKey} isLoading={waiting || executing === actionKey} showTextWhileLoading onPress={onNext}>{step.id === 'finish' ? 'Finish' : 'Next'}</Button>}
        </div>
      </div>
    </aside>
  </div>, host)
}
