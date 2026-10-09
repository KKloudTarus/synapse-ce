import { GuideSpotlight, GuideProgress, scrollGuideTarget, measureGuideBox } from '../GuideSpotlight'
import { guidePlacement } from '../guide-placement'
import { GuideToggle, guidePanelClass } from '../GuideToggle'
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { createPortal } from 'react-dom'
import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, CheckCircle, Flag05, XClose } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { canClickDemoControl, demoValue, fillDemoControl } from '../demo-controls'
import { findGuideTarget } from '../guided-actions'
import { isWorkflow, settleWorkflows, updateWorkflows, workflowStore } from './store'
import { WORKFLOW_NAMES, WORKFLOW_STEPS, workflowRoute } from './steps'
import { nextChapter, startDemoChapter } from '../journey'
import { restoreWorkflowControls } from './restore'

type Box = { top: number; left: number; width: number; height: number }
export function WorkflowWalkthrough() {
  const s = useSyncExternalStore(workflowStore.subscribe, workflowStore.getSnapshot)
  const location = useLocation(), navigate = useNavigate()
  const mode = isWorkflow(s.mode) ? s.mode : null
  const progress = mode ? s[mode] : null
  const stepIndex = progress?.step ?? 0
  const step = mode && progress ? WORKFLOW_STEPS[mode][progress.step] : null
  const active = Boolean(step && progress?.open && location.pathname !== '/demo')
  const [minimized, setMinimized] = useState(false)
  const [host, setHost] = useState<HTMLElement>(document.body)
  const [box, setBox] = useState<Box | null>(null)
  const actionKey = `${mode}:${stepIndex}`
  const [observed, setObserved] = useState({ key: '', ready: false, canExecute: false })
  const [busy, setBusy] = useState(false), [error, setError] = useState('')
  const executing = useRef(false), heading = useRef<HTMLHeadingElement>(null)
  const onPage = step?.route.split('?')[0] === location.pathname
  const advance = () => {
    if (!mode || !step || !progress) return
    const current = workflowStore.getSnapshot()
    if (!step.done(current, document) && !current[mode].completed.includes(progress.step)) return
    if (step.finish && WORKFLOW_STEPS[mode].slice(0, -1).some((_, index) => !current[mode].completed.includes(index))) return
    updateWorkflows(d => { const p = d[mode]; if (!p.completed.includes(p.step)) p.completed.push(p.step); if (step.finish) p.complete = true; else p.step++ })
    if (!step.finish) navigate(workflowRoute(mode, workflowStore.getSnapshot()))
  }
  useEffect(() => {
    if (!mode) return
    const timer = window.setInterval(settleWorkflows, 500)
    return () => window.clearInterval(timer)
  }, [mode])
  useEffect(() => {
    if (!active || !step || !mode) return
    let target: HTMLElement | null = null, raised: HTMLElement | null = null
    const measure = () => {
      const next = measureGuideBox(target)
      setBox(previous => JSON.stringify(previous) === JSON.stringify(next) ? previous : next)
    }
    const observe = () => {
      const current = workflowStore.getSnapshot()
      const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(el => !el.closest('[data-guided-demo], [hidden], [inert]') && (!el.closest('[aria-hidden="true"]') || Boolean(el.querySelector('[role="listbox"]'))) && el.getClientRects().length > 0)
      setHost(dialog ?? document.body)
      let layer = dialog ?? null
      for (let parent = dialog?.parentElement; parent && parent !== document.body; parent = parent.parentElement) if (getComputedStyle(parent).position === 'fixed') layer = parent
      if (layer !== raised) { raised?.removeAttribute('data-demo-modal-layer'); raised = layer; raised?.setAttribute('data-demo-modal-layer', '') }
      if (onPage && !current[mode].completed.includes(stepIndex)) { restoreWorkflowControls(current); fillDemoControl(step, current) }
      if (mode === 'ai' && onPage) document.querySelectorAll<HTMLDetailsElement>('[data-ai-review-evidence]').forEach(el => { el.open = true })
      const found = onPage ? findGuideTarget(step.target) : null
      const spotlight = onPage && step.spotlight ? findGuideTarget(step.spotlight) : found
      if (spotlight !== target && !document.querySelector('[role="listbox"]')) {
        target?.removeAttribute('data-demo-focus'); target?.removeAttribute('data-demo-filled')
        target = spotlight; target?.setAttribute('data-demo-focus', '')
        if (step.example) target?.setAttribute('data-demo-filled', '')
        scrollGuideTarget(target)
      }
      measure()
      const allDone = !step.finish || WORKFLOW_STEPS[mode].slice(0, -1).every((_, index) => current[mode].completed.includes(index))
      const ready = allDone && (step.done(current, document) || current[mode].completed.includes(stepIndex))
      const canExecute = onPage && (Boolean(step.perform) || Boolean(step.auto && canClickDemoControl(found)))
      setObserved(previous => previous.key === actionKey && previous.ready === ready && previous.canExecute === canExecute ? previous : { key: actionKey, ready, canExecute })
    }
    observe()
    const timer = window.setInterval(observe, 300)
    window.addEventListener('scroll', measure, true); window.addEventListener('resize', measure)
    return () => { window.clearInterval(timer); window.removeEventListener('scroll', measure, true); window.removeEventListener('resize', measure); target?.removeAttribute('data-demo-focus'); target?.removeAttribute('data-demo-filled'); raised?.removeAttribute('data-demo-modal-layer') }
  }, [active, mode, stepIndex, step, onPage, actionKey])
  useEffect(() => { setBusy(false); executing.current = false; setError(''); heading.current?.focus({ preventScroll: true }) }, [mode, progress?.step, active])
  useEffect(() => {
    if (busy && executing.current && observed.key === actionKey && observed.ready && !step?.perform) { executing.current = false; setBusy(false); advance() }
    // Read the latest immutable snapshot when a native API mutation completes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busy, observed.key, observed.ready, actionKey])
  useEffect(() => {
    if (!busy || step?.perform) return
    const timer = window.setTimeout(() => { executing.current = false; setBusy(false); setError('The action has not completed. Review the page message, then select Next to retry.') }, 12000)
    return () => window.clearTimeout(timer)
  }, [busy, step])
  if (!active || !mode || !progress || !step) return null
  const next = async () => {
    if (executing.current) return
    const current = workflowStore.getSnapshot()
    if (step.done(current, document) || current[mode].completed.includes(progress.step)) { advance(); return }
    if (!onPage) { navigate(step.route); return }
    setError('')
    if (step.perform) {
      executing.current = true; setBusy(true)
      try {
        const result = await fetch(`/api/v1${step.perform.path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(step.perform.body ?? {}) })
        if (!result.ok) { const data = await result.json(); throw new Error(data.message ?? 'The training action failed.') }
        // Reload only after the API checkpoint is saved, so native screens read the new dataset.
        window.location.reload()
      } catch (e) { setError(e instanceof Error ? e.message : 'The training action failed.'); setBusy(false); executing.current = false }
    } else {
      const target = findGuideTarget(step.target)
      if (step.auto && canClickDemoControl(target)) { executing.current = true; setBusy(true); queueMicrotask(() => target?.click()) }
    }
  }
  const ready = observed.key === actionKey && observed.ready
  const canExecute = observed.key === actionKey && observed.canExecute
  const finished = progress.complete
  const following = nextChapter(mode)
  return createPortal(<div data-guided-demo>
    <style>{'[data-demo-modal-layer] { z-index: 110 !important; } [data-demo-focus] { scroll-margin-top: 6rem; } [data-demo-filled] { background-color: var(--color-bg-brand-primary, #f9f5ff); }'}</style>
    <GuideSpotlight box={box} minimized={minimized} />
    <aside role="region" aria-label={WORKFLOW_NAMES[mode]} className={guidePanelClass} style={guidePlacement(box)}>
      <div className="mb-3 flex shrink-0 items-center justify-between gap-3"><div className="flex items-center gap-2 text-xs text-tertiary"><Flag05 className="size-4 text-fg-brand-primary" /><span>Step {progress.step + 1} of {WORKFLOW_STEPS[mode].length} · {step.chapter}</span></div><div className="flex shrink-0 items-center"><GuideToggle minimized={minimized} onToggle={() => setMinimized(v => !v)} /><Button size="sm" color="tertiary" iconLeading={XClose} aria-label="Pause walkthrough" onClick={() => updateWorkflows(d => { d[mode].open = false })} /></div></div>
      {minimized && <p className="text-sm font-semibold text-primary">{step.title}</p>}
      <div hidden={minimized} className="min-h-0 overflow-y-auto overscroll-contain"><h2 ref={heading} tabIndex={-1} className="text-md font-semibold text-primary outline-hidden">{step.title}</h2><p className="mt-2 text-sm leading-relaxed text-secondary">{finished ? 'Your demo data remains available. Close the guide to explore the recorded results.' : step.body}</p>
        {step.example && <div className="mt-3 rounded-lg border border-brand-solid/30 bg-brand-primary px-3 py-2"><p className="text-xs font-medium text-brand-secondary">Filled automatically</p><p className="mt-1 break-words font-mono text-sm font-medium text-primary">{demoValue(step, s)}</p></div>}
        <p className="mt-3 border-l-2 border-brand-solid pl-3 text-sm leading-relaxed text-secondary"><span className="font-medium">Why: </span>{step.why}</p>
        <p role="status" className={`mt-3 flex items-center gap-1.5 text-xs ${ready ? 'text-success-primary' : 'text-tertiary'}`}>{ready && <CheckCircle className="size-4" />}{finished ? 'All steps complete. Your demo data remains available.' : busy ? 'Performing the highlighted action…' : ready ? step.perform ? 'Action complete. Review the highlighted result, then select Continue.' : 'Review the result, then continue.' : canExecute ? 'Next performs the highlighted action for you.' : 'Waiting for the highlighted result…'}</p>
        {finished && <p className="mt-3 text-sm text-secondary">{following ? `Continue your journey with ${following.title}.` : 'Return to the journey to review your progress and choose another chapter.'}</p>}
        {error && <p role="alert" className="mt-2 text-xs text-warning-primary">{error}</p>}{s.storageWarning && <p role="alert" className="mt-2 text-xs text-warning-primary">Progress is kept in this tab only. Browser storage is unavailable.</p>}
      </div>
      <div className="mt-3 flex shrink-0 justify-between gap-2">{!finished && <GuideProgress index={progress.step} total={WORKFLOW_STEPS[mode].length} />}<div className="flex flex-wrap justify-end gap-2"><Button size="sm" color="secondary" iconLeading={ArrowLeft} isDisabled={progress.step === 0 || busy} onClick={() => { updateWorkflows(d => { d[mode].step--; d[mode].complete = false }); navigate(workflowRoute(mode, workflowStore.getSnapshot())) }}>Back</Button>{finished ? <div className="flex flex-wrap gap-2"><Button size="sm" color="secondary" onClick={() => updateWorkflows(d => { d[mode].open = false })}>Explore results</Button><Button size="sm" color="primary" iconTrailing={ArrowRight} onClick={() => following ? startDemoChapter(following.mode) : navigate('/demo')}>{following ? 'Next chapter' : 'Return to journey'}</Button></div> : <Button key={progress.step} size="sm" color="primary" iconTrailing={ArrowRight} isDisabled={busy || !(ready || canExecute || !onPage)} isLoading={busy} showTextWhileLoading onPress={() => void next()}>{step.finish ? 'Finish' : step.perform && ready ? 'Continue' : 'Next'}</Button>}</div></div>
    </aside>
  </div>, host)
}
