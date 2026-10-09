import { useRef, useState, useSyncExternalStore } from 'react'
import { ArrowRight, CheckCircle, Code02, GitBranch01, LayersTwo01, ShieldTick, CpuChip01, Activity, Settings02 } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { scenarioStore } from './scenario/store'
import { workflowStore, type DemoMode } from './workflows/store'
import { ADVANCED_CHAPTERS, DEMO_JOURNEY, chapterComplete, recommendedChapter, startDemoChapter } from './journey'
import { advancedStore, isAdvanced } from './advanced/store'
import './demo-journey.css'

const phases = [
  { title: 'Explore', description: 'Find your bearings', modes: ['overview'] },
  { title: 'Assess', description: 'Understand the findings', modes: ['quality', 'code'] },
  { title: 'Connect', description: 'Prepare your workflow', modes: ['ci-setup', 'ai-setup'] },
  { title: 'Operate', description: 'Put insight into action', modes: ['ai', 'runtime'] },
] as const
const chapters = [...DEMO_JOURNEY, ...ADVANCED_CHAPTERS]
const icons = { overview: LayersTwo01, quality: Code02, code: ShieldTick, 'ci-setup': GitBranch01, 'ai-setup': Settings02, ai: CpuChip01, runtime: Activity, remediation: ShieldTick, intelligence: Activity, policy: GitBranch01 }

export function DemoEntry() {
  const scenario = useSyncExternalStore(scenarioStore.subscribe, scenarioStore.getSnapshot)
  const workflows = useSyncExternalStore(workflowStore.subscribe, workflowStore.getSnapshot)
  const advanced = useSyncExternalStore(advancedStore.subscribe, advancedStore.getSnapshot)
  const recommended = recommendedChapter(scenario, workflows)
  const [selected, setSelected] = useState<DemoMode>(() => recommended?.mode ?? 'overview')
  const preview = useRef<HTMLElement>(null)
  const chapter = chapters.find(item => item.mode === selected)!
  const completed = DEMO_JOURNEY.filter(item => chapterComplete(item.mode, scenario, workflows)).length
  const advancedCompleted = ADVANCED_CHAPTERS.filter(item => advanced[item.mode].complete).length
  const complete = chapterComplete(selected, scenario, workflows)
  const progress = isAdvanced(selected) ? advanced[selected] : selected !== 'overview' && selected !== 'code' ? workflows[selected] : null
  const started = selected === 'code' ? Boolean(scenario.asset) : Boolean(progress && (progress.step > 0 || progress.completed.length > 0))
  const action = selected === 'overview' ? complete ? 'Review tour' : 'Start tour' : complete ? 'Review walkthrough' : started ? 'Resume walkthrough' : 'Start walkthrough'
  const SelectedIcon = icons[selected]

  function selectChapter(mode: DemoMode) {
    setSelected(mode)
    preview.current?.focus({ preventScroll: true })
    preview.current?.scrollIntoView({ block: 'nearest', behavior: 'instant' })
  }

  function node(mode: DemoMode) {
    const item = chapters.find(item => item.mode === mode)!
    const index = DEMO_JOURNEY.findIndex(item => item.mode === mode)
    const done = chapterComplete(mode, scenario, workflows)
    const next = recommended?.mode === mode
    const Icon = icons[mode]
    const nodeProgress = isAdvanced(mode) ? advanced[mode] : mode !== 'overview' && mode !== 'code' ? workflows[mode] : null
    const inProgress = mode === 'code' ? Boolean(scenario.asset) : Boolean(nodeProgress && (nodeProgress.step > 0 || nodeProgress.completed.length > 0))
    return <button type="button" key={mode} data-demo-chapter={mode} data-level={'level' in item ? item.level : 'Specialist'} aria-pressed={selected === mode} aria-controls="chapter-preview" onClick={() => selectChapter(mode)}
      className="journey-node relative w-full rounded-xl border p-4 text-left shadow-xs outline-offset-4 focus-visible:outline-2">
      <span className="flex items-center justify-between gap-2">
        <span className="journey-level-icon flex size-8 items-center justify-center rounded-lg"><Icon className="size-4" aria-hidden="true" /></span>
        <span className={`flex items-center gap-1 text-xs font-medium ${done ? 'text-success-primary' : next ? 'text-brand-secondary' : 'text-tertiary'}`}>{done ? <><CheckCircle className="size-3.5" aria-hidden="true" />Completed</> : next ? 'Up next' : inProgress ? 'In progress' : index >= 0 ? 'Ready to explore' : 'Optional'}</span>
      </span>
      <span className="mt-3 flex items-start gap-2"><span className="pt-0.5 text-xs font-medium tabular-nums text-tertiary">{index >= 0 ? String(index + 1).padStart(2, '0') : '↳'}</span><span className="text-sm font-semibold leading-5 text-primary">{item.title}</span></span>
      <span className="mt-2 flex items-center justify-between gap-2 text-xs text-tertiary"><span className="journey-level-badge">{'level' in item ? item.level : 'Specialist'}</span><span>{mode === 'overview' ? '20 steps' : item.detail.split(' · ')[0]}</span></span>
    </button>
  }

  return <main className="min-h-dvh bg-secondary px-4 py-7 sm:px-8 sm:py-9">
    <div className="mx-auto max-w-7xl">
      <header className="mb-6 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div className="max-w-2xl">
          <div className="mb-3 flex items-center gap-3"><span className="text-lg font-semibold text-primary">Synapse</span><span className="rounded-md border border-secondary bg-primary px-2 py-0.5 text-xs font-medium text-secondary">Playground</span></div>
          <h1 className="text-display-sm font-semibold tracking-tight text-primary">Your Synapse journey</h1>
          <p className="mt-2 text-sm leading-6 text-secondary">From your first look to advanced operations. Follow the path or choose a chapter to explore.</p>
        </div>
        <div className="w-full shrink-0 lg:w-64">
          <div className="flex justify-between text-xs"><span className="font-medium text-secondary">Core journey</span><span className="text-tertiary">{completed} / {DEMO_JOURNEY.length} complete</span></div>
          <div role="progressbar" aria-label="Journey progress" aria-valuemin={0} aria-valuemax={DEMO_JOURNEY.length} aria-valuenow={completed} aria-valuetext={`${completed} of ${DEMO_JOURNEY.length} chapters complete`} className="mt-2 h-1.5 overflow-hidden rounded-full bg-tertiary"><div className="h-full rounded-full bg-brand-solid" style={{ width: `${completed / DEMO_JOURNEY.length * 100}%` }} /></div>
          <p className="mt-2 text-xs text-tertiary">{completed === DEMO_JOURNEY.length ? 'Core complete. Explore a specialist chapter.' : 'Your progress is saved in this browser.'}</p>
        </div>
      </header>

      <section ref={preview} tabIndex={-1} id="chapter-preview" data-level={'level' in chapter ? chapter.level : 'Specialist'} aria-labelledby="chapter-preview-title" className="journey-preview mb-6 scroll-mt-5 rounded-xl outline-none border bg-primary p-5 shadow-xs sm:p-6">
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 gap-4">
            <span className="journey-level-icon hidden size-12 shrink-0 items-center justify-center rounded-xl sm:flex"><SelectedIcon className="size-6" aria-hidden="true" /></span>
            <div aria-live="polite" aria-atomic="true" className="min-w-0 max-w-3xl">
              <p className="text-xs font-medium text-brand-secondary">{recommended?.mode === selected ? 'Recommended next' : complete ? 'Completed chapter' : 'Chapter preview'}<span className="journey-level-badge ml-2">{'level' in chapter ? chapter.level : 'Specialist'}</span></p>
              <h2 id="chapter-preview-title" className="mt-1 text-lg font-semibold text-primary">{chapter.title}</h2>
              <p className="mt-1 text-sm leading-6 text-secondary">{chapter.description}</p>
              <p className="mt-2 text-xs text-tertiary">{chapter.detail}{started && !complete && progress ? ` · ${progress.completed.length} steps complete` : ''}</p>
              {'prerequisite' in chapter && <p className="mt-2 text-xs text-secondary">Recommended preparation: {chapter.prerequisite}</p>}
            </div>
          </div>
          <div className="flex shrink-0 flex-col gap-2 md:w-52">
            <Button size="lg" color="primary" iconTrailing={ArrowRight} onClick={() => startDemoChapter(selected)}>{action}</Button>
            {started && <Button size="sm" color="tertiary" onClick={() => startDemoChapter(selected, true)}>Start over</Button>}
            {recommended && recommended.mode !== selected && <Button size="sm" color="tertiary" onClick={() => selectChapter(recommended.mode)}>Back to recommended</Button>}
          </div>
        </div>
      </section>

      <section aria-labelledby="journey-map-title" className="overflow-hidden rounded-2xl border border-secondary bg-primary shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-secondary px-5 py-4 sm:px-6">
          <div><h2 id="journey-map-title" className="text-sm font-semibold text-primary">Journey map</h2><p className="mt-1 text-xs text-tertiary">Follow chapters 01–07. Select a node to preview its walkthrough.</p></div>
          <a href="#specialist-chapters" className="rounded text-xs font-medium text-brand-secondary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-brand">Specialist branches <span aria-hidden="true">↓</span></a>
        </div>
        <ul aria-label="Chapter difficulty colors" className="flex flex-wrap gap-x-5 gap-y-2 border-b border-secondary px-5 py-3 text-xs text-secondary sm:px-6">
          {['Foundation / Beginner', 'Intermediate', 'Advanced', 'Specialist'].map(level => <li key={level} data-level={level === 'Foundation / Beginner' ? 'Beginner' : level} className="flex items-center gap-2"><span className="journey-level-dot size-2 rounded-full" aria-hidden="true" />{level}</li>)}
        </ul>
        <div className="journey-canvas px-5 py-6 sm:px-6">
          <div className="journey-phases">
            {phases.map((phase, index) => <section key={phase.title} aria-labelledby={`phase-${index}`} className="journey-phase">
              <div className="journey-phase-label mb-5 flex items-center gap-3">
                <span className="flex size-7 shrink-0 items-center justify-center rounded-full border border-secondary bg-primary text-xs font-medium text-tertiary">{index + 1}</span>
                <div><h3 id={`phase-${index}`} className="text-sm font-semibold text-primary">{phase.title}</h3><p className="mt-0.5 text-xs text-tertiary">{phase.description}</p></div>
              </div>
              <div className="journey-phase-nodes">{phase.modes.map(node)}</div>
            </section>)}
          </div>
          <section id="specialist-chapters" aria-labelledby="specialist-title" className="mt-7 scroll-mt-5 border-t border-dashed border-secondary pt-5">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2"><div><h3 id="specialist-title" className="text-sm font-semibold text-primary">Go deeper</h3><p className="mt-1 text-xs text-tertiary">Optional branches to build on your core skills. Every chapter is open.</p></div><span className="text-xs text-tertiary">{advancedCompleted} / {ADVANCED_CHAPTERS.length} complete</span></div>
            <div className="grid gap-4 md:grid-cols-3">{ADVANCED_CHAPTERS.map(chapter => <div className="journey-branch" key={chapter.mode}><p className="mb-3 flex items-center gap-2 text-xs text-secondary"><GitBranch01 className="size-3.5" aria-hidden="true" />From {chapter.prerequisite.replace(' Walkthrough', '')}</p>{node(chapter.mode)}</div>)}</div>
          </section>
        </div>
      </section>
      <footer className="mt-5 flex flex-col justify-between gap-2 text-xs leading-5 text-tertiary sm:flex-row sm:gap-8"><p>Walkthrough examples are prefilled. Just select Next to follow along.<br />The Platform Overview also includes optional actions to explore.</p><p className="sm:max-w-sm sm:text-right">All activity is simulated in your browser.<br />Progress is saved on this device and browser only.</p></footer>
    </div>
  </main>
}
