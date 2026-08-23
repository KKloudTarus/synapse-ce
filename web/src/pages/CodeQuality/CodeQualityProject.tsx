import { AlertTriangle, ArrowLeft, BarChart01, Check, CheckCircle, Copy01, Play, Upload01 } from '@untitledui/icons'
import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useOutletContext, useParams } from 'react-router-dom'
import { Button, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type { Project, QualityGate, ScanJob } from '../../lib/types'

export interface ProjectRouteContext {
  projectKey: string
  project: Project
  job: ScanJob | null
  isRunning: boolean
  operationError: string | null
  analysisRevision: number
  startAnalysis: () => Promise<void>
  assignGate: (gateKey: string) => Promise<void>
  coverageFile: File | null
  setCoverageFile: (file: File | null) => void
}

export function useProjectRouteContext() {
  return useOutletContext<ProjectRouteContext>()
}

function formatRepoDisplay(value: string): string {
  if (!value) return 'Git'
  try {
    const cleaned = value.replace(/\.git$/i, '').replace(/\/+$/, '')
    const parts = cleaned.split(/[/:]/).filter(Boolean)
    if (parts.length >= 2) {
      return parts.slice(-2).join('/')
    }
    return parts[parts.length - 1] || value
  } catch {
    return value
  }
}

export function CodeQualityProject() {
  const { key = '' } = useParams()
  const location = useLocation()
  const startError = (location.state as { analysisStartError?: string } | null)?.analysisStartError
  const [project, setProject] = useState<Project | null | undefined>(undefined)
  const [job, setJob] = useState<ScanJob | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [operationError, setOperationError] = useState<string | null>(startError ?? null)
  const [coverageFile, setCoverageFile] = useState<File | null>(null)
  const [analysisRevision, setAnalysisRevision] = useState(0)
  const [copied, setCopied] = useState(false)
  const poll = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pollGeneration = useRef<symbol | null>(null)
  const lastTerminalJob = useRef<string | null>(null)

  function copySource(text: string) {
    if (!text) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  const isRunning = job?.status === 'running'

  function stopPoll(generation?: symbol) {
    if (generation && pollGeneration.current !== generation) return
    pollGeneration.current = null
    if (poll.current) clearTimeout(poll.current)
    poll.current = null
  }

  function noteTerminalJob(next: ScanJob) {
    const marker = `${next.id}:${next.status}:${next.finishedAt ?? ''}`
    if (lastTerminalJob.current === marker) return false
    lastTerminalJob.current = marker
    return true
  }

  function startPoll(projectKey: string) {
    stopPoll()
    const generation = Symbol()
    pollGeneration.current = generation

    const pollOnce = async () => {
      if (pollGeneration.current !== generation) return
      poll.current = null
      try {
        const next = await api.projectAnalysisStatus(projectKey)
        if (pollGeneration.current !== generation) return
        if (!next) throw new Error('Analysis status is unavailable')
        setJob(next)
        if (next.status === 'running') {
          poll.current = setTimeout(pollOnce, 1500)
          return
        }
        stopPoll(generation)
        if (next.status === 'succeeded') {
          if (noteTerminalJob(next)) setAnalysisRevision((value) => value + 1)
        } else {
          setOperationError(next.error || 'Analysis failed')
        }
      } catch (e) {
        if (pollGeneration.current !== generation) return
        stopPoll(generation)
        setOperationError(e instanceof Error ? e.message : 'Failed to refresh analysis status')
      }
    }

    poll.current = setTimeout(pollOnce, 1500)
  }

  useEffect(() => {
    let live = true
    setProject(undefined)
    setLoadError(null)
    setOperationError(startError ?? null)
    setJob(null)
    setAnalysisRevision(0)
    lastTerminalJob.current = null
    Promise.all([api.getProject(key), api.projectAnalysisStatus(key)])
      .then(([nextProject, nextJob]) => {
        if (!live) return
        setProject(nextProject)
        setJob(nextJob)
        if (nextJob?.status === 'running') startPoll(key)
        else if (nextJob?.status === 'failed') setOperationError(nextJob.error || 'Analysis failed')
        else if (nextJob) noteTerminalJob(nextJob)
      })
      .catch((e) => {
        if (live) setLoadError(e instanceof Error ? e.message : 'Failed to load project')
      })
    return () => {
      live = false
      stopPoll()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, startError])

  const { data: fetchedGates } = useFetch(
    () => api.listQualityGates().catch(() => [] as QualityGate[]),
    { deps: [] },
  )
  const gates = fetchedGates ?? []

  if (project && project.key !== key) return <Spinner label="Loading project…" />

  async function assignGate(gateId: string) {
    setOperationError(null)
    try {
      setProject(await api.assignProjectGate(key, gateId))
    } catch (e) {
      setOperationError(e instanceof Error ? e.message : 'Failed to assign quality gate')
    }
  }

  async function startAnalysis() {
    setOperationError(null)
    try {
      const next = await api.startProjectAnalysis(key, coverageFile ?? undefined)
      setCoverageFile(null)
      setJob(next)
      startPoll(key)
    } catch (e) {
      setOperationError(e instanceof Error ? e.message : 'Failed to start analysis')
    }
  }

  if (loadError && project === undefined) {
    return (
      <div className="mx-auto max-w-6xl space-y-3">
        <ErrorState message={loadError} />
        <Link to="/code-quality" className="inline-flex items-center gap-1.5 text-sm text-brand-secondary hover:underline">
          <ArrowLeft className="size-4" aria-hidden="true" /> All projects
        </Link>
      </div>
    )
  }
  if (project === undefined) return <Spinner label="Loading project…" />
  if (!project) return null

  const statusMeta = isRunning
    ? { label: 'Analyzing', icon: BarChart01, tone: 'border-brand/30 bg-brand/10 text-brand-secondary ring-brand/30' }
    : job?.status === 'failed'
    ? { label: 'Failed', icon: AlertTriangle, tone: 'border-critical/35 bg-critical/10 text-critical ring-critical/35' }
    : { label: 'Ready', icon: CheckCircle, tone: 'border-low/30 bg-low/10 text-low ring-low/30' }
  const StatusIcon = statusMeta.icon

  const context: ProjectRouteContext = {
    projectKey: key,
    project,
    job,
    isRunning,
    operationError,
    analysisRevision,
    startAnalysis,
    assignGate,
    coverageFile,
    setCoverageFile,
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <Link
        to="/code-quality"
        className="inline-flex items-center gap-1.5 text-sm text-tertiary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> All projects
      </Link>
      <header className="bg-hero rounded-xl border border-secondary p-5 shadow-xs">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="truncate text-2xl font-bold tracking-tight text-primary">{project.name}</h1>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-sm text-tertiary">
              <span className="font-mono text-xs">{project.key}</span>
              <span className="text-quaternary">·</span>
              {project.sourceBinding.kind === 'git' && project.sourceBinding.value ? (
                <span className="inline-flex items-center gap-1">
                  <span className="font-mono text-xs text-secondary" title={project.sourceBinding.value}>
                    {formatRepoDisplay(project.sourceBinding.value)}
                  </span>
                  <button
                    type="button"
                    onClick={() => copySource(project.sourceBinding.value)}
                    className="inline-flex size-5 items-center justify-center rounded text-quaternary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                    title={copied ? 'Copied Git URL!' : `Copy: ${project.sourceBinding.value}`}
                    aria-label="Copy Git URL"
                  >
                    {copied ? (
                      <Check className="size-3 text-low" aria-hidden="true" />
                    ) : (
                      <Copy01 className="size-3" aria-hidden="true" />
                    )}
                  </button>
                </span>
              ) : (
                <span className="capitalize">{project.sourceBinding.kind}</span>
              )}
              <span className="text-quaternary">·</span>
              <span className="font-mono text-xs">{project.sourceBinding.ref || 'main'}</span>
              <span className="text-quaternary">·</span>
              <select
                aria-label="Quality gate"
                value={project.gateId}
                disabled={isRunning}
                onChange={(event) => assignGate(event.target.value)}
                className="h-6 rounded border border-secondary bg-primary px-1.5 text-xs text-primary focus:outline-none focus:ring-2 focus:ring-brand/60"
              >
                <option value="">Synapse way</option>
                {gates.map((gate) => (
                  <option key={gate.key} value={gate.key}>{gate.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <Pill className={cn('shrink-0 ring-1 ring-inset', statusMeta.tone)}>
              <StatusIcon className="size-3" aria-hidden="true" /> {statusMeta.label}
            </Pill>
            <label className={cn('inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-secondary bg-primary px-2.5 py-1.5 text-xs', coverageFile ? 'text-primary' : 'text-tertiary')}>
              <Upload01 className="size-3.5" aria-hidden="true" />
              <span className="max-w-32 truncate">{coverageFile ? coverageFile.name : 'Coverage'}</span>
              <input aria-label="Coverage report (optional)" className="sr-only" type="file" accept=".info,.lcov,.xml,text/plain,application/xml,text/xml" disabled={isRunning} onChange={(event) => setCoverageFile(event.target.files?.[0] ?? null)} />
            </label>
            <Button variant="brand" loading={isRunning} disabled={isRunning} onClick={startAnalysis}>
              <Play className="size-4" aria-hidden="true" /> Run analysis
            </Button>
          </div>
        </div>
        {isRunning && (
          <div className="mt-4">
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className="capitalize text-primary">{job.stage || 'starting'}…</span>
              <span className="font-mono tabular-nums text-tertiary">{job.progress}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
              <div className="h-full rounded-full bg-brand transition-[width] duration-500" style={{ width: `${Math.max(3, job.progress)}%` }} />
            </div>
          </div>
        )}
      </header>
      <nav className="mb-6 flex gap-4 overflow-x-auto border-b border-secondary whitespace-nowrap" aria-label="Project views">
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}`} end>Overview</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/hotspots`}>Security Hotspots</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/issues`}>Issues</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/code`}>Code</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/measures`}>Measures</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/analysis`}>Analysis details</ProjectNavLink>
        <ProjectNavLink to={`/code-quality/projects/${encodeURIComponent(key)}/activity`}>Activity</ProjectNavLink>
      </nav>
      {operationError && <div className="mb-6"><ErrorState message={operationError} /></div>}
      <Outlet context={context} />
    </div>
  )
}

function ProjectNavLink({ to, end = false, children }: { to: string; end?: boolean; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) => cn(
        'shrink-0 border-b-2 px-1 pb-2 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
        isActive ? 'border-brand text-primary' : 'border-transparent text-tertiary',
      )}
    >
      {children}
    </NavLink>
  )
}

export function ProjectRouteEmpty({ running }: { running: boolean }) {
  return (
    <EmptyState
      icon={running ? BarChart01 : BarChart01}
      title={running ? 'Analysis in progress' : 'No completed analysis yet'}
      hint={running ? 'The Overview will appear after the first successful analysis completes.' : 'Run an analysis to see the Quality Gate verdict and code-quality metrics.'}
    />
  )
}
