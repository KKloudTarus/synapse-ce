import { ArrowLeft, FileUp, FolderGit2, Gauge, GitBranch, Play } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useOutletContext, useParams } from 'react-router-dom'
import { Button, EmptyState, ErrorState, InfoNote, Pill, Spinner, cn } from '../components/ui'
import { api } from '../lib/api'
import type { Project, QualityGate, ScanJob } from '../lib/types'

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

export function CodeQualityProject() {
  const { key = '' } = useParams()
  const location = useLocation()
  const startError = (location.state as { analysisStartError?: string } | null)?.analysisStartError
  const [project, setProject] = useState<Project | null | undefined>(undefined)
  const [job, setJob] = useState<ScanJob | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [operationError, setOperationError] = useState<string | null>(startError ?? null)
  const [coverageFile, setCoverageFile] = useState<File | null>(null)
  const [gates, setGates] = useState<QualityGate[]>([])
  const [analysisRevision, setAnalysisRevision] = useState(0)
  const poll = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pollGeneration = useRef<symbol | null>(null)
  const lastTerminalJob = useRef<string | null>(null)

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

  useEffect(() => {
    let live = true
    api.listQualityGates().then((next) => live && setGates(next)).catch(() => live && setGates([]))
    return () => {
      live = false
    }
  }, [])

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
        <Link to="/code-quality" className="inline-flex items-center gap-1.5 text-sm text-branddim hover:underline">
          <ArrowLeft className="size-4" aria-hidden="true" /> All projects
        </Link>
      </div>
    )
  }
  if (project === undefined) return <Spinner label="Loading project…" />
  if (!project) return null

  const status = isRunning ? 'Analyzing' : job?.status === 'failed' ? 'Failed' : 'Ready'
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
    <div className="mx-auto max-w-7xl animate-fade-in">
      <Link
        to="/code-quality"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-mutedfg transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> All projects
      </Link>
      <header className="bg-hero mb-6 rounded-xl border border-border p-6">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-branddim">
              <Gauge className="size-4" aria-hidden="true" />
              Code Quality project
            </div>
            <h1 className="truncate text-3xl font-bold tracking-tight">{project.name}</h1>
            <p className="mt-1.5 font-mono text-sm text-mutedfg">{project.key}</p>
          </div>
          <div className="flex max-w-xl flex-wrap items-center justify-end gap-2">
            <Pill className="shrink-0 bg-elevated ring-1 ring-inset ring-border">
              <Gauge className="size-3" aria-hidden="true" /> {status}
            </Pill>
            <label
              className={cn(
                'inline-flex cursor-pointer items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2 text-sm focus-within:ring-2 focus-within:ring-brand/60',
                coverageFile ? 'text-foreground' : 'text-mutedfg',
              )}
              title={coverageFile?.name ?? 'Optional LCOV, Cobertura, or JaCoCo report'}
            >
              <FileUp className="size-4" aria-hidden="true" />
              <span className="max-w-48 truncate">{coverageFile ? coverageFile.name : 'Attach coverage'}</span>
              <input
                aria-label="Coverage report (optional)"
                className="sr-only"
                type="file"
                accept=".info,.lcov,.xml,text/plain,application/xml,text/xml"
                disabled={isRunning}
                onChange={(event) => setCoverageFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <Button variant="brand" loading={isRunning} disabled={isRunning} onClick={startAnalysis}>
              <Play className="size-4" aria-hidden="true" />
              Run analysis
            </Button>
          </div>
        </div>
        <dl className="mt-5 grid grid-cols-1 gap-4 border-t border-border pt-4 text-sm md:grid-cols-3">
          <div className="min-w-0">
            <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Source</dt>
            <dd className="mt-1.5 flex min-w-0 items-center gap-2 text-foreground">
              <FolderGit2 className="size-4 shrink-0 text-mutedfg" aria-hidden="true" />
              <span className="capitalize">{project.sourceBinding.kind}</span>
              <span className="truncate font-mono text-xs" title={project.sourceBinding.value}>
                {project.sourceBinding.value}
              </span>
            </dd>
          </div>
          <div>
            <dt className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">
              Quality policy for future runs
              <InfoNote label="About quality policies">
                Repository policy uses <code>.synapse-gate.yaml</code> when present and falls back to Synapse way. Selecting a named policy ignores the repository policy. Previous analysis decisions remain unchanged.
              </InfoNote>
            </dt>
            <dd className="mt-1.5">
              <select
                aria-label="Quality gate"
                value={project.gateId}
                disabled={isRunning}
                onChange={(event) => assignGate(event.target.value)}
                className="h-8 rounded border border-border bg-bg px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand/60"
              >
                <option value="">Repository policy (fallback: Synapse way)</option>
                {gates.map((gate) => (
                  <option key={gate.key} value={gate.key}>
                    {gate.name}
                  </option>
                ))}
              </select>
            </dd>
          </div>
          <div>
            <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Branch / ref</dt>
            <dd className="mt-1.5 flex items-center gap-2 font-mono text-xs text-foreground">
              <GitBranch className="size-4 shrink-0 text-mutedfg" aria-hidden="true" />
              {project.sourceBinding.ref || 'Default branch'}
            </dd>
          </div>
        </dl>
        {isRunning && (
          <div className="mt-5">
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className="capitalize text-foreground">{job.stage || 'starting'}…</span>
              <span className="font-mono tabular-nums text-mutedfg">{job.progress}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-elevated">
              <div className="h-full rounded-full bg-brand transition-[width] duration-500" style={{ width: `${Math.max(3, job.progress)}%` }} />
            </div>
          </div>
        )}
      </header>
      <nav className="mb-6 flex gap-4 overflow-x-auto border-b border-border whitespace-nowrap" aria-label="Project views">
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
        isActive ? 'border-brand text-foreground' : 'border-transparent text-mutedfg',
      )}
    >
      {children}
    </NavLink>
  )
}

export function ProjectRouteEmpty({ running }: { running: boolean }) {
  return (
    <EmptyState
      icon={running ? Gauge : Gauge}
      title={running ? 'Analysis in progress' : 'No completed analysis yet'}
      hint={running ? 'The Overview will appear after the first successful analysis completes.' : 'Run an analysis to see the Quality Gate verdict and code-quality metrics.'}
    />
  )
}
