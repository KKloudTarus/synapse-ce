import {
  AlertTriangle,
  BarChart01,
  CheckCircle,
  Circle,
  Folder,
  GitBranch01,
  Plus,
  SearchLg,
  Upload01,
  XClose,
  XCircle,
} from '@untitledui/icons'
import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../../lib/api'
import type { Grade, Project, ProjectSourceKind } from '../../lib/types'
import { Button, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'

const allowLocalSource = import.meta.env.DEV
type Health = 'all' | 'failing' | 'passing' | 'analyzing' | 'failed' | 'unanalyzed'
type SortOption = 'recent' | 'name' | 'issues' | 'failed'

function formatLang(key: string): string {
  const map: Record<string, string> = {
    go: 'Go',
    golang: 'Go',
    ts: 'TypeScript',
    typescript: 'TypeScript',
    js: 'JavaScript',
    javascript: 'JavaScript',
    python: 'Python',
    py: 'Python',
    java: 'Java',
    csharp: 'C#',
    cs: 'C#',
    cpp: 'C++',
    rust: 'Rust',
    rs: 'Rust',
    php: 'PHP',
    ruby: 'Ruby',
    rb: 'Ruby',
    swift: 'Swift',
    kotlin: 'Kotlin',
    kt: 'Kotlin',
    terraform: 'Terraform',
    yaml: 'YAML',
    dockerfile: 'Docker',
  }
  return map[key.toLowerCase()] || key.charAt(0).toUpperCase() + key.slice(1)
}

export function CodeQualityProjects() {
  const { data: projects, error, refetch } = useFetch<Project[]>(
    () => api.listProjects(),
    { deps: [] },
  )
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')
  const [health, setHealth] = useState<Health>('all')
  const [sortBy, setSortBy] = useState<SortOption>('recent')

  const counts = useMemo(() => {
    const next = { failing: 0, passing: 0, analyzing: 0, failed: 0, unanalyzed: 0 }
    for (const project of projects ?? []) next[projectHealth(project)]++
    return next
  }, [projects])

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = (projects ?? []).filter((project) => {
      const matchesQuery =
        !needle ||
        [project.name, project.key, project.sourceBinding.value, project.sourceBinding.ref].some((value) =>
          value.toLowerCase().includes(needle),
        )
      return matchesQuery && (health === 'all' || projectHealth(project) === health)
    })

    return filtered.sort((a, b) => {
      if (sortBy === 'name') {
        return a.name.localeCompare(b.name)
      }
      if (sortBy === 'issues') {
        const aIssues = a.latestAnalysis?.issues.total ?? 0
        const bIssues = b.latestAnalysis?.issues.total ?? 0
        return bIssues - aIssues
      }
      if (sortBy === 'failed') {
        const aFailed = projectHealth(a) === 'failing' || projectHealth(a) === 'failed' ? 1 : 0
        const bFailed = projectHealth(b) === 'failing' || projectHealth(b) === 'failed' ? 1 : 0
        return bFailed - aFailed
      }
      // Default: recent
      const aTime = a.latestAnalysis?.createdAt ? new Date(a.latestAnalysis.createdAt).getTime() : 0
      const bTime = b.latestAnalysis?.createdAt ? new Date(b.latestAnalysis.createdAt).getTime() : 0
      return bTime - aTime
    })
  }, [health, projects, query, sortBy])

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            Code Quality
          </h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="brand"
            className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            onClick={() => setCreating(true)}
          >
            <Plus className="size-4" aria-hidden="true" /> New project
          </Button>
        </div>
      </header>

      {creating && (
        <CreateProjectModal
          onClose={() => setCreating(false)}
          onCreated={refetch}
        />
      )}
      {error && <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={refetch}>Retry</Button></div>}
      {!projects && !error && <Spinner label="Loading projects…" />}
      {projects && projects.length === 0 && (
        <EmptyState
          icon={Folder}
          title="No code quality projects yet"
          hint={`Create a project from Git${allowLocalSource ? ', a server-local path,' : ''} or an uploaded archive. Its first analysis starts automatically.`}
        />
      )}
      {projects && projects.length > 0 && (
        <>
          <section aria-label="Portfolio health" className="flex flex-wrap items-center gap-x-6 gap-y-2.5 rounded-xl border border-secondary bg-primary px-5 py-3.5 shadow-xs">
            <StatPill count={counts.failing} label="Gate failed" tone="critical" />
            <span className="hidden text-quaternary sm:inline" aria-hidden="true">·</span>
            <StatPill count={counts.passing} label="Gate passed" tone="low" />
            <span className="hidden text-quaternary sm:inline" aria-hidden="true">·</span>
            <StatPill count={counts.analyzing} label="Analyzing" tone="brand" />
            <span className="hidden text-quaternary sm:inline" aria-hidden="true">·</span>
            <StatPill count={counts.failed} label="Run failed" tone="critical" />
            <span className="hidden text-quaternary sm:inline" aria-hidden="true">·</span>
            <StatPill count={counts.unanalyzed} label="No analysis" tone="muted" />
          </section>
          <div className="grid gap-3 rounded-xl border border-secondary bg-primary p-3 sm:grid-cols-[1fr_13rem_12rem]">
            <label className="relative">
              <span className="sr-only">Search projects</span>
              <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" aria-hidden="true" />
              <Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects, keys, sources…" />
            </label>
            <Select
              value={health}
              onValueChange={(value) => setHealth(value as Health)}
              ariaLabel="Filter by health"
              options={[
                { value: 'all', label: 'All health states' },
                { value: 'failing', label: 'Gate failed' },
                { value: 'passing', label: 'Gate passed' },
                { value: 'analyzing', label: 'Analyzing' },
                { value: 'failed', label: 'Run failed' },
                { value: 'unanalyzed', label: 'No analysis' },
              ]}
            />
            <Select
              value={sortBy}
              onValueChange={(value) => setSortBy(value as SortOption)}
              ariaLabel="Sort projects"
              options={[
                { value: 'recent', label: 'Recently analyzed' },
                { value: 'name', label: 'Name (A-Z)' },
                { value: 'issues', label: 'Most issues' },
                { value: 'failed', label: 'Failing gate first' },
              ]}
            />
          </div>
          {visible.length === 0 ? (
            <EmptyState
              icon={SearchLg}
              title="No matching projects"
              hint="Change the search or health filter to see more projects."
              action={<Button variant="secondary" onClick={() => { setQuery(''); setHealth('all'); setSortBy('recent') }}>Clear filters</Button>}
            />
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {visible.map((project) => <ProjectCard key={project.id} project={project} />)}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function StatPill({ count, label, tone }: { count: number; label: string; tone: 'critical' | 'low' | 'brand' | 'muted' }) {
  const colors = {
    critical: 'text-critical',
    low: 'text-low',
    brand: 'text-brand-secondary',
    muted: 'text-tertiary',
  }
  return (
    <span className="flex items-center gap-2 text-sm">
      <span className={cn('font-mono text-lg font-bold tabular-nums', colors[tone])}>{count}</span>
      <span className="font-medium text-secondary">{label}</span>
    </span>
  )
}

function projectHealth(project: Project): Exclude<Health, 'all'> {
  if (project.latestJob?.status === 'running') return 'analyzing'
  if (project.latestJob?.status === 'failed') return 'failed'
  if (!project.latestAnalysis) return 'unanalyzed'
  return project.latestAnalysis.gate.passed ? 'passing' : 'failing'
}

function gradeStyle(grade: Grade) {
  switch (grade) {
    case 'A':
      return 'bg-success-primary/15 text-success-primary ring-success-primary/30 border border-success-primary/20'
    case 'B':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 ring-utility-blue-200 dark:ring-utility-blue-800'
    case 'C':
      return 'bg-warning-primary/15 text-warning-primary ring-warning-primary/30 border border-warning-primary/20'
    case 'D':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 ring-utility-orange-200 dark:ring-utility-orange-800'
    case 'E':
      return 'bg-error-primary/15 text-error-primary ring-error-primary/30 border border-error-primary/20'
    default:
      return 'bg-secondary text-tertiary ring-secondary'
  }
}

function ProjectCard({ project }: { project: Project }) {
  const analysis = project.latestAnalysis
  const health = projectHealth(project)
  const healthMeta = {
    failing: { label: 'Gate failed', icon: XCircle, tone: 'border-error/40 bg-error-primary/10 text-error-primary ring-error/20' },
    passing: { label: 'Gate passed', icon: CheckCircle, tone: 'border-success-primary/40 bg-success-primary/10 text-success-primary ring-success-primary/20' },
    analyzing: { label: 'Analyzing', icon: BarChart01, tone: 'border-brand/40 bg-brand-primary/15 text-brand-secondary ring-brand/20' },
    failed: { label: 'Run failed', icon: AlertTriangle, tone: 'border-error/40 bg-error-primary/10 text-error-primary ring-error/20' },
    unanalyzed: { label: 'No analysis', icon: Circle, tone: 'border-secondary bg-secondary/50 text-tertiary ring-secondary' },
  }[health]
  const HealthIcon = healthMeta.icon
  const languages = Object.keys(project.defaultProfileByLang || {})

  return (
    <Link
      to={`/code-quality/projects/${encodeURIComponent(project.key)}`}
      className={cn(
        'group flex flex-col justify-between rounded-xl border bg-primary p-4 shadow-xs transition-all hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50',
        health === 'failing' || health === 'failed'
          ? 'border-error/25 hover:border-error/60'
          : health === 'passing'
          ? 'border-secondary hover:border-success-primary/50'
          : 'border-secondary hover:border-brand/50',
      )}
    >
      <div>
        {/* Card Top: Title, Subtitle, Languages, and Health Pill */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <h2 className="truncate text-base font-bold text-primary group-hover:text-brand-secondary transition-colors">
              {project.name}
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="truncate font-mono text-xs text-utility-blue-700 dark:text-utility-blue-300 italic">
                {project.key}
              </span>
              {languages.length > 0 && (
                <div className="flex items-center gap-1">
                  {languages.map((lang) => (
                    <span
                      key={lang}
                      className="inline-flex items-center rounded-md bg-secondary/70 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-secondary border border-secondary"
                    >
                      {formatLang(lang)}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
          <Pill className={cn('shrink-0 ring-1 ring-inset font-semibold', healthMeta.tone)}>
            <HealthIcon className="size-3" aria-hidden="true" /> {healthMeta.label}
          </Pill>
        </div>

        {/* Middle: SonarQube-style 3 Pillars (Grade + Issue Count) */}
        {analysis ? (
          <div className="mt-3.5 flex flex-wrap gap-2" aria-label="Quality ratings">
            {(['security', 'reliability', 'maintainability'] as const).map((dim) => {
              const count =
                dim === 'security'
                  ? (analysis.issues.byKind?.vulnerability ??
                    (analysis.issues.bySeverity.critical ?? 0) + (analysis.issues.bySeverity.high ?? 0))
                  : dim === 'reliability'
                  ? (analysis.issues.byKind?.bug ?? (analysis.issues.bySeverity.medium ?? 0))
                  : (analysis.issues.byKind?.code_smell ?? (analysis.issues.bySeverity.low ?? 0))

              return (
                <span
                  key={dim}
                  aria-label={`${dim.charAt(0).toUpperCase() + dim.slice(1)} rating ${analysis.rating[dim]}`}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-bold ring-1 ring-inset shadow-2xs',
                    gradeStyle(analysis.rating[dim]),
                  )}
                >
                  <span className="font-extrabold text-sm">{analysis.rating[dim]}</span>
                  <span className="font-mono font-semibold tabular-nums">{count}</span>
                  <span className="font-normal text-[11px] capitalize opacity-80">{dim.slice(0, 3)}</span>
                </span>
              )
            })}
          </div>
        ) : project.latestJob?.status === 'running' ? (
          <div className="mt-3 rounded-lg border border-brand/30 bg-brand-primary/10 p-2.5 text-xs text-brand-secondary space-y-1.5">
            <div className="flex items-center justify-between font-semibold">
              <span className="capitalize">{project.latestJob.stage || 'Analyzing'}...</span>
              <span>{project.latestJob.progress ?? 0}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-brand-primary/20">
              <div
                className="h-full bg-brand-solid transition-all duration-300 rounded-full"
                style={{ width: `${Math.max(5, project.latestJob.progress ?? 0)}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="mt-3 rounded-lg border border-dashed border-secondary bg-secondary/30 px-3 py-2 text-xs text-tertiary">
            Run the first analysis to establish a baseline and evaluate the quality gate.
          </div>
        )}
      </div>

      {/* Footer: Detailed metrics, Branch, Commit & Date */}
      <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2 border-t border-secondary pt-3 text-xs">
        {analysis ? (
          <>
            <span className="flex items-center gap-1 text-xs">
              <span className="font-mono font-bold text-error-primary tabular-nums">
                {analysis.issues.bySeverity.critical ?? 0}
              </span>
              <span className="text-quaternary">/</span>
              <span className="font-mono font-bold text-utility-orange-600 dark:text-utility-orange-400 tabular-nums">
                {analysis.issues.bySeverity.high ?? 0}
              </span>
              <span className="text-tertiary text-[11px]">crit+high</span>
              <span className="text-quaternary mx-0.5">·</span>
              <span className="font-mono font-bold text-brand-secondary tabular-nums">
                {analysis.newCode.counts.total}
              </span>
              <span className="text-tertiary text-[11px]">new</span>
            </span>
            <span className="flex items-center gap-1.5 text-xs text-tertiary truncate">
              {project.sourceBinding.ref && (
                <span className="inline-flex items-center gap-1 font-mono text-[11px] text-quaternary bg-secondary/40 px-1 rounded">
                  <GitBranch01 className="size-3" aria-hidden="true" />
                  {project.sourceBinding.ref}
                </span>
              )}
              <span className="font-semibold text-secondary truncate">
                {analysis.gateInfo.name || project.gateId || 'Synapse way'}
              </span>
              <span className="text-quaternary">·</span>
              <span className="shrink-0">{formatDate(analysis.createdAt)}</span>
            </span>
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-mono capitalize bg-secondary text-secondary">
              <GitBranch01 className="size-3" aria-hidden="true" />
              {project.sourceBinding.kind} · {project.sourceBinding.ref || 'default'}
            </span>
            <span className="font-semibold text-secondary">{project.gateId || 'Default gate'}</span>
          </>
        )}
        <span className="sr-only">Open decision details</span>
      </div>
    </Link>
  )
}

function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

function CreateProjectModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated?: () => void
}) {
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [keyEdited, setKeyEdited] = useState(false)
  const [kind, setKind] = useState<ProjectSourceKind>('git')
  const [value, setValue] = useState('')
  const [ref, setRef] = useState('')
  const [archive, setArchive] = useState<File | null>(null)
  const [gateId, setGateId] = useState('')
  const [gates, setGates] = useState<{ key: string; name: string }[]>([])
  const [dragging, setDragging] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const archiveInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  useEffect(() => {
    api.listQualityGates().then(setGates).catch(() => setGates([]))
  }, [])

  function chooseArchive(file: File | undefined) {
    if (!file) return
    if (!/\.(zip|tgz|tar\.gz)$/i.test(file.name)) {
      setError('Choose a .zip, .tar.gz, or .tgz archive.')
      return
    }
    if (file.size > 512 * 1024 * 1024) {
      setError('Archive must be 512 MiB or smaller.')
      return
    }
    setArchive(file)
    setError(null)
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!name.trim() || !key.trim() || (kind === 'archive' ? !archive : !value.trim())) {
      setError('Name, key, and source are required.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const project = kind === 'archive'
        ? await api.createProjectFromArchive(name.trim(), key.trim(), archive!, gateId)
        : await api.createProject({ name: name.trim(), key: key.trim(), sourceBinding: { kind, value: value.trim(), ref: kind === 'git' ? ref.trim() : '' }, gateId })
      onClose()
      onCreated?.()
      try {
        await api.startProjectAnalysis(project.key)
        navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`)
      } catch (e) {
        navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`, { state: { analysisStartError: e instanceof Error ? e.message : 'Failed to start analysis' } })
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create project')
    } finally {
      setSubmitting(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-project-title"
        className="relative z-10 w-full max-w-xl rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-brand/30 bg-brand-primary/10 text-brand-secondary shadow-sm">
              <Folder className="size-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="create-project-title" className="text-base font-bold text-primary">
                New code quality project
              </h2>
              <p className="text-xs text-secondary">
                Create a project from Git{allowLocalSource ? ', local path,' : ''} or archive
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-tertiary transition hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={submit} className="p-6 space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor="project-name">
              <Input
                id="project-name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  if (!keyEdited) setKey(slugify(e.target.value))
                }}
                placeholder="Synapse CE"
                autoFocus
              />
            </Field>
            <Field label="Key" hint="Lowercase letters, numbers, hyphens" htmlFor="project-key">
              <Input
                id="project-key"
                className="font-mono text-xs"
                value={key}
                onChange={(e) => {
                  setKeyEdited(true)
                  setKey(e.target.value)
                }}
                placeholder="synapse-ce"
              />
            </Field>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]">
            <Field label="Source kind" htmlFor="project-source-kind">
              <Select
                id="project-source-kind"
                value={kind}
                onValueChange={(next) => {
                  setKind(next as ProjectSourceKind)
                  setArchive(null)
                  setError(null)
                }}
                ariaLabel="Source kind"
                className="w-full"
                options={[
                  { value: 'git', label: 'Git URL' },
                  ...(allowLocalSource ? [{ value: 'local', label: 'Local path' }] : []),
                  { value: 'archive', label: 'Upload archive' },
                ]}
              />
            </Field>
            {kind === 'archive' ? (
              <Field label="Source archive" htmlFor="project-archive" hint=".zip, .tar.gz, or .tgz · max 512 MiB">
                <input
                  ref={archiveInput}
                  id="project-archive"
                  type="file"
                  accept=".zip,.tar.gz,.tgz"
                  className="sr-only"
                  onChange={(e) => {
                    chooseArchive(e.target.files?.[0])
                    e.target.value = ''
                  }}
                />
                <button
                  type="button"
                  onClick={() => archiveInput.current?.click()}
                  onDragEnter={(e) => {
                    e.preventDefault()
                    setDragging(true)
                  }}
                  onDragOver={(e) => e.preventDefault()}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault()
                    setDragging(false)
                    chooseArchive(e.dataTransfer.files[0])
                  }}
                  className={cn(
                    'flex min-h-16 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-4 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
                    dragging
                      ? 'border-brand bg-brand-primary/10 text-primary'
                      : 'border-secondary bg-secondary/30 text-tertiary hover:border-brand/50',
                  )}
                >
                  <Upload01 className="size-4" aria-hidden="true" />
                  {archive ? `${archive.name} (${(archive.size / 1024 / 1024).toFixed(1)} MiB)` : 'Drop archive here or choose a file'}
                </button>
              </Field>
            ) : (
              <Field label="Source" htmlFor="project-source">
                <Input
                  id="project-source"
                  className="font-mono text-xs"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={kind === 'git' ? 'https://github.com/acme/app.git' : '/path/to/source'}
                />
              </Field>
            )}
          </div>

          {kind === 'git' && (
            <Field label="Branch or tag" hint="Optional; uses default branch when empty" htmlFor="project-ref">
              <Input
                id="project-ref"
                className="font-mono text-xs"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder="main"
              />
            </Field>
          )}

          <Field label="Quality policy" hint="Leave unassigned to allow repository .synapse-gate.yaml; otherwise Synapse way is used." htmlFor="project-gate">
            <select
              id="project-gate"
              value={gateId}
              onChange={(e) => setGateId(e.target.value)}
              className="h-9 w-full rounded-lg border border-secondary bg-primary px-3 text-xs text-primary focus:outline-none focus:ring-2 focus:ring-brand/60"
            >
              <option value="">Default / repository gate</option>
              {gates.map((gate) => (
                <option key={gate.key} value={gate.key}>
                  {gate.name}
                </option>
              ))}
            </select>
          </Field>

          {error && <ErrorState message={error} />}

          {/* Modal Footer: NO Cancel button, only Primary CTA */}
          <div className="mt-6 flex items-center justify-end pt-2">
            <Button
              variant="brand"
              type="submit"
              loading={submitting}
              className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
            >
              <GitBranch01 className="size-4" aria-hidden="true" /> Create and analyze
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}
