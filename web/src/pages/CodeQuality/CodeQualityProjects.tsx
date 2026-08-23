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
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../../lib/api'
import type { Grade, Project, ProjectSourceKind } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'

const allowLocalSource = import.meta.env.DEV
type Health = 'all' | 'failing' | 'passing' | 'analyzing' | 'failed' | 'unanalyzed'

export function CodeQualityProjects() {
  const { data: projects, error, refetch } = useFetch<Project[]>(
    () => api.listProjects(),
    { deps: [] },
  )
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')
  const [health, setHealth] = useState<Health>('all')

  const counts = useMemo(() => {
    const next = { failing: 0, passing: 0, analyzing: 0, failed: 0, unanalyzed: 0 }
    for (const project of projects ?? []) next[projectHealth(project)]++
    return next
  }, [projects])
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (projects ?? []).filter((project) => {
      const matchesQuery = !needle || [project.name, project.key, project.sourceBinding.value, project.sourceBinding.ref].some((value) => value.toLowerCase().includes(needle))
      return matchesQuery && (health === 'all' || projectHealth(project) === health)
    })
  }, [health, projects, query])

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            Code Quality
          </h1>
          <p className="mt-1 text-sm text-secondary">
            See what needs attention, enforce quality policy, and track every successful analysis against its previous baseline
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="brand" onClick={() => setCreating((value) => !value)}>
            {creating ? <><XClose className="size-4" /> Cancel</> : <><Plus className="size-4" /> New project</>}
          </Button>
        </div>
      </header>

      {creating && <div><CreateProjectForm onCreated={refetch} /></div>}
      {error && <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={refetch}>Retry</Button></div>}
      {!projects && !error && <Spinner label="Loading projects…" />}
      {projects && projects.length === 0 && !creating && (
        <EmptyState
          icon={Folder}
          title="No code quality projects yet"
          hint={`Create a project from Git${allowLocalSource ? ', a server-local path,' : ''} or an uploaded archive. Its first analysis starts automatically.`}
          action={<Button variant="brand" onClick={() => setCreating(true)}><Plus className="size-4" aria-hidden="true" /> New project</Button>}
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
          <div className="grid gap-3 rounded-xl border border-secondary bg-primary p-3 sm:grid-cols-[1fr_13rem]">
            <label className="relative">
              <span className="sr-only">Search projects</span>
              <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" aria-hidden="true" />
              <Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects, keys, sources…" />
            </label>
            <Select value={health} onValueChange={(value) => setHealth(value as Health)} ariaLabel="Filter by health" options={[{ value: 'all', label: 'All health states' }, { value: 'failing', label: 'Gate failed' }, { value: 'passing', label: 'Gate passed' }, { value: 'analyzing', label: 'Analyzing' }, { value: 'failed', label: 'Run failed' }, { value: 'unanalyzed', label: 'No analysis' }]} />
          </div>
          {visible.length === 0 ? (
            <EmptyState
              icon={SearchLg}
              title="No matching projects"
              hint="Change the search or health filter to see more projects."
              action={<Button variant="secondary" onClick={() => { setQuery(''); setHealth('all') }}>Clear filters</Button>}
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
      return 'bg-low/10 text-low ring-low/30'
    case 'B':
      return 'bg-utility-blue-50 text-utility-blue-700 ring-utility-blue-200'
    case 'C':
      return 'bg-warning/10 text-warning ring-warning/30'
    case 'D':
      return 'bg-utility-orange-50 text-utility-orange-700 ring-utility-orange-200'
    case 'E':
      return 'bg-critical/10 text-critical ring-critical/30'
    default:
      return 'bg-secondary text-tertiary ring-secondary'
  }
}

function ProjectCard({ project }: { project: Project }) {
  const analysis = project.latestAnalysis
  const health = projectHealth(project)
  const healthMeta = {
    failing: { label: 'Gate failed', icon: XCircle, tone: 'border-critical/35 bg-critical/10 text-critical' },
    passing: { label: 'Gate passed', icon: CheckCircle, tone: 'border-low/30 bg-low/10 text-low' },
    analyzing: { label: 'Analyzing', icon: BarChart01, tone: 'border-brand/30 bg-brand/10 text-brand-secondary' },
    failed: { label: 'Run failed', icon: AlertTriangle, tone: 'border-critical/35 bg-critical/10 text-critical' },
    unanalyzed: { label: 'No analysis', icon: Circle, tone: 'border-secondary bg-secondary/50 text-tertiary' },
  }[health]
  const HealthIcon = healthMeta.icon
  return (
    <Link
      to={`/code-quality/projects/${encodeURIComponent(project.key)}`}
      className={cn(
        'group flex flex-col justify-between rounded-xl border bg-primary p-4 shadow-xs transition-all hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50',
        health === 'failing' || health === 'failed'
          ? 'border-critical/25 hover:border-critical/50'
          : 'border-secondary hover:border-brand/40',
      )}
    >
      <div>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-primary">{project.name}</h2>
            <p className="mt-0.5 truncate font-mono text-xs text-quaternary">{project.key}</p>
          </div>
          <Pill className={cn('shrink-0 ring-1 ring-inset', healthMeta.tone)}>
            <HealthIcon className="size-3" aria-hidden="true" /> {healthMeta.label}
          </Pill>
        </div>
        {analysis ? (
          <div className="mt-3 flex flex-wrap gap-2" aria-label="Quality ratings">
            {(['security', 'reliability', 'maintainability'] as const).map((dim) => (
              <span
                key={dim}
                aria-label={`${dim.charAt(0).toUpperCase() + dim.slice(1)} rating ${analysis.rating[dim]}`}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset',
                  gradeStyle(analysis.rating[dim]),
                )}
              >
                <span>{analysis.rating[dim]}</span>
                <span className="font-normal capitalize text-tertiary">{dim.slice(0, 3)}</span>
              </span>
            ))}
          </div>
        ) : (
          <div className="mt-3 rounded-lg border border-dashed border-secondary bg-secondary/30 px-3 py-2 text-xs text-tertiary">
            Run the first analysis to establish a baseline and evaluate the quality gate.
          </div>
        )}
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-secondary pt-3 text-xs text-tertiary">
        {analysis ? (
          <>
            <span>
              {analysis.issues.bySeverity.critical ?? 0} / {analysis.issues.bySeverity.high ?? 0} critical+high · {analysis.newCode.counts.total} new
            </span>
            <span className="truncate">
              {analysis.gateInfo.name || project.gateId || 'Synapse way'} · {formatDate(analysis.createdAt)}
            </span>
          </>
        ) : (
          <>
            <span className="capitalize">{project.sourceBinding.kind}</span>
            <span>{project.gateId || 'Default gate'}</span>
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

function CreateProjectForm({ onCreated: _onCreated }: { onCreated?: () => void }) {
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

  return (
    <Card title={<span className="inline-flex items-center gap-2 text-primary"><Folder className="size-4 text-tertiary" aria-hidden="true" /> New code quality project</span>}>
      <form onSubmit={submit} className="space-y-5">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor="project-name">
            <Input id="project-name" value={name} onChange={(e) => { setName(e.target.value); if (!keyEdited) setKey(slugify(e.target.value)) }} placeholder="Synapse CE" autoFocus />
          </Field>
          <Field label="Key" hint="Lowercase letters, numbers, and hyphens" htmlFor="project-key">
            <Input id="project-key" className="font-mono" value={key} onChange={(e) => { setKeyEdited(true); setKey(e.target.value) }} placeholder="synapse-ce" />
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]">
          <Field label="Source kind" htmlFor="project-source-kind">
            <Select id="project-source-kind" value={kind} onValueChange={(next) => { setKind(next as ProjectSourceKind); setArchive(null); setError(null) }} ariaLabel="Source kind" className="w-full" options={[{ value: 'git', label: 'Git URL' }, ...(allowLocalSource ? [{ value: 'local', label: 'Local path' }] : []), { value: 'archive', label: 'Upload archive' }]} />
          </Field>
          {kind === 'archive' ? (
            <Field label="Source archive" htmlFor="project-archive" hint=".zip, .tar.gz, or .tgz · max 512 MiB">
              <input ref={archiveInput} id="project-archive" type="file" accept=".zip,.tar.gz,.tgz" className="sr-only" onChange={(e) => { chooseArchive(e.target.files?.[0]); e.target.value = '' }} />
              <button type="button" onClick={() => archiveInput.current?.click()} onDragEnter={(e) => { e.preventDefault(); setDragging(true) }} onDragOver={(e) => e.preventDefault()} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); chooseArchive(e.dataTransfer.files[0]) }} className={cn('flex min-h-20 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-4 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg', dragging ? 'border-brand bg-brand-primary/10 text-primary' : 'border-secondary bg-secondary/50 text-tertiary hover:border-brand/50')}>
                <Upload01 className="size-4" aria-hidden="true" />
                {archive ? `${archive.name} (${(archive.size / 1024 / 1024).toFixed(1)} MiB)` : 'Drop an archive here or choose a file'}
              </button>
            </Field>
          ) : (
            <Field label="Source" htmlFor="project-source">
              <Input id="project-source" className="font-mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === 'git' ? 'https://github.com/acme/app.git' : '/path/to/source'} />
            </Field>
          )}
        </div>
        {kind === 'git' && (
          <Field label="Branch or tag" hint="Optional; uses the default branch when empty" htmlFor="project-ref">
            <Input id="project-ref" className="font-mono" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" />
          </Field>
        )}
        <Field label="Quality policy" hint="Leave unassigned to allow a repository .synapse-gate.yaml; otherwise Synapse way is used." htmlFor="project-gate">
          <select id="project-gate" value={gateId} onChange={(e) => setGateId(e.target.value)} className="h-10 w-full rounded-lg border border-secondary bg-primary px-3 text-sm text-primary focus:outline-none focus:ring-2 focus:ring-brand/60">
            <option value="">Default / repository gate</option>
            {gates.map((gate) => <option key={gate.key} value={gate.key}>{gate.name}</option>)}
          </select>
        </Field>
        {error && <ErrorState message={error} />}
        <div className="flex justify-end">
          <Button variant="brand" type="submit" loading={submitting}>
            <GitBranch01 className="size-4" aria-hidden="true" /> Create and analyze
          </Button>
        </div>
      </form>
    </Card>
  )
}
