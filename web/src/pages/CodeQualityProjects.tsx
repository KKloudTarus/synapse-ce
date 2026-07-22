import { AlertTriangle, ArrowRight, CheckCircle2, CircleDashed, FolderGit2, Gauge, GitBranch, Plus, Search, Upload, X, XCircle } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import type { Grade, Project, ProjectSourceKind } from '../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../components/ui'

const allowLocalSource = import.meta.env.DEV
type Health = 'all' | 'failing' | 'passing' | 'analyzing' | 'failed' | 'unanalyzed'

export function CodeQualityProjects() {
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')
  const [health, setHealth] = useState<Health>('all')

  function load() {
    setError(null)
    setProjects(null)
    api.listProjects().then(setProjects).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load projects'))
  }
  useEffect(load, [])

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
    <div className="mx-auto max-w-7xl animate-fade-in">
      <header className="bg-hero mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border p-6">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-branddim"><Gauge className="size-4" aria-hidden="true" />Portfolio</div>
          <h1 className="text-3xl font-bold tracking-tight">Code Quality</h1>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-mutedfg">See what needs attention, enforce quality policy, and track every successful analysis against its previous baseline.</p>
        </div>
        <div className="flex gap-2"><Link to="/code-quality/profiles"><Button variant="secondary">Quality profiles</Button></Link><Link to="/code-quality/gates"><Button variant="secondary">Quality gates</Button></Link><Button variant="brand" onClick={() => setCreating((value) => !value)}>{creating ? <><X className="size-4" aria-hidden="true" /> Cancel</> : <><Plus className="size-4" aria-hidden="true" /> New project</>}</Button></div>
      </header>

      {creating && <div className="mb-6"><CreateProjectForm /></div>}
      {error && <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={load}>Retry</Button></div>}
      {!projects && !error && <Spinner label="Loading projects…" />}
      {projects && projects.length === 0 && !creating && <EmptyState icon={FolderGit2} title="No code quality projects yet" hint={`Create a project from Git${allowLocalSource ? ', a server-local path,' : ''} or an uploaded archive. Its first analysis starts automatically.`} action={<Button variant="brand" onClick={() => setCreating(true)}><Plus className="size-4" aria-hidden="true" /> New project</Button>} />}
      {projects && projects.length > 0 && <>
        <section aria-label="Portfolio health" className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
          <PortfolioStat label="Gate failed" value={counts.failing} tone="critical" />
          <PortfolioStat label="Gate passed" value={counts.passing} tone="low" />
          <PortfolioStat label="Analyzing" value={counts.analyzing} tone="brand" />
          <PortfolioStat label="Run failed" value={counts.failed} tone="critical" />
          <PortfolioStat label="No analysis" value={counts.unanalyzed} tone="muted" />
        </section>
        <div className="mb-5 grid gap-3 rounded-xl border border-border bg-card p-3 sm:grid-cols-[1fr_13rem]">
          <label className="relative"><span className="sr-only">Search projects</span><Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtlefg" aria-hidden="true" /><Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects, keys, sources…" /></label>
          <Select value={health} onValueChange={(value) => setHealth(value as Health)} ariaLabel="Filter by health" options={[{ value: 'all', label: 'All health states' }, { value: 'failing', label: 'Gate failed' }, { value: 'passing', label: 'Gate passed' }, { value: 'analyzing', label: 'Analyzing' }, { value: 'failed', label: 'Run failed' }, { value: 'unanalyzed', label: 'No analysis' }]} />
        </div>
        {visible.length === 0 ? <EmptyState icon={Search} title="No matching projects" hint="Change the search or health filter to see more projects." action={<Button variant="secondary" onClick={() => { setQuery(''); setHealth('all') }}>Clear filters</Button>} /> : <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">{visible.map((project) => <ProjectCard key={project.id} project={project} />)}</div>}
      </>}
    </div>
  )
}

function PortfolioStat({ label, value, tone }: { label: string; value: number; tone: 'critical' | 'low' | 'brand' | 'muted' }) {
  const tones = { critical: 'border-critical/25 bg-critical/5 text-critical', low: 'border-low/25 bg-low/5 text-low', brand: 'border-brand/25 bg-brand/5 text-branddim', muted: 'border-border bg-card text-mutedfg' }
  return <div className={cn('rounded-lg border px-4 py-3', tones[tone])}><div className="font-mono text-2xl font-semibold tabular-nums">{value}</div><div className="text-xs">{label}</div></div>
}

function projectHealth(project: Project): Exclude<Health, 'all'> {
  if (project.latestJob?.status === 'running') return 'analyzing'
  if (project.latestJob?.status === 'failed') return 'failed'
  if (!project.latestAnalysis) return 'unanalyzed'
  return project.latestAnalysis.gate.passed ? 'passing' : 'failing'
}

function ProjectCard({ project }: { project: Project }) {
  const analysis = project.latestAnalysis
  const health = projectHealth(project)
  const healthMeta = {
    failing: { label: 'Gate failed', icon: XCircle, tone: 'border-critical/35 bg-critical/10 text-critical' },
    passing: { label: 'Gate passed', icon: CheckCircle2, tone: 'border-low/30 bg-low/10 text-low' },
    analyzing: { label: 'Analyzing', icon: Gauge, tone: 'border-brand/30 bg-brand/10 text-branddim' },
    failed: { label: 'Run failed', icon: AlertTriangle, tone: 'border-critical/35 bg-critical/10 text-critical' },
    unanalyzed: { label: 'No analysis', icon: CircleDashed, tone: 'border-border bg-elevated text-mutedfg' },
  }[health]
  const HealthIcon = healthMeta.icon
  return (
    <Link to={`/code-quality/projects/${encodeURIComponent(project.key)}`} className={cn('lift card-sheen elev group flex min-h-80 flex-col rounded-xl border bg-card p-5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50', health === 'failing' || health === 'failed' ? 'border-critical/25 hover:border-critical/50' : 'border-border hover:border-brand/40')}>
      <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-subtlefg">Project</p><h2 className="truncate text-lg font-semibold text-foreground">{project.name}</h2><p className="mt-1 truncate font-mono text-xs text-subtlefg">{project.key}</p></div><Pill className={cn('shrink-0 ring-1 ring-inset', healthMeta.tone)}><HealthIcon className="size-3" aria-hidden="true" /> {healthMeta.label}</Pill></div>
      {analysis ? <>
        <div className="mt-5 grid grid-cols-3 gap-2" aria-label="Quality ratings"><MiniGrade label="Security" grade={analysis.rating.security} /><MiniGrade label="Reliability" grade={analysis.rating.reliability} /><MiniGrade label="Maintainability" grade={analysis.rating.maintainability} /></div>
        <div className="mt-4 grid grid-cols-2 gap-2"><Count label="Critical / high" value={`${analysis.issues.bySeverity.critical ?? 0} / ${analysis.issues.bySeverity.high ?? 0}`} /><Count label="New issues" value={analysis.newCode.counts.total} /></div>
      </> : <div className="mt-5 rounded-lg border border-dashed border-border bg-bg px-4 py-5 text-sm text-mutedfg">Run the first analysis to establish a baseline and evaluate the quality gate.</div>}
      <dl className="mt-5 flex-1 space-y-3 text-sm"><div><dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Source</dt><dd className="mt-1 flex min-w-0 items-center gap-2 text-mutedfg"><FolderGit2 className="size-4 shrink-0" aria-hidden="true" /><span className="capitalize">{project.sourceBinding.kind}</span><span className="truncate font-mono text-xs text-foreground" title={project.sourceBinding.value}>{project.sourceBinding.value}</span></dd></div><div className="flex flex-wrap gap-x-5 gap-y-2"><div><dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Policy</dt><dd className="mt-1 text-foreground">{analysis?.gateInfo.name || project.gateId || 'Default / repository'}</dd></div>{analysis && <div><dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Last analysis</dt><dd className="mt-1 text-foreground">{formatDate(analysis.createdAt)}</dd></div>}</div>{(analysis?.sourceCommit || project.sourceBinding.ref) && <div className="flex items-center gap-2 font-mono text-xs text-mutedfg"><GitBranch className="size-3.5" aria-hidden="true" />{analysis?.sourceCommit ? analysis.sourceCommit.slice(0, 12) : project.sourceBinding.ref}</div>}</dl>
      <div className="mt-5 flex items-center justify-between gap-4 border-t border-border pt-4"><p className="text-xs text-mutedfg">Open decision details</p><ArrowRight className="size-4 text-subtlefg transition-transform group-hover:translate-x-0.5 group-hover:text-branddim" aria-hidden="true" /></div>
    </Link>
  )
}

function MiniGrade({ label, grade }: { label: string; grade: Grade }) { return <div className="rounded-lg border border-border bg-bg px-2 py-2 text-center" aria-label={`${label} rating ${grade}`}><div className={cn('font-mono text-xl font-semibold', grade === 'A' || grade === 'B' ? 'text-low' : grade === 'C' ? 'text-medium' : grade === '?' ? 'text-mutedfg' : 'text-critical')}>{grade}</div><div className="truncate text-[10px] text-mutedfg">{label}</div></div> }
function Count({ label, value }: { label: string; value: number | string }) { return <div className="rounded-lg bg-elevated px-3 py-2"><div className="font-mono text-lg font-semibold tabular-nums">{value}</div><div className="text-[10px] text-mutedfg">{label}</div></div> }
function formatDate(value: string) { return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) }

function slugify(value: string): string { return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') }

function CreateProjectForm() {
  const [name, setName] = useState(''); const [key, setKey] = useState(''); const [keyEdited, setKeyEdited] = useState(false)
  const [kind, setKind] = useState<ProjectSourceKind>('git'); const [value, setValue] = useState(''); const [ref, setRef] = useState('')
  const [archive, setArchive] = useState<File | null>(null); const [gateId, setGateId] = useState(''); const [gates, setGates] = useState<{ key: string; name: string }[]>([])
  const [dragging, setDragging] = useState(false); const [submitting, setSubmitting] = useState(false); const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate(); const archiveInput = useRef<HTMLInputElement>(null)
  useEffect(() => { api.listQualityGates().then(setGates).catch(() => setGates([])) }, [])
  function chooseArchive(file: File | undefined) { if (!file) return; if (!/\.(zip|tgz|tar\.gz)$/i.test(file.name)) { setError('Choose a .zip, .tar.gz, or .tgz archive.'); return } if (file.size > 512 * 1024 * 1024) { setError('Archive must be 512 MiB or smaller.'); return } setArchive(file); setError(null) }
  async function submit(event: React.FormEvent) { event.preventDefault(); if (!name.trim() || !key.trim() || (kind === 'archive' ? !archive : !value.trim())) { setError('Name, key, and source are required.'); return } setSubmitting(true); setError(null); try { const project = kind === 'archive' ? await api.createProjectFromArchive(name.trim(), key.trim(), archive!, gateId) : await api.createProject({ name: name.trim(), key: key.trim(), sourceBinding: { kind, value: value.trim(), ref: kind === 'git' ? ref.trim() : '' }, gateId }); try { await api.startProjectAnalysis(project.key); navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`) } catch (e) { navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`, { state: { analysisStartError: e instanceof Error ? e.message : 'Failed to start analysis' } }) } } catch (e) { setError(e instanceof Error ? e.message : 'Failed to create project') } finally { setSubmitting(false) } }
  return <Card title={<span className="inline-flex items-center gap-2"><FolderGit2 className="size-4 text-mutedfg" aria-hidden="true" /> New code quality project</span>}><form onSubmit={submit} className="space-y-5"><div className="grid grid-cols-1 gap-4 sm:grid-cols-2"><Field label="Name" htmlFor="project-name"><Input id="project-name" value={name} onChange={(e) => { setName(e.target.value); if (!keyEdited) setKey(slugify(e.target.value)) }} placeholder="Synapse CE" autoFocus /></Field><Field label="Key" hint="Lowercase letters, numbers, and hyphens" htmlFor="project-key"><Input id="project-key" className="font-mono" value={key} onChange={(e) => { setKeyEdited(true); setKey(e.target.value) }} placeholder="synapse-ce" /></Field></div><div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]"><Field label="Source kind" htmlFor="project-source-kind"><Select id="project-source-kind" value={kind} onValueChange={(next) => { setKind(next as ProjectSourceKind); setArchive(null); setError(null) }} ariaLabel="Source kind" className="w-full" options={[{ value: 'git', label: 'Git URL' }, ...(allowLocalSource ? [{ value: 'local', label: 'Local path' }] : []), { value: 'archive', label: 'Upload archive' }]} /></Field>{kind === 'archive' ? <Field label="Source archive" htmlFor="project-archive" hint=".zip, .tar.gz, or .tgz · max 512 MiB"><input ref={archiveInput} id="project-archive" type="file" accept=".zip,.tar.gz,.tgz" className="sr-only" onChange={(e) => { chooseArchive(e.target.files?.[0]); e.target.value = '' }} /><button type="button" onClick={() => archiveInput.current?.click()} onDragEnter={(e) => { e.preventDefault(); setDragging(true) }} onDragOver={(e) => e.preventDefault()} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); chooseArchive(e.dataTransfer.files[0]) }} className={cn('flex min-h-20 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-4 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg', dragging ? 'border-brand bg-brand/10 text-foreground' : 'border-border bg-elevated text-mutedfg hover:border-brand/50')}><Upload className="size-4" aria-hidden="true" />{archive ? `${archive.name} (${(archive.size / 1024 / 1024).toFixed(1)} MiB)` : 'Drop an archive here or choose a file'}</button></Field> : <Field label="Source" htmlFor="project-source"><Input id="project-source" className="font-mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === 'git' ? 'https://github.com/acme/app.git' : '/path/to/source'} /></Field>}</div>{kind === 'git' && <Field label="Branch or tag" hint="Optional; uses the default branch when empty" htmlFor="project-ref"><Input id="project-ref" className="font-mono" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" /></Field>}<Field label="Quality policy" hint="Leave unassigned to allow a repository .synapse-gate.yaml; otherwise Synapse way is used." htmlFor="project-gate"><select id="project-gate" value={gateId} onChange={(e) => setGateId(e.target.value)} className="h-10 w-full rounded-lg border border-border bg-bg px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand/60"><option value="">Default / repository gate</option>{gates.map((gate) => <option key={gate.key} value={gate.key}>{gate.name}</option>)}</select></Field>{error && <ErrorState message={error} />}<div className="flex justify-end"><Button variant="brand" type="submit" loading={submitting}><GitBranch className="size-4" aria-hidden="true" /> Create and analyze</Button></div></form></Card>
}
