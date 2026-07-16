import { ArrowRight, FolderGit2, Gauge, GitBranch, Plus, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import type { Project, ProjectSourceKind } from '../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'

export function CodeQualityProjects() {
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  function load() {
    setError(null)
    api.listProjects().then(setProjects).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load projects'))
  }
  useEffect(load, [])

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <header className="bg-hero mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border p-6">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-branddim">
            <Gauge className="size-4" aria-hidden="true" />
            Projects
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Code Quality</h1>
          <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-mutedfg">Long-lived projects keep code health separate from time-bounded pentest engagements.</p>
        </div>
        <Button variant="brand" onClick={() => setCreating((value) => !value)}>
          {creating ? <><X className="size-4" aria-hidden="true" /> Cancel</> : <><Plus className="size-4" aria-hidden="true" /> New project</>}
        </Button>
      </header>

      {creating && <div className="mb-6"><CreateProjectForm /></div>}
      {error && <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={load}>Retry</Button></div>}
      {!projects && !error && <Spinner label="Loading projects…" />}
      {projects && projects.length === 0 && !creating && (
        <EmptyState icon={FolderGit2} title="No code quality projects yet" hint="Create a project to define its source. Project analyses arrive in the next Code Quality phase." action={<Button variant="brand" onClick={() => setCreating(true)}><Plus className="size-4" aria-hidden="true" /> New project</Button>} />
      )}
      {projects && projects.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {projects.map((project) => <ProjectCard key={project.id} project={project} />)}
        </div>
      )}
    </div>
  )
}

function ProjectCard({ project }: { project: Project }) {
  return (
    <Link to={`/code-quality/projects/${encodeURIComponent(project.key)}`} className="lift card-sheen elev group flex min-h-64 flex-col rounded-xl border border-border bg-card p-5 transition-colors hover:border-brand/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-subtlefg">Project</p>
          <h2 className="truncate text-lg font-semibold text-foreground">{project.name}</h2>
          <p className="mt-1 truncate font-mono text-xs text-subtlefg">{project.key}</p>
        </div>
        <Pill className="shrink-0 bg-elevated ring-1 ring-inset ring-border"><Gauge className="size-3" aria-hidden="true" /> Not analyzed</Pill>
      </div>

      <dl className="mt-6 flex-1 space-y-4 text-sm">
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Source</dt>
          <dd className="mt-1 flex min-w-0 items-center gap-2 text-mutedfg">
            <FolderGit2 className="size-4 shrink-0" aria-hidden="true" />
            <span className="capitalize">{project.sourceBinding.kind}</span>
            <span className="truncate font-mono text-xs text-foreground" title={project.sourceBinding.value}>{project.sourceBinding.value}</span>
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Quality gate</dt>
          <dd className="mt-1 text-foreground">{project.gateId || 'Default'}</dd>
        </div>
      </dl>

      <div className="mt-6 flex items-center justify-between gap-4 border-t border-border pt-4">
        <p className="text-xs leading-relaxed text-mutedfg">Open project</p>
        <ArrowRight className="size-4 shrink-0 text-subtlefg transition-transform group-hover:translate-x-0.5 group-hover:text-branddim" aria-hidden="true" />
      </div>
    </Link>
  )
}

function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

function CreateProjectForm() {
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [keyEdited, setKeyEdited] = useState(false)
  const [kind, setKind] = useState<ProjectSourceKind>('git')
  const [value, setValue] = useState('')
  const [ref, setRef] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!name.trim() || !key.trim() || !value.trim()) { setError('Name, key, and source are required.'); return }
    setSubmitting(true); setError(null)
    try {
      const project = await api.createProject({ name: name.trim(), key: key.trim(), sourceBinding: { kind, value: value.trim(), ref: kind === 'git' ? ref.trim() : '' } })
      navigate(`/code-quality/projects/${encodeURIComponent(project.key)}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create project')
    } finally { setSubmitting(false) }
  }

  return (
    <Card title={<span className="inline-flex items-center gap-2"><FolderGit2 className="size-4 text-mutedfg" aria-hidden="true" /> New project</span>} className="animate-fade-in">
      <form onSubmit={submit} className="space-y-5">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor="project-name"><Input id="project-name" value={name} onChange={(e) => { setName(e.target.value); if (!keyEdited) setKey(slugify(e.target.value)) }} placeholder="Synapse CE" autoFocus /></Field>
          <Field label="Key" hint="Lowercase letters, numbers, and hyphens" htmlFor="project-key"><Input id="project-key" className="font-mono" value={key} onChange={(e) => { setKeyEdited(true); setKey(e.target.value) }} placeholder="synapse-ce" /></Field>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]">
          <Field label="Source kind" htmlFor="project-source-kind"><Select id="project-source-kind" value={kind} onValueChange={(next) => setKind(next as ProjectSourceKind)} ariaLabel="Source kind" className="w-full" options={[{ value: 'git', label: 'Git URL' }, { value: 'local', label: 'Local path' }, { value: 'archive', label: 'Archive path' }]} /></Field>
          <Field label="Source" htmlFor="project-source"><Input id="project-source" className="font-mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === 'git' ? 'https://github.com/acme/app.git' : '/path/to/source'} /></Field>
        </div>
        {kind === 'git' && <Field label="Branch or tag" hint="Optional; uses the default branch when empty" htmlFor="project-ref"><Input id="project-ref" className="font-mono" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" /></Field>}
        {error && <ErrorState message={error} />}
        <div className="flex justify-end"><Button variant="brand" type="submit" loading={submitting}><GitBranch className="size-4" aria-hidden="true" /> Create project</Button></div>
      </form>
    </Card>
  )
}
