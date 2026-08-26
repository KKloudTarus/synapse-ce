import { Folder, Plus, SearchLg } from '@untitledui/icons'
import { useMemo, useState } from 'react'
import { api } from '../../lib/api'
import type { Project } from '../../lib/types'
import { Button, EmptyState, ErrorState, Input, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { CreateProjectModal } from './components/CreateProjectModal'
import { ProjectCard } from './components/ProjectCard'
import { StatPill, projectHealth, type Health, type SortOption } from './components/projectCardHelpers'

const allowLocalSource = import.meta.env.DEV

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
            variant="primary"
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
