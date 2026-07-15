import { ArrowLeft, FolderGit2, Gauge, GitBranch } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { CodeQualityReportView } from '../components/codequality/CodeQualityReportView'
import { Card, EmptyState, ErrorState, Pill, Spinner } from '../components/ui'
import { api } from '../lib/api'
import type { Project } from '../lib/types'

export function CodeQualityProject() {
  const { key = '' } = useParams()
  const [project, setProject] = useState<Project | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setProject(undefined)
    setError(null)
    api.getProject(key).then(setProject).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load project'))
  }, [key])

  if (error) return <div className="mx-auto max-w-6xl space-y-3"><ErrorState message={error} /><Link to="/code-quality" className="inline-flex items-center gap-1.5 text-sm text-branddim hover:underline"><ArrowLeft className="size-4" aria-hidden="true" /> All projects</Link></div>
  if (project === undefined) return <Spinner label="Loading project…" />
  if (!project) return null

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <Link to="/code-quality" className="mb-4 inline-flex items-center gap-1.5 text-sm text-mutedfg transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50">
        <ArrowLeft className="size-4" aria-hidden="true" /> All projects
      </Link>
      <header className="bg-hero mb-6 rounded-xl border border-border p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-branddim">
              <Gauge className="size-4" aria-hidden="true" />
              Code Quality project
            </div>
            <h1 className="truncate text-3xl font-bold tracking-tight">{project.name}</h1>
            <p className="mt-1.5 font-mono text-sm text-mutedfg">{project.key}</p>
          </div>
          <Pill className="shrink-0 bg-elevated ring-1 ring-inset ring-border"><Gauge className="size-3" aria-hidden="true" /> Not analyzed</Pill>
        </div>
        <dl className="mt-5 grid grid-cols-1 gap-4 border-t border-border pt-4 text-sm sm:grid-cols-2">
          <div className="min-w-0">
            <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Source</dt>
            <dd className="mt-1.5 flex min-w-0 items-center gap-2 text-foreground">
              <FolderGit2 className="size-4 shrink-0 text-mutedfg" aria-hidden="true" />
              <span className="capitalize">{project.sourceBinding.kind}</span>
              <span className="truncate font-mono text-xs leading-5" title={project.sourceBinding.value}>{project.sourceBinding.value}</span>
            </dd>
          </div>
          <div>
            <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Quality gate</dt>
            <dd className="mt-1.5 leading-5 text-foreground">{project.gateId || 'Default'}</dd>
          </div>
          {project.sourceBinding.ref && (
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-subtlefg">Branch or tag</dt>
              <dd className="mt-1.5 flex items-center gap-2 font-mono text-xs leading-5 text-foreground">
                <GitBranch className="size-4 shrink-0 text-mutedfg" aria-hidden="true" />
                {project.sourceBinding.ref}
              </dd>
            </div>
          )}
        </dl>
      </header>
      <CodeQualityReportView
        report={undefined}
        empty={
          <Card title="Analysis">
            <EmptyState icon={Gauge} title="No analyses yet" hint="This project’s source and quality gate are configured. Source acquisition and analysis execution arrive in the next Code Quality phase." />
          </Card>
        }
      />
    </div>
  )
}
