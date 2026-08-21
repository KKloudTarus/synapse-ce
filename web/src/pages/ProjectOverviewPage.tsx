import { CalendarClock, GitCommit, GitBranch, Gauge, ShieldAlert } from 'lucide-react'
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CodeLensToggle } from '../components/codequality/projectOverview/CodeLensToggle'
import { OverviewIssueSummary } from '../components/codequality/projectOverview/OverviewIssueSummary'
import { OverviewMetricGrid } from '../components/codequality/projectOverview/OverviewMetricGrid'
import { ProjectOverviewSkeleton } from '../components/codequality/projectOverview/ProjectOverviewSkeleton'
import { QualityGateBanner } from '../components/codequality/projectOverview/QualityGateBanner'
import { Button, Card, EmptyState, ErrorState, Pill } from '../components/ui'
import { useFetch } from '../hooks'
import { api } from '../lib/api'
import type { ProjectOverview } from '../lib/projectOverview'
import {
  isValidCodeLens,
  parseCodeLens,
  serializeCodeLens,
  type CodeLens,
} from '../lib/projectOverviewPresentation'
import { useProjectRouteContext } from './CodeQualityProject'

export function ProjectOverviewPage() {
  const { projectKey, isRunning, analysisRevision, startAnalysis } = useProjectRouteContext()
  const [searchParams, setSearchParams] = useSearchParams()
  const lens = parseCodeLens(searchParams.get('lens'))

  useEffect(() => {
    const raw = searchParams.get('lens')
    if (raw !== null && !isValidCodeLens(raw)) {
      const next = new URLSearchParams(searchParams)
      next.set('lens', 'overall')
      setSearchParams(next, { replace: true })
    }
  }, [searchParams, setSearchParams])

  function setLens(nextLens: CodeLens) {
    const next = new URLSearchParams(searchParams)
    next.set('lens', serializeCodeLens(nextLens))
    setSearchParams(next)
  }

  const { data: overview, loading, error, refetch: load } = useFetch<ProjectOverview>(
    () => api.projectOverview(projectKey).catch((e) => {
      const message = e instanceof Error && e.message === 'Invalid project overview response'
        ? 'Project Overview data is unavailable.'
        : e instanceof Error ? e.message : 'Failed to load Project Overview'
      throw new Error(message)
    }),
    { deps: [projectKey, analysisRevision] },
  )

  if (loading) return <ProjectOverviewSkeleton />
  if (error) {
    return (
      <div className="space-y-3">
        <ErrorState message={error} />
        <Button variant="secondary" onClick={load}>Retry Overview</Button>
      </div>
    )
  }

  if (!overview) return <ProjectOverviewSkeleton />
  if (overview.state === 'not_analyzed') {
    return (
      <Card title="Project Overview">
        <EmptyState
          icon={isRunning ? Gauge : ShieldAlert}
          title={isRunning ? 'Analysis in progress' : 'No completed analysis yet'}
          hint={isRunning ? 'The Overview will appear after the first successful analysis completes.' : 'Run an analysis to see the Quality Gate verdict and code-quality metrics.'}
          action={!isRunning && <Button variant="brand" onClick={startAnalysis}>Run first analysis</Button>}
        />
      </Card>
    )
  }

  const selectedMetrics = lens === 'overall' ? overview.lenses.overall : overview.lenses.newCode
  return (
    <div className="space-y-6">
      {isRunning && (
        <Card>
          <p className="text-sm text-mutedfg">A new analysis is in progress. Values below are from the latest completed analysis.</p>
        </Card>
      )}
      {overview.gate && <QualityGateBanner gate={overview.gate} />}
      {overview.latestAnalysis && <OverviewAnalysisMetadata overview={overview} />}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">Overview lens</h2>
          <p className="mt-1 text-sm text-mutedfg">Switch between stored Overall Code and New Code metrics.</p>
        </div>
        <CodeLensToggle value={lens} onChange={setLens} />
      </div>
      <OverviewIssueSummary summary={overview.issueSummary} />
      <OverviewMetricGrid projectKey={projectKey} lens={lens} metrics={selectedMetrics} />
    </div>
  )
}

function OverviewAnalysisMetadata({ overview }: { overview: ProjectOverview }) {
  const analysis = overview.latestAnalysis
  if (!analysis) return null
  const date = new Date(analysis.createdAt)
  const fullDate = Number.isNaN(date.getTime()) ? analysis.createdAt : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3 text-sm text-mutedfg">
        <Pill className="bg-elevated ring-1 ring-inset ring-border">
          <CalendarClock className="size-3.5" aria-hidden="true" />
          <time dateTime={analysis.createdAt} title={analysis.createdAt}>Analyzed {fullDate}</time>
        </Pill>
        {analysis.sourceRef && (
          <Pill className="bg-elevated ring-1 ring-inset ring-border">
            <GitBranch className="size-3.5" aria-hidden="true" />
            Source ref: <span className="font-mono">{analysis.sourceRef}</span>
          </Pill>
        )}
        {analysis.sourceCommit && (
          <Pill className="bg-elevated ring-1 ring-inset ring-border">
            <GitCommit className="size-3.5" aria-hidden="true" />
            Commit: <span className="font-mono" title={analysis.sourceCommit}>{analysis.sourceCommit.slice(0, 12)}</span>
          </Pill>
        )}
      </div>
    </Card>
  )
}
