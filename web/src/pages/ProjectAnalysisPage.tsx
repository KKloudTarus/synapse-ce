import { AlertTriangle, ArrowLeft, CalendarClock, ShieldAlert } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { CodeQualityReportView } from '../components/codequality/CodeQualityReportView'
import { FindingExplorer } from '../components/codequality/FindingExplorer'
import { ProjectAnalysisFocusController } from '../components/codequality/ProjectAnalysisFocusController'
import { ProjectCoverageDetail } from '../components/codequality/ProjectCoverageDetail'
import { GateEvidence, GradeBadge } from '../components/codequality/qualityPresentation'
import { Button, Card, EmptyState, ErrorState, Pill } from '../components/ui'
import { api } from '../lib/api'
import {
  normalizeProjectAnalysisSearch,
  projectAnalysisLandmarks,
  projectOverviewPath,
  type ProjectAnalysisFocus,
  type ProjectCodeLens,
} from '../lib/projectAnalysisNavigation'
import { formatOverviewPercentage } from '../lib/projectOverviewPresentation'
import type { RatedFindingDimension } from '../lib/ratedFindingDimensions'
import type { LatestProjectAnalysis } from '../lib/types'
import { ProjectRouteEmpty, useProjectRouteContext } from './CodeQualityProject'

type LoadState =
  | { status: 'loading'; projectKey: string; analysisRevision: number }
  | { status: 'loaded'; projectKey: string; analysisRevision: number; latest: LatestProjectAnalysis | null }
  | { status: 'error'; projectKey: string; analysisRevision: number; message: string }

export function ProjectAnalysisPage() {
  const { projectKey, isRunning, analysisRevision } = useProjectRouteContext()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigation = normalizeProjectAnalysisSearch(searchParams)
  const normalizedSearch = navigation.params.toString()
  const [state, setState] = useState<LoadState>({ status: 'loading', projectKey, analysisRevision })
  const latestRequest = useRef<symbol | null>(null)

  function load(requestedProjectKey = projectKey, requestedRevision = analysisRevision) {
    const token = Symbol()
    latestRequest.current = token
    setState({ status: 'loading', projectKey: requestedProjectKey, analysisRevision: requestedRevision })
    api.latestProjectAnalysis(requestedProjectKey)
      .then((latest) => {
        if (latestRequest.current === token) {
          setState({ status: 'loaded', projectKey: requestedProjectKey, analysisRevision: requestedRevision, latest })
        }
      })
      .catch((e) => {
        if (latestRequest.current === token) {
          setState({
            status: 'error',
            projectKey: requestedProjectKey,
            analysisRevision: requestedRevision,
            message: e instanceof Error ? e.message : 'Failed to load analysis result',
          })
        }
      })
    return token
  }

  useEffect(() => {
    const token = load(projectKey, analysisRevision)
    return () => {
      if (latestRequest.current === token) latestRequest.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectKey, analysisRevision])

  useEffect(() => {
    if (navigation.changed) setSearchParams(new URLSearchParams(normalizedSearch), { replace: true })
  }, [navigation.changed, normalizedSearch, setSearchParams])

  const currentState = state.projectKey === projectKey && state.analysisRevision === analysisRevision
    ? state
    : { status: 'loading' as const, projectKey, analysisRevision }
  const backToOverview = projectOverviewPath(projectKey, navigation.lens)
  const backLink = (
    <Link to={backToOverview} className="inline-flex w-fit items-center gap-1.5 rounded-md text-sm text-branddim hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
      <ArrowLeft className="size-4" aria-hidden="true" /> Back to Overview
    </Link>
  )

  if (currentState.status === 'loading') return <div className="space-y-3">{backLink}<Card title="Analysis details"><EmptyState icon={ShieldAlert} title="Loading analysis details" hint="Fetching the full latest analysis report." /></Card></div>
  if (currentState.status === 'error') {
    return (
      <div className="space-y-3">
        {backLink}
        <ErrorState message={currentState.message} />
        <Button variant="secondary" onClick={() => load()}>Retry analysis details</Button>
      </div>
    )
  }
  if (!currentState.latest) return <div className="space-y-3">{backLink}<Card title="Analysis details"><ProjectRouteEmpty running={isRunning} /></Card></div>
  return (
    <div className="space-y-3">
      {backLink}
      <LatestAnalysisView
        latest={currentState.latest}
        running={isRunning}
        projectKey={projectKey}
        analysisRevision={analysisRevision}
        focus={navigation.focus}
        lens={navigation.lens}
      />
    </div>
  )
}

function LatestAnalysisView({
  latest,
  running,
  projectKey,
  analysisRevision,
  focus,
  lens,
}: {
  latest: LatestProjectAnalysis
  running: boolean
  projectKey: string
  analysisRevision: number
  focus: ProjectAnalysisFocus | null
  lens: ProjectCodeLens
}) {
  const { analysis: snapshot, result: scan } = latest
  const coverage = snapshot.coverage && snapshot.coverage.totalLines > 0 ? 100 * snapshot.coverage.coveredLines / snapshot.coverage.totalLines : null
  const duplication = snapshot.duplication.totalLines > 0 ? 100 * snapshot.duplication.duplicatedLines / snapshot.duplication.totalLines : 0
  const dimension = ratedDimensionForNavigation(focus, lens)
  const navigationKey = `${projectKey}:${analysisRevision}:${lens}:${focus ?? 'none'}`
  return (
    <div className="space-y-6">
      <ProjectAnalysisFocusController projectKey={projectKey} analysisRevision={analysisRevision} focus={focus} lens={lens} />
      {running && (
        <Card>
          <p className="text-sm text-mutedfg">A new analysis is in progress. Full details below are from the latest completed analysis.</p>
        </Card>
      )}
      <Card title="Quality gate decision" className={snapshot.gate.passed ? 'border-low/25' : 'border-critical/30'}>
        <GateEvidence gate={snapshot.gate} info={snapshot.gateInfo} />
      </Card>
      <div className="grid gap-6 xl:grid-cols-[1fr_1.25fr]">
        <Card title="New Code period" titleId={projectAnalysisLandmarks.newCode} titleTabIndex={-1} titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60" actions={<Pill>{snapshot.delta ? 'Compared with previous' : 'First baseline'}</Pill>}>
          <p className="text-sm text-mutedfg">
            {snapshot.delta ? `Changes since analysis ${snapshot.newCode.previousId.slice(0, 12)}. Material escalation and reactivation count as New Code.` : 'First analysis: every current publishable issue is treated as New Code; no comparison delta is available.'}
          </p>
          <div className="mt-4 grid grid-cols-3 gap-3">
            <HealthMetric label="New issues" value={snapshot.newCode.counts.total} />
            <HealthMetric label="New critical" value={snapshot.newCode.counts.bySeverity.critical ?? 0} />
            <HealthMetric label="New high" value={snapshot.newCode.counts.bySeverity.high ?? 0} />
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <GradeBadge compact label="Security" grade={snapshot.newCode.rating.security} />
            <GradeBadge compact label="Reliability" grade={snapshot.newCode.rating.reliability} />
            {snapshot.newCode.rating.maintainability && <GradeBadge compact label="Maintainability" grade={snapshot.newCode.rating.maintainability} />}
          </div>
          {!snapshot.newCode.rating.maintainability && <p className="mt-3 text-xs text-mutedfg">New Code maintainability is unavailable until source-diff changed lines are measured.</p>}
          <p className="mt-3 text-xs text-mutedfg">Individual New Code issues are not available in this view.</p>
        </Card>
        <Card title="Overall health" actions={<span className="flex items-center gap-1.5 text-xs text-mutedfg"><CalendarClock className="size-3.5" aria-hidden="true" />{formatDate(snapshot.createdAt)}</span>}>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <HealthMetric label="Issues" value={withDelta(snapshot.issues.total, snapshot.delta?.issues.total)} />
            <HealthMetric label="Coverage" value={coverage === null ? 'Not supplied' : formatOverviewPercentage(coverage)} />
            <HealthMetric label="Duplication" value={formatOverviewPercentage(duplication)} hint={snapshot.delta ? `${signed(snapshot.delta.measures.duplication_density ?? 0)}% vs previous` : undefined} />
            <HealthMetric label="Code lines" value={snapshot.rating.linesOfCode.toLocaleString()} />
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <GradeBadge compact label="Security" grade={snapshot.rating.security} />
            <GradeBadge compact label="Reliability" grade={snapshot.rating.reliability} />
            <GradeBadge compact label="Maintainability" grade={snapshot.rating.maintainability} />
          </div>
        </Card>
      </div>
      <ProjectCoverageDetail coverage={snapshot.coverage} />
      <Card title="Security analysis">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <HealthMetric label="Findings" value={scan.findings.length} />
          <HealthMetric label="Vulnerabilities" value={scan.vulnerabilities.length} />
          <HealthMetric label="Packages" value={scan.components.length} />
          <HealthMetric label="License issues" value={scan.licenses.filter((license) => license.verdict !== 'allow').length} />
        </div>
        {scan.completeness.warning && (
          <p className="mt-4 flex items-start gap-2 text-xs text-medium">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            {scan.completeness.warning}
          </p>
        )}
      </Card>
      <FindingExplorer findings={scan.findings} headingId={projectAnalysisLandmarks.findings} initialDimension={dimension} dimensionNavigationKey={navigationKey} />
      <CodeQualityReportView
        report={scan.codeQuality}
        empty={<Card title="Code quality"><EmptyState icon={ShieldAlert} title="Code quality unavailable" hint="This completed scan did not produce a code-quality report." /></Card>}
        landmarkIds={{
          qualityRatings: projectAnalysisLandmarks.qualityRatings,
          duplications: projectAnalysisLandmarks.duplications,
        }}
      />
    </div>
  )
}

function ratedDimensionForNavigation(
  focus: ProjectAnalysisFocus | null,
  lens: ProjectCodeLens,
): RatedFindingDimension | null {
  if (lens !== 'overall') return null
  return focus === 'security' || focus === 'reliability' || focus === 'maintainability' ? focus : null
}

function HealthMetric({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-4 py-3">
      <div className="font-mono text-xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-mutedfg">{label}</div>
      {hint && <div className="mt-1 text-[10px] text-subtlefg">{hint}</div>}
    </div>
  )
}

function withDelta(value: number, delta?: number) {
  return delta === undefined ? value.toLocaleString() : `${value.toLocaleString()} (${signed(delta)})`
}

function signed(value: number) {
  return value > 0 ? `+${Number(value.toFixed(2))}` : String(Number(value.toFixed(2)))
}

function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
