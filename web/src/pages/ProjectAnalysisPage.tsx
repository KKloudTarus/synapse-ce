import { AlertTriangle, CalendarClock, ShieldAlert } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { CodeQualityReportView } from '../components/codequality/CodeQualityReportView'
import { FindingExplorer } from '../components/codequality/FindingExplorer'
import { ProjectCoverageDetail } from '../components/codequality/ProjectCoverageDetail'
import { GateEvidence, GradeBadge } from '../components/codequality/qualityPresentation'
import { Button, Card, EmptyState, ErrorState, Pill } from '../components/ui'
import { api } from '../lib/api'
import { projectAnalysisLandmarks } from '../lib/projectAnalysisNavigation'
import type { LatestProjectAnalysis } from '../lib/types'
import { ProjectRouteEmpty, useProjectRouteContext } from './CodeQualityProject'

type LoadState =
  | { status: 'loading' }
  | { status: 'loaded'; latest: LatestProjectAnalysis | null }
  | { status: 'error'; message: string }

export function ProjectAnalysisPage() {
  const { projectKey, isRunning, analysisRevision } = useProjectRouteContext()
  const [state, setState] = useState<LoadState>({ status: 'loading' })
  const latestRequest = useRef<symbol | null>(null)

  function load() {
    const token = Symbol()
    latestRequest.current = token
    setState({ status: 'loading' })
    api.latestProjectAnalysis(projectKey)
      .then((latest) => {
        if (latestRequest.current === token) setState({ status: 'loaded', latest })
      })
      .catch((e) => {
        if (latestRequest.current === token) setState({ status: 'error', message: e instanceof Error ? e.message : 'Failed to load analysis result' })
      })
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectKey, analysisRevision])

  if (state.status === 'loading') return <Card title="Analysis details"><EmptyState icon={ShieldAlert} title="Loading analysis details" hint="Fetching the full latest analysis report." /></Card>
  if (state.status === 'error') {
    return (
      <div className="space-y-3">
        <ErrorState message={state.message} />
        <Button variant="secondary" onClick={load}>Retry analysis details</Button>
      </div>
    )
  }
  if (!state.latest) return <Card title="Analysis details"><ProjectRouteEmpty running={isRunning} /></Card>
  return <LatestAnalysisView latest={state.latest} running={isRunning} />
}

function LatestAnalysisView({ latest, running }: { latest: LatestProjectAnalysis; running: boolean }) {
  const { analysis: snapshot, result: scan } = latest
  const coverage = snapshot.coverage && snapshot.coverage.totalLines > 0 ? 100 * snapshot.coverage.coveredLines / snapshot.coverage.totalLines : null
  const duplication = snapshot.duplication.totalLines > 0 ? 100 * snapshot.duplication.duplicatedLines / snapshot.duplication.totalLines : 0
  return (
    <div className="space-y-6">
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
          <p className="mt-3 text-xs text-mutedfg">Individual New Code issue drill-down will be available in the Issues Explorer.</p>
        </Card>
        <Card title="Overall health" actions={<span className="flex items-center gap-1.5 text-xs text-mutedfg"><CalendarClock className="size-3.5" aria-hidden="true" />{formatDate(snapshot.createdAt)}</span>}>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <HealthMetric label="Issues" value={withDelta(snapshot.issues.total, snapshot.delta?.issues.total)} />
            <HealthMetric label="Coverage" value={coverage === null ? 'Not supplied' : `${coverage.toFixed(1)}%`} />
            <HealthMetric label="Duplication" value={`${duplication.toFixed(1)}%`} hint={snapshot.delta ? `${signed(snapshot.delta.measures.duplication_density ?? 0)}% vs previous` : undefined} />
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
      <FindingExplorer findings={scan.findings} headingId={projectAnalysisLandmarks.findings} />
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
