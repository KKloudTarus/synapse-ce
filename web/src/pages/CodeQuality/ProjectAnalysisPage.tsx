import { AlertTriangle, Calendar } from '@untitledui/icons'
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FindingExplorer } from '../../components/codequality/FindingExplorer'
import { ProjectAnalysisFocusController } from '../../components/codequality/ProjectAnalysisFocusController'
import { ProjectCoverageDetail } from '../../components/codequality/ProjectCoverageDetail'
import { GateEvidence } from '../../components/codequality/qualityPresentation'
import { Button, Card, ErrorState, Pill } from '../../components/ui'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import {
  normalizeProjectAnalysisSearch,
  projectAnalysisLandmarks,
  type ProjectAnalysisFocus,
  type ProjectCodeLens,
} from '../../lib/projectAnalysisNavigation'
import { formatOverviewPercentage } from '../../lib/projectOverviewPresentation'
import type { RatedFindingDimension } from '../../lib/ratedFindingDimensions'
import type { LatestProjectAnalysis } from '../../lib/types'
import { ProjectRouteEmpty, useProjectRouteContext } from './CodeQualityProject'

export function ProjectAnalysisPage() {
  const { projectKey, isRunning, analysisRevision } = useProjectRouteContext()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigation = normalizeProjectAnalysisSearch(searchParams)
  const normalizedSearch = navigation.params.toString()

  const { data: latest, loading, error, refetch } = useFetch(
    () => api.latestProjectAnalysis(projectKey),
    { deps: [projectKey, analysisRevision] },
  )

  useEffect(() => {
    if (navigation.changed) setSearchParams(new URLSearchParams(normalizedSearch), { replace: true })
  }, [navigation.changed, normalizedSearch, setSearchParams])

  if (loading) {
    return <div className="h-20" />
  }
  if (error) {
    return (
      <div className="space-y-4">
        <ErrorState message={error} />
        <Button variant="secondary" onClick={() => refetch()}>Retry analysis details</Button>
      </div>
    )
  }
  if (!latest) {
    return (
      <div className="space-y-4">
        <Card title="Analysis details">
          <ProjectRouteEmpty running={isRunning} />
        </Card>
      </div>
    )
  }
  return (
    <div className="space-y-4">
      <LatestAnalysisView
        latest={latest}
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
  const duplication = snapshot.duplication && snapshot.duplication.totalLines > 0 ? 100 * snapshot.duplication.duplicatedLines / snapshot.duplication.totalLines : 0
  const dimension = ratedDimensionForNavigation(focus, lens)
  const navigationKey = `${projectKey}:${analysisRevision}:${lens}:${focus ?? 'none'}`

  const hasDuplicationBlocks = Boolean(snapshot.duplication && snapshot.duplication.blocks.length > 0)
  const languages = scan.codeQuality?.inventory ?? []

  return (
    <div className="space-y-4">
      <ProjectAnalysisFocusController projectKey={projectKey} analysisRevision={analysisRevision} focus={focus} lens={lens} />
      {running && (
        <Card>
          <p className="text-sm text-tertiary">A new analysis is in progress. Full details below are from the latest completed analysis.</p>
        </Card>
      )}

      {/* Section 1: Quality gate decision (compact) */}
      <Card title="Quality gate decision" className={snapshot.gate.passed ? 'border-low/25' : 'border-critical/30'}>
        <GateEvidence compact gate={snapshot.gate} info={snapshot.gateInfo} />
      </Card>

      {/* Section 2: Health Summary (merged 5 sections into 1 dense card) */}
      <Card
        title={lens === 'new-code' ? 'New Code period' : 'Analysis summary'}
        titleId={projectAnalysisLandmarks.newCode}
        titleTabIndex={-1}
        titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
        actions={
          <div className="flex items-center gap-2">
            <Pill>{snapshot.delta ? 'Compared with previous' : 'First baseline'}</Pill>
            <span className="flex items-center gap-1.5 text-xs text-tertiary">
              <Calendar className="size-3.5" aria-hidden="true" />
              {formatDate(snapshot.createdAt)}
            </span>
          </div>
        }
      >
        {/* Row 1: Key metrics */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <MetricCell label="Issues" value={snapshot.issues.total} />
          <MetricCell label="New issues" value={snapshot.newCode.counts.total} />
          <MetricCell label="Coverage" value={coverage === null ? 'Not supplied' : formatOverviewPercentage(coverage)} />
          <MetricCell label="Duplication" value={snapshot.duplication ? formatOverviewPercentage(duplication) : 'Unavailable'} />
          <MetricCell label="Code lines" value={snapshot.rating.linesOfCode.toLocaleString()} />
          <MetricCell label="Tech debt" value={formatDebt(snapshot.rating.techDebtMinutes)} />
        </div>

        {/* Row 2: Ratings (Overall + New Code side by side) */}
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-secondary bg-primary p-3">
            <div className="mb-2 text-xs font-semibold text-tertiary">Overall ratings</div>
            <div className="flex flex-wrap gap-4">
              <GradeBadgeItem label="Security" grade={snapshot.rating.security} />
              <GradeBadgeItem label="Reliability" grade={snapshot.rating.reliability} />
              <GradeBadgeItem label="Maintainability" grade={snapshot.rating.maintainability} />
            </div>
          </div>
          <div className="rounded-lg border border-secondary bg-primary p-3">
            <div className="mb-2 text-xs font-semibold text-tertiary">New code ratings</div>
            <div className="flex flex-wrap gap-4">
              <GradeBadgeItem label="Security" grade={snapshot.newCode.rating.security} />
              <GradeBadgeItem label="Reliability" grade={snapshot.newCode.rating.reliability} />
              {snapshot.newCode.rating.maintainability && <GradeBadgeItem label="Maintainability" grade={snapshot.newCode.rating.maintainability} />}
            </div>
          </div>
        </div>
        {!snapshot.newCode.rating.maintainability && (
          <p className="mt-3 text-xs text-tertiary">New Code maintainability is unavailable until source-diff changed lines are measured.</p>
        )}
        <p className="mt-2 text-xs text-tertiary">Individual New Code issues are not available in this view.</p>
      </Card>

      {/* Section 3: Conditional Details (only render when data is present) */}
      {/* Coverage details */}
      {snapshot.coverage && snapshot.coverage.totalLines > 0 && (
        <ProjectCoverageDetail coverage={snapshot.coverage} />
      )}

      {/* Security scan metadata */}
      {(scan.vulnerabilities.length > 0 || scan.components.length > 0 || scan.licenses.some((l) => l.verdict !== 'allow') || Boolean(scan.completeness?.warning)) && (
        <Card title="Security analysis">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MetricCell label="Findings" value={scan.findings.length} />
            <MetricCell label="Vulnerabilities" value={scan.vulnerabilities.length} />
            <MetricCell label="Packages" value={scan.components.length} />
            <MetricCell label="License issues" value={scan.licenses.filter((l) => l.verdict !== 'allow').length} />
          </div>
          {scan.completeness?.warning && (
            <p className="mt-4 flex items-start gap-2 text-xs text-medium">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {scan.completeness.warning}
            </p>
          )}
        </Card>
      )}

      {/* Findings Explorer */}
      {scan.findings.length > 0 && (
        <FindingExplorer
          findings={scan.findings}
          aiTriage={scan.aiTriage}
          headingId={projectAnalysisLandmarks.findings}
          initialDimension={dimension}
          dimensionNavigationKey={navigationKey}
        />
      )}

      {/* Languages */}
      {languages.length > 0 && (
        <Card title="Languages" actions={<span className="text-xs text-tertiary">{languages.length} detected</span>}>
          <div className="flex flex-wrap gap-2">
            {languages.map((lang) => (
              <Pill key={lang.language}>
                {lang.language} · {lang.codeLines.toLocaleString()} lines ({lang.files} files)
              </Pill>
            ))}
          </div>
        </Card>
      )}

      {/* Duplicated blocks */}
      {hasDuplicationBlocks && snapshot.duplication && (
        <Card
          title="Duplicated blocks"
          titleId={projectAnalysisLandmarks.duplications}
          titleTabIndex={-1}
          titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
          actions={<Pill>{snapshot.duplication.blocks.length} blocks</Pill>}
        >
          <ol className="max-h-[32rem] divide-y divide-secondary overflow-y-auto overscroll-contain">
            {snapshot.duplication.blocks.map((block, index) => (
              <li key={index} className="py-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                  <span className="font-medium text-primary">Duplicate group {index + 1}</span>
                  <span className="font-mono text-xs tabular-nums text-tertiary">
                    {block.tokens.toLocaleString()} tokens · {block.occurrences.length} locations
                  </span>
                </div>
                <div className="mt-2 space-y-1 rounded-md border border-secondary bg-secondary/30 px-3 py-2 font-mono text-xs text-tertiary">
                  {block.occurrences.map((occ, occIndex) => (
                    <div key={occIndex} className="flex min-w-0 items-center justify-between gap-2">
                      <span className="truncate text-primary">{occ.file}</span>
                      <span className="shrink-0 tabular-nums">lines {occ.startLine}–{occ.endLine}</span>
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        </Card>
      )}
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

function MetricCell({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-secondary bg-secondary/30 p-3 shadow-xs">
      <div className="font-mono text-xl font-bold tabular-nums text-primary">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      <div className="mt-0.5 text-xs text-tertiary">{label}</div>
    </div>
  )
}

function GradeBadgeItem({ label, grade }: { label: string; grade: string | null }) {
  const color =
    grade === 'A'
      ? 'text-utility-green-600 dark:text-utility-green-400'
      : grade === 'B'
      ? 'text-utility-blue-600 dark:text-utility-blue-400'
      : grade === 'C'
      ? 'text-utility-orange-600 dark:text-utility-orange-400'
      : grade === 'D'
      ? 'text-utility-yellow-600 dark:text-utility-yellow-400'
      : grade === 'E'
      ? 'text-utility-red-600 dark:text-utility-red-400'
      : 'text-tertiary'
  return (
    <span className="flex items-center gap-1.5">
      <span className={`font-mono text-lg font-bold ${color}`}>{grade || '?'}</span>
      <span className="text-xs text-tertiary">{label}</span>
    </span>
  )
}

function formatDebt(minutes: number) {
  const h = Math.floor(minutes / 60)
  const m = minutes % 60
  if (h === 0) return `${m}m`
  if (m === 0) return `${h}h`
  return `${h}h ${m}m`
}

function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
