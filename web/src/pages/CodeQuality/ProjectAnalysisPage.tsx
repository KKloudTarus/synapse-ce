import {
  AlertTriangle,
  Calendar,
  Clock,
  Copy01,
  FileCode01,
  PackageCheck,
  Shield01,
  ShieldTick,
  Virus,
  Zap,
} from '@untitledui/icons'
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FindingExplorer } from '../../components/codequality/FindingExplorer'
import { ProjectAnalysisFocusController } from '../../components/codequality/ProjectAnalysisFocusController'
import { ProjectCoverageDetail } from '../../components/codequality/ProjectCoverageDetail'
import { GateEvidence } from '../../components/codequality/qualityPresentation'
import { Button, Card, ErrorState, Pill, cn } from '../../components/ui'
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

const LANGUAGE_COLORS = [
  'bg-utility-blue-600',
  'bg-utility-orange-600',
  'bg-brand-solid',
  'bg-utility-green-600',
  'bg-utility-pink-600',
  'bg-utility-purple-600',
  'bg-utility-indigo-600',
]

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
        <Button variant="secondary" onClick={() => refetch()}>
          Retry analysis details
        </Button>
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
  const coverage =
    snapshot.coverage && snapshot.coverage.totalLines > 0
      ? (100 * snapshot.coverage.coveredLines) / snapshot.coverage.totalLines
      : null
  const duplication =
    snapshot.duplication && snapshot.duplication.totalLines > 0
      ? (100 * snapshot.duplication.duplicatedLines) / snapshot.duplication.totalLines
      : 0
  const dimension = ratedDimensionForNavigation(focus, lens)
  const navigationKey = `${projectKey}:${analysisRevision}:${lens}:${focus ?? 'none'}`

  const hasDuplicationBlocks = Boolean(snapshot.duplication && snapshot.duplication.blocks.length > 0)
  const languages = scan.codeQuality?.inventory ?? []
  const totalLanguageLines = languages.reduce((acc, curr) => acc + curr.codeLines, 0)

  return (
    <div className="space-y-4">
      <ProjectAnalysisFocusController
        projectKey={projectKey}
        analysisRevision={analysisRevision}
        focus={focus}
        lens={lens}
      />
      {running && (
        <Card>
          <p className="text-sm text-tertiary">
            A new analysis is in progress. Full details below are from the latest completed analysis.
          </p>
        </Card>
      )}

      {/* Section 1: Quality Gate Decision (Compact) */}
      <Card title="Quality gate decision" className="border-secondary bg-primary">
        <GateEvidence compact gate={snapshot.gate} info={snapshot.gateInfo} />
      </Card>

      {/* Section 2: Analysis Summary & Quality Ratings */}
      <Card
        title={lens === 'new-code' ? 'New Code period' : 'Analysis summary'}
        titleId={projectAnalysisLandmarks.newCode}
        titleTabIndex={-1}
        titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
        actions={
          <div className="flex items-center gap-2">
            <Pill className="font-medium text-xs">
              {snapshot.delta ? 'Compared with previous' : 'First baseline'}
            </Pill>
            <span className="flex items-center gap-1 text-xs text-tertiary font-medium">
              <Calendar className="size-3.5" aria-hidden="true" />
              {formatDate(snapshot.createdAt)}
            </span>
          </div>
        }
      >
        {/* Row 1: Key metrics */}
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
          <MetricCell label="Total Issues" value={snapshot.issues.total} icon={Virus} />
          <MetricCell label="New Issues" value={snapshot.newCode.counts.total} icon={AlertTriangle} />
          <MetricCell
            label="Line Coverage"
            value={coverage === null ? 'Not supplied' : formatOverviewPercentage(coverage)}
            icon={ShieldTick}
          />
          <MetricCell
            label="Duplication"
            value={snapshot.duplication ? formatOverviewPercentage(duplication) : 'Unavailable'}
            icon={Copy01}
          />
          <MetricCell
            label="Code Lines"
            value={snapshot.rating.linesOfCode.toLocaleString()}
            icon={FileCode01}
          />
          <MetricCell
            label="Tech Debt"
            value={formatDebt(snapshot.rating.techDebtMinutes)}
            icon={Clock}
          />
        </div>

        {/* Row 2: Ratings (Overall + New Code side by side) */}
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-secondary bg-primary p-3 shadow-2xs">
            <div className="mb-2 text-xs font-bold uppercase tracking-wider text-tertiary">
              Overall code ratings
            </div>
            <div className="flex flex-wrap gap-4">
              <GradeBadgeItem label="Security" grade={snapshot.rating.security} />
              <GradeBadgeItem label="Reliability" grade={snapshot.rating.reliability} />
              <GradeBadgeItem label="Maintainability" grade={snapshot.rating.maintainability} />
            </div>
          </div>
          <div className="rounded-xl border border-secondary bg-primary p-3 shadow-2xs">
            <div className="mb-2 text-xs font-bold uppercase tracking-wider text-tertiary">
              New code ratings
            </div>
            <div className="flex flex-wrap gap-4">
              <GradeBadgeItem label="Security" grade={snapshot.newCode.rating.security} />
              <GradeBadgeItem label="Reliability" grade={snapshot.newCode.rating.reliability} />
              {snapshot.newCode.rating.maintainability && (
                <GradeBadgeItem label="Maintainability" grade={snapshot.newCode.rating.maintainability} />
              )}
            </div>
          </div>
        </div>
        {lens === 'new-code' && (
          <p className="mt-3 text-xs text-tertiary">Individual New Code issues are not available in this view.</p>
        )}
      </Card>

      {/* Section 3: Coverage details */}
      {snapshot.coverage && snapshot.coverage.totalLines > 0 && (
        <ProjectCoverageDetail coverage={snapshot.coverage} />
      )}

      {/* Section 4: Security scan metadata & Languages (Combined Overview) */}
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
        {/* Security Scan Summary */}
        {(scan.vulnerabilities.length > 0 ||
          scan.components.length > 0 ||
          scan.licenses.some((l) => l.verdict !== 'allow') ||
          Boolean(scan.completeness?.warning)) && (
          <Card title="Security scan overview" className="h-full flex flex-col justify-between">
            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
              <MetricCell label="Findings" value={scan.findings.length} icon={Zap} />
              <MetricCell label="Vulnerabilities" value={scan.vulnerabilities.length} icon={Shield01} />
              <MetricCell label="Packages" value={scan.components.length} icon={PackageCheck} />
              <MetricCell
                label="License Issues"
                value={scan.licenses.filter((l) => l.verdict !== 'allow').length}
                icon={AlertTriangle}
              />
            </div>
            {scan.completeness?.warning && (
              <p className="mt-2.5 flex items-start gap-2 text-xs text-warning-primary font-medium">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                <span>{scan.completeness.warning}</span>
              </p>
            )}
          </Card>
        )}

        {/* Language Distribution */}
        {languages.length > 0 && (
          <Card
            title="Language distribution"
            actions={<span className="text-xs text-tertiary font-semibold">{languages.length} detected</span>}
            className="h-full flex flex-col justify-between"
          >
            {/* Visual Language Bar */}
            <div className="h-3 w-full rounded-full bg-secondary overflow-hidden flex mb-3 shadow-2xs">
              {languages.map((lang, idx) => {
                const pct = totalLanguageLines > 0 ? (lang.codeLines / totalLanguageLines) * 100 : 0
                return (
                  <div
                    key={lang.language}
                    className={cn('h-full transition-all', LANGUAGE_COLORS[idx % LANGUAGE_COLORS.length])}
                    style={{ width: `${Math.max(2, pct)}%` }}
                    title={`${lang.language}: ${pct.toFixed(1)}%`}
                  />
                )
              })}
            </div>

            <div className="flex flex-wrap gap-2">
              {languages.map((lang, idx) => {
                const pct = totalLanguageLines > 0 ? (lang.codeLines / totalLanguageLines) * 100 : 0
                return (
                  <Pill key={lang.language} className="text-xs py-1 px-2.5 flex items-center gap-1.5">
                    <span className={cn('size-2 rounded-full shrink-0', LANGUAGE_COLORS[idx % LANGUAGE_COLORS.length])} />
                    <strong className="text-primary">{lang.language}</strong>
                    <span>:</span>
                    <span>{lang.codeLines.toLocaleString()} lines ({pct.toFixed(1)}%)</span>
                    <span className="text-tertiary">({lang.files} files)</span>
                  </Pill>
                )
              })}
            </div>
          </Card>
        )}
      </div>

      {/* Section 5: Findings Explorer */}
      {scan.findings.length > 0 && (
        <FindingExplorer
          findings={scan.findings}
          aiTriage={scan.aiTriage}
          headingId={projectAnalysisLandmarks.findings}
          initialDimension={dimension}
          dimensionNavigationKey={navigationKey}
        />
      )}

      {/* Section 6: Duplicated blocks */}
      {hasDuplicationBlocks && snapshot.duplication && (
        <Card
          title="Duplicated blocks"
          titleId={projectAnalysisLandmarks.duplications}
          titleTabIndex={-1}
          titleClassName="scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60"
          actions={<Pill className="font-semibold">{snapshot.duplication.blocks.length} blocks</Pill>}
        >
          <ol className="max-h-[32rem] divide-y divide-secondary/50 overflow-y-auto overscroll-contain">
            {snapshot.duplication.blocks.map((block, index) => (
              <li key={index} className="py-2.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                  <span className="font-bold text-primary">Duplicate group {index + 1}</span>
                  <span className="font-mono text-xs tabular-nums text-tertiary">
                    {block.tokens.toLocaleString()} tokens ({block.occurrences.length} locations)
                  </span>
                </div>
                <div className="mt-1.5 space-y-1 rounded-lg border border-secondary bg-secondary/30 px-3 py-2 font-mono text-xs text-tertiary">
                  {block.occurrences.map((occ, occIndex) => (
                    <div key={occIndex} className="flex min-w-0 items-center justify-between gap-2">
                      <span className="truncate text-primary font-medium">{occ.file}</span>
                      <span className="shrink-0 tabular-nums text-secondary">
                        lines {occ.startLine}–{occ.endLine}
                      </span>
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

function MetricCell({
  label,
  value,
  icon: Icon,
}: {
  label: string
  value: string | number
  icon?: React.ComponentType<{ className?: string }>
}) {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-2.5 sm:p-3 shadow-2xs flex flex-col justify-between min-w-0">
      <div className="flex items-center justify-between gap-1 text-secondary mb-1">
        <span className="text-[11px] font-semibold truncate">{label}</span>
        {Icon && <Icon className="size-3.5 text-brand-secondary shrink-0" aria-hidden="true" />}
      </div>
      <div className="font-mono text-base sm:text-lg font-bold tabular-nums text-primary truncate leading-tight">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  )
}

function GradeBadgeItem({ label, grade }: { label: string; grade: string | null }) {
  const g = (grade || '?').toUpperCase()
  const colorMap: Record<string, string> = {
    A: 'bg-success-primary/15 text-success-primary border-success-primary/35',
    B: 'bg-utility-green-500/15 text-utility-green-600 dark:text-utility-green-400 border-utility-green-500/35',
    C: 'bg-warning-primary/15 text-warning-primary border-warning-primary/35',
    D: 'bg-utility-orange-500/15 text-utility-orange-600 dark:text-utility-orange-400 border-utility-orange-500/35',
    E: 'bg-error-primary/15 text-error-primary border-error-primary/35',
  }

  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          'inline-flex items-center justify-center size-6 rounded-md font-mono font-bold text-xs border shadow-2xs',
          colorMap[g] || 'bg-secondary text-primary border-secondary',
        )}
      >
        {g}
      </span>
      <span className="text-xs font-semibold text-primary">{label}</span>
    </div>
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
