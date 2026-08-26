import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BarChart01,
  CheckCircle,
  Copy01,
  FileCode01,
  GitBranch01,
  PieChart01,
  Shield01,
  ShieldTick,
  Target04,
  XCircle,
} from '@untitledui/icons'
import { useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ProjectOverviewSkeleton } from '../../components/codequality/projectOverview/ProjectOverviewSkeleton'
import { Button, Card, EmptyState, ErrorState, Pill, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type {
  OverviewGrade,
  ProjectOverview,
  ProjectOverviewAnalysis,
  ProjectOverviewGate,
  ProjectOverviewLens,
} from '../../lib/projectOverview'
import { overviewDetailTarget } from '../../lib/projectOverviewDetailTargets'
import {
  formatGateEvidenceValue,
  formatOverviewPercentage,
  gateMetricLabel,
  gateSourceLabel,
  isValidCodeLens,
  metricCardsForLens,
  parseCodeLens,
  serializeCodeLens,
  unavailableReasonText,
  type CodeLens,
  type OverviewMetricCardModel,
} from '../../lib/projectOverviewPresentation'
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
          icon={isRunning ? BarChart01 : ShieldTick}
          title={isRunning ? 'Analysis in progress' : 'No completed analysis yet'}
          hint={isRunning ? 'The Overview will appear after the first successful analysis completes.' : 'Run an analysis to see the Quality Gate verdict and code-quality metrics.'}
          action={!isRunning && <Button variant="brand" onClick={startAnalysis}>Run first analysis</Button>}
        />
      </Card>
    )
  }

  const selectedMetrics = lens === 'overall' ? overview.lenses.overall : overview.lenses.newCode
  const failedConditions = overview.gate?.status === 'failed' ? overview.gate.failedConditions : []
  const failedCount = failedConditions.length

  return (
    <div className="space-y-6">
      {isRunning && (
        <Card>
          <p className="text-sm text-tertiary">A new analysis is in progress. Values below are from the latest completed analysis.</p>
        </Card>
      )}
      {overview.gate && <QualityGateCard gate={overview.gate} analysis={overview.latestAnalysis} />}

      {/* Overview lens toggle + inline issue stats */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-secondary bg-primary px-4 py-3 shadow-xs">
        <div role="group" aria-label="Overview lens" className="flex items-center gap-1 rounded-lg bg-secondary p-1">
          <button
            type="button"
            className={cn(
              'rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
              lens === 'overall'
                ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                : 'text-tertiary hover:text-primary',
            )}
            aria-pressed={lens === 'overall'}
            onClick={() => setLens('overall')}
          >
            Overall Code
          </button>
          <button
            type="button"
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
              lens === 'new-code'
                ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                : 'text-tertiary hover:text-primary',
            )}
            aria-pressed={lens === 'new-code'}
            onClick={() => setLens('new-code')}
          >
            <span>New Code</span>
            {failedCount > 0 && (
              <span className="inline-flex items-center rounded-full px-1.5 py-0.2 font-mono text-[10px] font-bold bg-error-primary/15 text-error-primary border border-error/30">
                {failedCount} failed
              </span>
            )}
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-warning/30 bg-warning-primary/10 px-2.5 py-1 font-medium text-warning-primary">
            <AlertTriangle className="size-3.5" aria-hidden="true" />
            <span className="font-bold tabular-nums font-mono">
              {overview.issueSummary?.newCodeTotal?.value !== null && overview.issueSummary?.newCodeTotal?.value !== undefined
                ? overview.issueSummary.newCodeTotal.value.toLocaleString()
                : '0'}
            </span>
            <span>new issues</span>
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-secondary/60 px-2.5 py-1 font-medium text-secondary">
            <CheckCircle className="size-3.5 text-success-primary" aria-hidden="true" />
            <span className="font-bold tabular-nums font-mono">
              {overview.issueSummary?.acceptedOverallTotal?.value !== null && overview.issueSummary?.acceptedOverallTotal?.value !== undefined
                ? overview.issueSummary.acceptedOverallTotal.value.toLocaleString()
                : '0'}
            </span>
            <span>accepted (overall)</span>
          </span>
        </div>
      </div>

      {/* Quality metrics compact 6 cards */}
      <MetricCardsSection
        projectKey={projectKey}
        lens={lens}
        metrics={selectedMetrics}
        failedConditions={failedConditions}
      />
    </div>
  )
}

function QualityGateCard({ gate, analysis }: { gate: ProjectOverviewGate; analysis: ProjectOverviewAnalysis | null }) {
  const passed = gate.status === 'passed'
  const incomplete = gate.status === 'incomplete'
  const source = gateSourceLabel(gate.source)
  const gateName = gate.name ?? 'Recorded quality gate'
  const tone = passed
    ? { card: 'border-low/30 bg-low/5', text: 'text-low', pill: 'bg-low/15 text-low ring-1 ring-inset ring-low/20', label: 'Passed', icon: CheckCircle }
    : incomplete
      ? { card: 'border-medium/30 bg-medium/5', text: 'text-medium', pill: 'bg-medium/15 text-medium ring-1 ring-inset ring-medium/20', label: 'Incomplete', icon: AlertTriangle }
      : { card: 'border-critical/30 bg-critical/5', text: 'text-critical', pill: 'bg-critical/15 text-critical ring-1 ring-inset ring-critical/20', label: 'Failed', icon: XCircle }
  const Icon = tone.icon
  const date = analysis ? new Date(analysis.createdAt) : null
  const fullDate = date && !Number.isNaN(date.getTime())
    ? date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : analysis?.createdAt ?? ''

  return (
    <Card className={cn(tone.card, 'shadow-xs')}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon className={cn('size-5', tone.text)} aria-hidden="true" />
            <h2 className={cn('text-xl font-bold tracking-tight', tone.text)}>Quality Gate {tone.label}</h2>
          </div>
          <p className="mt-1 text-xs text-secondary font-medium">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={cn(tone.pill, 'font-semibold')}>{tone.label}</Pill>
      </div>
      {incomplete && (
        <p className="mt-4 text-sm text-primary">
          Analysis was incomplete, so this quality gate cannot be used as a passing result.
        </p>
      )}
      {gate.status === 'failed' && (
        <div className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-secondary">
            {gate.failedConditions.length} {gate.failedConditions.length === 1 ? 'condition' : 'conditions'} failed
          </p>
          <ol className="mt-2.5 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {gate.failedConditions.map((condition, index) => (
              <li
                key={`${condition.metric}-${index}`}
                className="flex flex-col justify-between rounded-xl border border-critical/30 bg-primary p-3 shadow-2xs transition-all hover:border-critical/60"
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                  <AlertTriangle className="size-3.5 text-critical shrink-0" aria-hidden="true" />
                  <span className="truncate">{gateMetricLabel(condition.metric)}</span>
                </div>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-1.5">
                  <span className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-bold bg-error-primary/10 text-error-primary border border-error/20">
                    Actual: {formatGateEvidenceValue(condition.metric, condition.actual)}
                  </span>
                  <span className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] text-secondary bg-secondary border border-secondary">
                    Target: {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                  </span>
                </div>
                {/* Screen reader / test compatibility string */}
                <div className="sr-only">
                  {formatGateEvidenceValue(condition.metric, condition.actual)} — expected {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
      {analysis && (
        <div className="mt-3.5 flex flex-wrap items-center gap-2.5 border-t border-secondary pt-3 text-xs text-tertiary">
          <span>Analyzed {fullDate}</span>
          {analysis.sourceRef && (
            <>
              <span className="text-quaternary">·</span>
              <span className="inline-flex items-center gap-1 font-mono text-secondary">
                <GitBranch01 className="size-3 text-quaternary" aria-hidden="true" />
                {analysis.sourceRef}
              </span>
            </>
          )}
          {analysis.sourceCommit && (
            <>
              <span className="text-quaternary">·</span>
              <span className="font-mono text-secondary" title={analysis.sourceCommit}>
                {analysis.sourceCommit.slice(0, 12)}
              </span>
            </>
          )}
        </div>
      )}
    </Card>
  )
}

function getMetricColor(card: OverviewMetricCardModel): string {
  if (card.metric.availability !== 'available') return 'text-tertiary'
  if (card.kind === 'rating') {
    switch (card.metric.grade) {
      case 'A':
        return 'text-success-primary'
      case 'B':
        return 'text-utility-blue-600 dark:text-utility-blue-400'
      case 'C':
        return 'text-warning-primary'
      case 'D':
        return 'text-utility-orange-600 dark:text-utility-orange-400'
      case 'E':
        return 'text-error-primary'
      default:
        return 'text-primary'
    }
  }
  if (card.kind === 'percentage' && card.metric.value !== null) {
    const val = card.metric.value
    if (card.key === 'duplications') {
      if (val <= 3.5) return 'text-success-primary'
      if (val <= 10) return 'text-utility-orange-600 dark:text-utility-orange-400'
      return 'text-error-primary'
    }
    if (card.key === 'coverage') {
      if (val >= 80) return 'text-success-primary'
      if (val >= 50) return 'text-utility-indigo-600 dark:text-utility-indigo-400'
      return 'text-error-primary'
    }
    if (card.key === 'securityHotspotsReviewed') {
      if (val >= 80) return 'text-success-primary'
      if (val >= 50) return 'text-brand-secondary'
      return 'text-error-primary'
    }
  }
  return 'text-primary'
}

function gradePillStyle(grade: OverviewGrade | null) {
  switch (grade) {
    case 'A':
      return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    case 'B':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'C':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'D':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'E':
      return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

const domainIcons: Record<string, typeof Shield01> = {
  security: Shield01,
  reliability: AlertCircle,
  maintainability: FileCode01,
  securityHotspotsReviewed: Target04,
  coverage: PieChart01,
  duplications: Copy01,
}

function MetricCardsSection({
  projectKey,
  lens,
  metrics,
  failedConditions = [],
}: {
  projectKey: string
  lens: CodeLens
  metrics: ProjectOverviewLens
  failedConditions?: ProjectOverviewGateCondition[]
}) {
  const cards = metricCardsForLens(metrics)
  return (
    <section aria-labelledby="overview-metrics-heading">
      <h2 id="overview-metrics-heading" className="sr-only">Quality metrics</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {cards.map((card) => {
          const detailTarget = overviewDetailTarget(projectKey, lens, card)
          const metric = card.metric
          const available = metric.availability === 'available'
          const value = card.kind === 'rating'
            ? available ? card.metric.grade : '—'
            : available && card.metric.value !== null ? formatOverviewPercentage(card.metric.value) : '—'
          const reason = !available && metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null
          const colorClass = getMetricColor(card)
          const Icon = domainIcons[card.key] || BarChart01

          // Match failed condition if any
          const matchingCondition = failedConditions.find((c) => {
            if (card.key === 'security') return c.metric === 'security_rating' || c.metric === 'new_critical' || c.metric === 'total_critical' || c.metric === 'new_vulnerability'
            if (card.key === 'reliability') return c.metric === 'reliability_rating' || c.metric === 'new_high'
            if (card.key === 'maintainability') return c.metric === 'maintainability_rating' || c.metric === 'new_medium'
            if (card.key === 'coverage') return c.metric === 'coverage'
            if (card.key === 'duplications') return c.metric === 'duplication_density'
            return false
          })

          const helperText = card.kind === 'rating' && available
            ? `Grade ${card.metric.grade} · ${card.metric.grade === 'A' ? 'Clean standard' : card.metric.grade === 'B' ? 'Good standing' : card.metric.grade === 'C' ? 'Moderate risk' : 'High risk'}`
            : card.key === 'securityHotspotsReviewed' && available
            ? 'Hotspot review progress'
            : card.key === 'duplications' && available
            ? 'Code duplication density'
            : card.key === 'coverage' && available
            ? `Line coverage on ${lens === 'overall' ? 'overall code' : 'new code'}`
            : reason

          const content = (
            <div className="group/card flex h-full flex-col justify-between rounded-xl border border-secondary bg-primary p-5 shadow-xs transition-all hover:shadow-md hover:border-brand/40">
              {/* Header of card: Label on left, Icon on right */}
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                  {card.label}
                </span>
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary/50 text-secondary transition-colors group-hover/card:bg-brand-primary/10 group-hover/card:border-brand/30 group-hover/card:text-brand-secondary">
                  <Icon className="size-4" aria-hidden="true" />
                </span>
              </div>

              {/* Center value + Target requirement badge */}
              <div className="my-3 flex flex-wrap items-baseline gap-2.5">
                <span className={cn('text-4xl font-extrabold font-mono tabular-nums tracking-tight', colorClass)}>
                  {value}
                </span>
                {card.kind === 'rating' && available && (
                  <span className={cn('text-xs font-semibold px-2 py-0.5 rounded-md border', gradePillStyle(card.metric.grade))}>
                    Rating {card.metric.grade}
                  </span>
                )}
                {matchingCondition && (
                  <span className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[10px] font-bold bg-error-primary/10 text-error-primary border border-error/25">
                    Target: {matchingCondition.operator} {formatGateEvidenceValue(matchingCondition.metric, matchingCondition.threshold)}
                  </span>
                )}
              </div>

              {/* Bottom description / reason & Action link */}
              <div className="border-t border-secondary/60 pt-3 flex items-center justify-between text-xs">
                <span className={cn('truncate text-xs', reason ? 'text-quaternary' : 'text-tertiary')}>
                  {helperText}
                </span>
                {detailTarget && (
                  <span className="inline-flex items-center gap-1 font-semibold text-brand-secondary group-hover/card:text-brand-solid transition-colors shrink-0 ml-2">
                    View <ArrowRight className="size-3.5 transition-transform group-hover/card:translate-x-0.5" aria-hidden="true" />
                  </span>
                )}
              </div>
            </div>
          )

          if (detailTarget) {
            return (
              <Link
                key={card.key}
                to={detailTarget.to}
                aria-label={detailTarget.label}
                className="group block rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
              >
                {content}
              </Link>
            )
          }

          return (
            <div key={card.key} className="rounded-xl">
              {content}
            </div>
          )
        })}
      </div>
    </section>
  )
}
