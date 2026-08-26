import {
  AlertCircle,
  AlertTriangle,
  BarChart01,
  CheckCircle,
  Copy01,
  FileCode01,
  GitBranch01,
  HelpCircle,
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
  ProjectOverviewGateCondition,
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
          hint={isRunning ? 'The Overview will appear after the first successful analysis completes.' : 'Run an analysis to see the Quality Gate verdict and code quality metrics.'}
          action={!isRunning && <Button variant="brand" onClick={startAnalysis}>Run first analysis</Button>}
        />
      </Card>
    )
  }

  const selectedMetrics = lens === 'overall' ? overview.lenses.overall : overview.lenses.newCode
  const failedConditions = overview.gate?.status === 'failed' ? overview.gate.failedConditions : []
  const failedCount = failedConditions.length

  return (
    <div className="space-y-5">
      {isRunning && (
        <Card>
          <p className="text-sm text-tertiary">A new analysis is in progress. Values below are from the latest completed analysis.</p>
        </Card>
      )}
      {overview.gate && <QualityGateCard gate={overview.gate} analysis={overview.latestAnalysis} />}

      {/* Overview lens toggle + inline issue stats */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-secondary bg-primary px-4 py-2.5 shadow-xs">
        <div role="group" aria-label="Overview lens" className="flex items-center gap-1 rounded-lg bg-secondary p-0.5">
          <button
            type="button"
            className={cn(
              'rounded-md px-3 py-1.5 text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
              lens === 'overall'
                ? 'bg-primary text-brand-secondary shadow-xs'
                : 'text-tertiary hover:bg-primary_hover hover:text-primary',
            )}
            aria-pressed={lens === 'overall'}
            onClick={() => setLens('overall')}
          >
            Overall Code
          </button>
          <button
            type="button"
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
              lens === 'new-code'
                ? 'bg-primary text-brand-secondary shadow-xs'
                : 'text-tertiary hover:bg-primary_hover hover:text-primary',
            )}
            aria-pressed={lens === 'new-code'}
            onClick={() => setLens('new-code')}
          >
            <span>New Code</span>
            {failedCount > 0 && (
              <span className="inline-flex items-center rounded-full border border-error bg-error-primary px-1.5 py-0.2 font-mono text-[10px] font-bold text-error-primary">
                {failedCount} failed
              </span>
            )}
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-warning-primary bg-warning-primary px-2.5 py-1 font-semibold text-warning-primary">
            <AlertTriangle className="size-3.5 text-fg-warning-primary" aria-hidden="true" />
            <span className="font-mono font-bold tabular-nums">
              {overview.issueSummary?.newCodeTotal?.value !== null && overview.issueSummary?.newCodeTotal?.value !== undefined
                ? overview.issueSummary.newCodeTotal.value.toLocaleString()
                : '0'}
            </span>
            <span>new issues</span>
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-secondary px-2.5 py-1 font-semibold text-secondary">
            <CheckCircle className="size-3.5 text-fg-success-primary" aria-hidden="true" />
            <span className="font-mono font-bold tabular-nums">
              {overview.issueSummary?.acceptedOverallTotal?.value !== null && overview.issueSummary?.acceptedOverallTotal?.value !== undefined
                ? overview.issueSummary.acceptedOverallTotal.value.toLocaleString()
                : '0'}
            </span>
            <span>accepted (overall)</span>
          </span>
        </div>
      </div>

      {/* Quality metrics 6 cards */}
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
    ? {
        card: 'border-utility-green-300 bg-success-primary',
        text: 'text-success-primary',
        pill: 'border-utility-green-400 bg-primary text-fg-success-primary',
        label: 'Passed',
        icon: CheckCircle,
      }
    : incomplete
      ? {
          card: 'border-warning-primary bg-warning-primary',
          text: 'text-warning-primary',
          pill: 'border-warning-primary bg-primary text-fg-warning-primary',
          label: 'Incomplete',
          icon: AlertTriangle,
        }
      : {
          card: 'border-error bg-error-primary',
          text: 'text-error-primary',
          pill: 'border-error bg-primary text-fg-error-primary',
          label: 'Failed',
          icon: XCircle,
        }
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
          <p className="mt-1 text-xs font-medium text-secondary">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={cn(tone.pill, 'font-bold')}>{tone.label}</Pill>
      </div>
      {incomplete && (
        <p className="mt-4 text-sm text-primary">
          Analysis was incomplete, so this quality gate cannot be used as a passing result.
        </p>
      )}
      {gate.status === 'failed' && (
        <div className="mt-4">
          <p className="text-xs font-bold uppercase tracking-wider text-secondary">
            {gate.failedConditions.length} {gate.failedConditions.length === 1 ? 'condition' : 'conditions'} failed
          </p>
          <ol className="mt-2.5 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {gate.failedConditions.map((condition, index) => (
              <li
                key={`${condition.metric}-${index}`}
                className="flex flex-col justify-between rounded-xl border border-error bg-primary p-3 shadow-2xs transition-all hover:border-error"
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                  <AlertTriangle className="size-3.5 text-fg-error-primary shrink-0" aria-hidden="true" />
                  <span className="truncate">{gateMetricLabel(condition.metric)}</span>
                </div>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-1.5">
                  <span className="inline-flex items-center rounded-md border border-error bg-primary px-1.5 py-0.5 font-mono text-[11px] font-bold text-error-primary">
                    Actual: {formatGateEvidenceValue(condition.metric, condition.actual)}
                  </span>
                  <span className="inline-flex items-center rounded-md border border-secondary bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-secondary">
                    Target: {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                  </span>
                </div>
                {/* Screen reader and test compatibility string */}
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
              <span className="inline-flex items-center gap-1 font-mono font-medium text-secondary">
                <GitBranch01 className="size-3 text-fg-tertiary" aria-hidden="true" />
                {analysis.sourceRef}
              </span>
            </>
          )}
          {analysis.sourceCommit && (
            <>
              <span className="text-quaternary">·</span>
              <span className="font-mono font-bold text-primary" title={analysis.sourceCommit}>
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
        return 'text-utility-blue-600'
      case 'C':
        return 'text-warning-primary'
      case 'D':
        return 'text-utility-orange-600'
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
      if (val <= 10) return 'text-utility-orange-600'
      return 'text-error-primary'
    }
    if (card.key === 'coverage') {
      if (val >= 80) return 'text-success-primary'
      if (val >= 50) return 'text-utility-blue-600'
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

function getProgressBarColor(key: OverviewMetricCardModel['key'], val: number | null): string {
  if (val === null) return 'bg-secondary'
  if (key === 'duplications') {
    if (val <= 3.5) return 'bg-utility-green-600'
    if (val <= 10) return 'bg-utility-orange-600'
    return 'bg-utility-pink-600'
  }
  if (key === 'coverage') {
    if (val >= 80) return 'bg-utility-green-600'
    if (val >= 50) return 'bg-utility-blue-600'
    return 'bg-utility-orange-600'
  }
  if (key === 'securityHotspotsReviewed') {
    if (val >= 80) return 'bg-utility-green-600'
    if (val >= 50) return 'bg-brand-solid'
    return 'bg-utility-orange-600'
  }
  return 'bg-brand-solid'
}

function gradePillStyle(grade: OverviewGrade | null) {
  switch (grade) {
    case 'A':
      return 'bg-success-primary text-success-primary border-utility-green-300'
    case 'B':
      return 'bg-utility-blue-50 text-utility-blue-700 border-utility-blue-200'
    case 'C':
      return 'bg-warning-primary text-warning-primary border-warning-primary'
    case 'D':
      return 'bg-utility-orange-50 text-utility-orange-700 border-utility-orange-200'
    case 'E':
      return 'bg-error-primary text-error-primary border-error'
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
      <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 xl:grid-cols-3">
        {cards.map((card) => {
          const detailTarget = overviewDetailTarget(projectKey, lens, card)
          const metric = card.metric
          const available = metric.availability === 'available'
          const reason = !available && metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null
          const colorClass = getMetricColor(card)
          const Icon = domainIcons[card.key] || BarChart01

          // Formatted Value: If unavailable/not supplied, show 0.0% / 0 instead of '-' or em dash
          const value = card.kind === 'rating'
            ? available ? card.metric.grade : '0'
            : available && card.metric.value !== null ? formatOverviewPercentage(card.metric.value) : '0.0%'

          // Match failed condition if any
          const matchingCondition = failedConditions.find((c) => {
            if (card.key === 'security') return c.metric === 'security_rating' || c.metric === 'new_critical' || c.metric === 'total_critical' || c.metric === 'new_vulnerability'
            if (card.key === 'reliability') return c.metric === 'reliability_rating' || c.metric === 'new_high'
            if (card.key === 'maintainability') return c.metric === 'maintainability_rating' || c.metric === 'new_medium'
            if (card.key === 'coverage') return c.metric === 'coverage'
            if (card.key === 'duplications') return c.metric === 'duplication_density'
            return false
          })

          const progressPercent = card.kind === 'percentage' && available && card.metric.value !== null
            ? Math.min(100, Math.max(0, card.metric.value))
            : 0

          const content = (
            <div className="group/card flex h-full flex-col justify-between rounded-xl border border-secondary bg-primary p-4 shadow-xs transition-all hover:border-brand-solid hover:shadow-md">
              {/* Header of card: Label on left, Icon on right */}
              <div className="flex items-start justify-between gap-3">
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                    {card.label}
                  </span>
                  {available && card.kind === 'rating' && (
                    <p className="mt-0.5 text-xs text-tertiary">Grade {card.metric.grade}</p>
                  )}
                  {available && card.kind === 'percentage' && (
                    <p className="mt-0.5 text-xs text-tertiary">Measured on {lens === 'overall' ? 'Overall Code' : 'New Code'}</p>
                  )}
                  {!available && reason && (
                    <p className="mt-0.5 text-xs text-quaternary">{reason}</p>
                  )}
                </div>
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary text-secondary transition-colors group-hover/card:border-brand-solid group-hover/card:bg-brand-primary group-hover/card:text-brand-secondary">
                  <Icon className="size-4" aria-hidden="true" />
                </span>
              </div>

              {/* Center value + Target requirement badge */}
              <div className="my-2.5 flex flex-wrap items-baseline gap-2.5">
                <span className={cn('text-3xl font-bold font-mono tabular-nums tracking-tight', colorClass)}>
                  {value}
                </span>
                {card.kind === 'rating' && available && (
                  <span className={cn('text-xs font-bold px-2 py-0.5 rounded-md border', gradePillStyle(card.metric.grade))}>
                    Rating {card.metric.grade}
                  </span>
                )}
                {matchingCondition && (
                  <span className="inline-flex items-center rounded-md border border-error bg-error-primary px-1.5 py-0.5 font-mono text-[10px] font-bold text-error-primary">
                    Target: {matchingCondition.operator} {formatGateEvidenceValue(matchingCondition.metric, matchingCondition.threshold)}
                  </span>
                )}
                {!available && reason && (
                  <span className="text-tertiary hover:text-primary cursor-help" title={reason}>
                    <HelpCircle className="size-4 text-fg-tertiary" aria-hidden="true" />
                  </span>
                )}
              </div>

              {/* Progress Bar for Percentage Metrics */}
              {card.kind === 'percentage' && available && card.metric.value !== null && (
                <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                  <div
                    className={cn('h-full transition-all duration-300', getProgressBarColor(card.key, card.metric.value))}
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
              )}
            </div>
          )

          if (detailTarget) {
            return (
              <Link
                key={card.key}
                to={detailTarget.to}
                aria-label={detailTarget.label}
                className="group block rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
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
