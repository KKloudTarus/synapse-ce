import { AlertTriangle, BarChart01, CheckCircle, ShieldTick, XCircle } from '@untitledui/icons'
import { useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ProjectOverviewSkeleton } from '../../components/codequality/projectOverview/ProjectOverviewSkeleton'
import { Button, Card, EmptyState, ErrorState, Pill, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type {
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
        <div className="flex items-center gap-1 rounded-lg bg-secondary p-1">
          <button
            type="button"
            className={cn('rounded-md px-3 py-1.5 text-xs font-semibold transition-colors', lens === 'overall' ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary')}
            aria-pressed={lens === 'overall'}
            onClick={() => setLens('overall')}
          >
            Overall Code
          </button>
          <button
            type="button"
            className={cn('rounded-md px-3 py-1.5 text-xs font-semibold transition-colors', lens === 'new-code' ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary')}
            aria-pressed={lens === 'new-code'}
            onClick={() => setLens('new-code')}
          >
            New Code
          </button>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span>
            <span className="font-bold tabular-nums text-primary">
              {overview.issueSummary?.newCodeTotal?.value !== null && overview.issueSummary?.newCodeTotal?.value !== undefined
                ? overview.issueSummary.newCodeTotal.value.toLocaleString()
                : '—'}
            </span>{' '}
            <span className="text-tertiary">new issues</span>
          </span>
          <span>
            <span className="font-bold tabular-nums text-primary">
              {overview.issueSummary?.acceptedOverallTotal?.value !== null && overview.issueSummary?.acceptedOverallTotal?.value !== undefined
                ? overview.issueSummary.acceptedOverallTotal.value.toLocaleString()
                : '—'}
            </span>{' '}
            <span className="text-tertiary">accepted (overall)</span>
          </span>
        </div>
      </div>

      {/* Quality metrics compact 6 cards */}
      <MetricCardsSection projectKey={projectKey} lens={lens} metrics={selectedMetrics} />
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
    <Card className={tone.card}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon className={cn('size-5', tone.text)} aria-hidden="true" />
            <h2 className={cn('text-xl font-semibold', tone.text)}>Quality Gate {tone.label}</h2>
          </div>
          <p className="mt-1 text-sm text-tertiary">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={tone.pill}>{tone.label}</Pill>
      </div>
      {incomplete && (
        <p className="mt-4 text-sm text-primary">
          Analysis was incomplete, so this quality gate cannot be used as a passing result.
        </p>
      )}
      {gate.status === 'failed' && (
        <div className="mt-4">
          <p className="text-sm font-medium text-primary">
            {gate.failedConditions.length} {gate.failedConditions.length === 1 ? 'condition' : 'conditions'} failed
          </p>
          <ol className="mt-2.5 grid gap-2">
            {gate.failedConditions.map((condition, index) => (
              <li key={`${condition.metric}-${index}`} className="rounded-lg border border-critical/25 bg-primary px-4 py-2.5 shadow-xs">
                <div className="text-sm font-medium text-primary">{gateMetricLabel(condition.metric)}</div>
                <div className="mt-0.5 font-mono text-xs tabular-nums text-tertiary">
                  {formatGateEvidenceValue(condition.metric, condition.actual)} — expected {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
      {analysis && (
        <div className="mt-3 flex flex-wrap items-center gap-2.5 border-t border-secondary pt-3 text-xs text-tertiary">
          <span>Analyzed {fullDate}</span>
          {analysis.sourceRef && (
            <>
              <span className="text-quaternary">·</span>
              <span className="font-mono">{analysis.sourceRef}</span>
            </>
          )}
          {analysis.sourceCommit && (
            <>
              <span className="text-quaternary">·</span>
              <span className="font-mono" title={analysis.sourceCommit}>{analysis.sourceCommit.slice(0, 12)}</span>
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
        return 'text-utility-green-600 dark:text-utility-green-400'
      case 'B':
        return 'text-utility-blue-600 dark:text-utility-blue-400'
      case 'C':
        return 'text-utility-orange-600 dark:text-utility-orange-400'
      case 'D':
        return 'text-utility-yellow-600 dark:text-utility-yellow-400'
      case 'E':
        return 'text-utility-red-600 dark:text-utility-red-400'
      default:
        return 'text-primary'
    }
  }
  if (card.kind === 'percentage' && card.metric.value !== null) {
    const val = card.metric.value
    if (card.key === 'duplications') {
      if (val <= 3.5) return 'text-utility-green-600 dark:text-utility-green-400'
      if (val <= 10) return 'text-utility-orange-600 dark:text-utility-orange-400'
      return 'text-utility-red-600 dark:text-utility-red-400'
    }
    if (card.key === 'coverage') {
      if (val >= 80) return 'text-utility-green-600 dark:text-utility-green-400'
      if (val >= 50) return 'text-utility-indigo-600 dark:text-utility-indigo-400'
      return 'text-utility-red-600 dark:text-utility-red-400'
    }
    if (card.key === 'securityHotspotsReviewed') {
      if (val >= 80) return 'text-utility-green-600 dark:text-utility-green-400'
      if (val >= 50) return 'text-utility-purple-600 dark:text-utility-purple-400'
      return 'text-utility-red-600 dark:text-utility-red-400'
    }
  }
  return 'text-primary'
}

function MetricCardsSection({ projectKey, lens, metrics }: { projectKey: string; lens: CodeLens; metrics: ProjectOverviewLens }) {
  const cards = metricCardsForLens(metrics)
  return (
    <section aria-labelledby="overview-metrics-heading">
      <h2 id="overview-metrics-heading" className="sr-only">Quality metrics</h2>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {cards.map((card) => {
          const detailTarget = overviewDetailTarget(projectKey, lens, card)
          const metric = card.metric
          const available = metric.availability === 'available'
          const value = card.kind === 'rating'
            ? available ? card.metric.grade : '—'
            : available && card.metric.value !== null ? formatOverviewPercentage(card.metric.value) : '—'
          const reason = !available && metric.unavailableReason ? unavailableReasonText(metric.unavailableReason) : null
          const colorClass = getMetricColor(card)

          const content = (
            <div className="flex h-full flex-col justify-between rounded-xl border border-secondary bg-primary p-4 shadow-xs transition-colors group-hover:border-primary">
              <div className={cn('text-3xl font-bold tabular-nums', colorClass)}>{value}</div>
              <div className="mt-1 text-xs font-medium text-tertiary">{card.label}</div>
              {reason && <div className="mt-1 text-xs text-quaternary">{reason}</div>}
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
