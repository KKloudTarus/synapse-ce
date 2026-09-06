import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  ChevronDown,
  GitBranch01,
  GitCommit,
  HelpCircle,
  InfoCircle,
} from '@untitledui/icons'
import { useState } from 'react'
import type { ProjectAnalysis } from '../../lib/types'
import { Button, Card, EmptyState, Pill, Select, cn } from '../ui'
import { GateEvidence, GateStatus, gradeNumber, metricLabel } from './qualityPresentation'

type Mode = 'overall' | 'new'
type MetricKey =
  | 'issues'
  | 'security'
  | 'reliability'
  | 'maintainability'
  | 'duplication'
  | 'coverage'
  | 'critical'
  | 'high'

type Props = {
  analyses: ProjectAnalysis[]
  hasOlder?: boolean
  loadingOlder?: boolean
  onLoadOlder?: () => void
}

const overallMetrics: { value: MetricKey; label: string }[] = [
  { value: 'issues', label: 'Total issues' },
  { value: 'security', label: 'Security rating' },
  { value: 'reliability', label: 'Reliability rating' },
  { value: 'maintainability', label: 'Maintainability rating' },
  { value: 'duplication', label: 'Duplication density' },
  { value: 'coverage', label: 'Line coverage' },
]

const newMetrics: { value: MetricKey; label: string }[] = [
  { value: 'issues', label: 'New issues' },
  { value: 'critical', label: 'New critical' },
  { value: 'high', label: 'New high' },
  { value: 'security', label: 'New Code security rating' },
  { value: 'reliability', label: 'New Code reliability rating' },
]

export function ProjectActivityView({
  analyses,
  hasOlder = false,
  loadingOlder = false,
  onLoadOlder,
}: Props) {
  const [mode, setMode] = useState<Mode>('overall')
  const [metric, setMetric] = useState<MetricKey>('issues')
  const [expanded, setExpanded] = useState<string | null>(analyses[0]?.id ?? null)

  if (analyses.length === 0) {
    return (
      <Card title="Activity">
        <EmptyState
          icon={Activity}
          title="No analysis history yet"
          hint="Each successful analysis will appear here as an immutable decision record."
        />
      </Card>
    )
  }

  const options = mode === 'overall' ? overallMetrics : newMetrics
  const chronological = [...analyses].reverse()
  const points = chronological
    .map((analysis) => pointOf(analysis, mode, metric))
    .filter((point): point is TrendPoint => point !== null)

  const latestPoint = pointOf(analyses[0], mode, metric)
  const previousPoint = pointOf(analyses[1], mode, metric)
  const direction =
    latestPoint && previousPoint ? trendDirection(latestPoint.value, previousPoint.value, metric) : null

  function changeMode(next: Mode) {
    setMode(next)
    setMetric('issues')
  }

  return (
    <section className="space-y-5" aria-label="Project activity">
      {/* Quality Trend Section */}
      <Card
        title="Quality trend"
        actions={
          <div className="flex flex-wrap items-center gap-2.5">
            {direction && <DirectionBadge direction={direction} />}
            <div className="w-44">
              <Select
                value={metric}
                onValueChange={(value) => setMetric(value as MetricKey)}
                ariaLabel="Trend metric"
                options={options}
              />
            </div>
            <div
              className="flex items-center gap-1 rounded-lg border border-secondary bg-secondary p-0.5"
              aria-label="Activity scope"
            >
              <ScopeButton active={mode === 'overall'} onClick={() => changeMode('overall')}>
                Overall
              </ScopeButton>
              <ScopeButton active={mode === 'new'} onClick={() => changeMode('new')}>
                New Code
              </ScopeButton>
            </div>
          </div>
        }
        bodyClass="p-0"
      >
        {mode === 'overall' && metric !== 'coverage' && !analyses.some((analysis) => analysis.coverage) && (
          <span className="sr-only">
            Line coverage is unavailable because no coverage artifact was supplied.
          </span>
        )}

        {metric === 'coverage' && points.length === 0 ? (
          <div className="m-4 flex items-center gap-2.5 rounded-lg border border-dashed border-secondary bg-secondary px-4 py-4 text-xs text-tertiary">
            <InfoCircle className="size-4 shrink-0 text-fg-tertiary" aria-hidden="true" />
            <span>Line coverage is unavailable because no coverage artifact was supplied.</span>
          </div>
        ) : ['security', 'reliability', 'maintainability'].includes(metric) && points.length === 0 ? (
          <div className="m-4 flex items-center gap-2.5 rounded-lg border border-dashed border-secondary bg-secondary px-4 py-4 text-xs text-tertiary">
            <InfoCircle className="size-4 shrink-0 text-fg-tertiary" aria-hidden="true" />
            <span>Rating is unavailable because the analysis did not provide a grade.</span>
          </div>
        ) : (
          <Trend metric={metric} points={points} />
        )}
      </Card>

      {/* Analysis Timeline Section */}
      <Card
        title="Analysis timeline"
        actions={
          <Pill className="border border-secondary bg-secondary text-secondary font-medium text-xs">
            {analyses.length} loaded
          </Pill>
        }
        bodyClass="p-3.5"
      >
        <ol className="space-y-2.5">
          {analyses.map((analysis, index) => {
            const open = expanded === analysis.id
            const first = index === analyses.length - 1 && !hasOlder
            const isPassed = analysis.gate.passed

            return (
              <li
                key={analysis.id}
                className={cn(
                  'overflow-hidden rounded-xl border transition-all shadow-2xs',
                  isPassed
                    ? 'border-utility-green-300 bg-success-primary'
                    : 'border-error bg-error-primary',
                )}
              >
                <button
                  type="button"
                  className={cn(
                    'flex w-full flex-wrap items-center justify-between gap-3.5 px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-solid',
                    isPassed ? 'hover:bg-success-secondary' : 'hover:bg-error-secondary',
                  )}
                  aria-expanded={open}
                  onClick={() => setExpanded(open ? null : analysis.id)}
                >
                  <div className="flex min-w-0 items-start gap-3">
                    <span
                      className={cn(
                        'mt-0.5 inline-flex size-8 shrink-0 items-center justify-center rounded-lg border shadow-2xs',
                        isPassed
                          ? 'border-utility-green-400 bg-primary text-fg-success-primary'
                          : 'border-error bg-primary text-fg-error-primary',
                      )}
                    >
                      <GitCommit className="size-4.5" aria-hidden="true" />
                    </span>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2 font-semibold text-primary text-sm">
                        <span>{formatDate(analysis.createdAt)}</span>
                        {first && (
                          <span className="rounded-md border border-secondary bg-primary px-2 py-0.5 text-[11px] font-medium text-tertiary">
                            first analysis
                          </span>
                        )}
                        {analysis.origin === 'ci' && (
                          <span
                            className="rounded-md border border-secondary bg-primary px-2 py-0.5 text-[11px] font-medium text-secondary"
                            title={
                              analysis.ci
                                ? `Recorded by ${analysis.ci.provider || 'a pipeline'}${analysis.ci.actor ? ` for ${analysis.ci.actor}` : ''}. Branch and commit are the pipeline's own account.`
                                : 'Recorded by a pipeline through synapse-cli.'
                            }
                          >
                            from CI{analysis.ci?.provider ? ` · ${analysis.ci.provider}` : ''}
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 font-mono text-xs text-tertiary">
                        <span className="inline-flex items-center gap-1 font-medium text-secondary">
                          <GitBranch01 className="size-3 text-fg-tertiary" aria-hidden="true" />
                          {analysis.sourceRef || 'source ref unavailable'}
                        </span>
                        {analysis.sourceCommit && (
                          <span className="rounded border border-secondary bg-primary px-1.5 py-0.2 text-[11px] font-bold text-primary">
                            {analysis.sourceCommit.slice(0, 12)}
                          </span>
                        )}
                        {analysis.ci?.runUrl && (
                          <a
                            href={analysis.ci.runUrl}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="underline decoration-dotted underline-offset-2 hover:text-primary"
                            onClick={(event) => event.stopPropagation()}
                          >
                            pipeline run{analysis.ci.runId ? ` #${analysis.ci.runId}` : ''}
                          </a>
                        )}
                        <span>· {analysis.gateInfo.name || 'Quality gate'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2.5">
                    <GateStatus passed={analysis.gate.passed} />
                    <ChevronDown
                      className={cn(
                        'size-4 text-tertiary transition-transform duration-200',
                        open && 'rotate-180',
                      )}
                      aria-hidden="true"
                    />
                  </div>
                </button>

                {open && (
                  <div className="border-t border-secondary bg-primary p-4">
                    <div className="grid gap-4 xl:grid-cols-[1.15fr_1fr]">
                      <GateEvidence compact gate={analysis.gate} info={analysis.gateInfo} />
                      <div className="rounded-xl border border-secondary bg-secondary p-3.5 shadow-xs">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold uppercase tracking-wider text-secondary">
                            Changes in this analysis
                          </h3>
                          {analysis.delta ? (
                            <span
                              className="text-tertiary hover:text-primary cursor-help"
                              title={`Signed changes are compared with analysis ${analysis.newCode.previousId.slice(0, 12)}.`}
                            >
                              <HelpCircle className="size-3.5 text-fg-tertiary" aria-hidden="true" />
                              <span className="sr-only">
                                Signed changes are compared with analysis {analysis.newCode.previousId.slice(0, 12)}.
                              </span>
                            </span>
                          ) : (
                            <span
                              className="text-tertiary hover:text-primary cursor-help"
                              title="Baseline analysis: no previous successful result exists, so no delta is shown."
                            >
                              <HelpCircle className="size-3.5 text-fg-tertiary" aria-hidden="true" />
                              <span className="sr-only">
                                Baseline analysis: no previous successful result exists, so no delta is shown.
                              </span>
                            </span>
                          )}
                        </div>

                        <div className="mt-2.5 grid grid-cols-2 gap-2.5">
                          <AuditMetric
                            label="Total issues"
                            value={analysis.issues.total}
                            delta={analysis.delta?.issues.total}
                          />
                          <AuditMetric
                            label="New issues"
                            value={analysis.newCode.counts.total}
                          />
                          <AuditMetric
                            label="New critical"
                            value={analysis.newCode.counts.bySeverity.critical ?? 0}
                          />
                          <AuditMetric
                            label="New high"
                            value={analysis.newCode.counts.bySeverity.high ?? 0}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </li>
            )
          })}
        </ol>

        {hasOlder && onLoadOlder && (
          <div className="mt-3 border-t border-secondary pt-3 text-center">
            <Button
              variant="secondary"
              loading={loadingOlder}
              disabled={loadingOlder}
              onClick={onLoadOlder}
            >
              Load older analyses
            </Button>
          </div>
        )}
      </Card>
    </section>
  )
}

type TrendPoint = { id: string; label: string; commit: string; value: number; display: string }

function pointOf(analysis: ProjectAnalysis | undefined, mode: Mode, metric: MetricKey): TrendPoint | null {
  if (!analysis) return null
  const rating = mode === 'overall' ? analysis.rating : analysis.newCode.rating
  let value: number
  let display: string

  switch (metric) {
    case 'issues':
      value = mode === 'overall' ? analysis.issues.total : analysis.newCode.counts.total
      display = value.toLocaleString()
      break
    case 'critical':
      value = analysis.newCode.counts.bySeverity.critical ?? 0
      display = value.toLocaleString()
      break
    case 'high':
      value = analysis.newCode.counts.bySeverity.high ?? 0
      display = value.toLocaleString()
      break
    case 'security': {
      const grade = gradeNumber(rating.security)
      if (grade === undefined) return null
      value = grade
      display = rating.security
      break
    }
    case 'reliability': {
      const grade = gradeNumber(rating.reliability)
      if (grade === undefined) return null
      value = grade
      display = rating.reliability
      break
    }
    case 'maintainability': {
      const maintainability =
        mode === 'new' ? analysis.newCode.rating.maintainability : analysis.rating.maintainability
      if (!maintainability) return null
      const grade = gradeNumber(maintainability)
      if (grade === undefined) return null
      value = grade
      display = maintainability
      break
    }
    case 'duplication':
      if (!analysis.duplication) return null
      value = analysis.duplication.totalLines
        ? (100 * analysis.duplication.duplicatedLines) / analysis.duplication.totalLines
        : 0
      display = `${value.toFixed(1)}%`
      break
    case 'coverage':
      if (!analysis.coverage) return null
      value = analysis.coverage.totalLines
        ? (100 * analysis.coverage.coveredLines) / analysis.coverage.totalLines
        : 0
      display = `${value.toFixed(1)}%`
      break
  }
  return {
    id: analysis.id,
    label: formatDate(analysis.createdAt),
    commit: analysis.sourceCommit.slice(0, 12),
    value,
    display,
  }
}

function Trend({ metric, points }: { metric: MetricKey; points: TrendPoint[] }) {
  const width = 760
  const height = 150
  const padLeft = 48
  const padRight = 32
  const padTop = 28
  const baselineY = height - 38
  const plotWidth = width - padLeft - padRight
  const plotHeight = baselineY - padTop

  const grade = ['security', 'reliability', 'maintainability'].includes(metric)
  const values = points.map((point) => point.value)

  let min = 0
  let max = 10
  if (grade) {
    min = 1
    max = 5
  } else if (metric === 'coverage' || metric === 'duplication') {
    min = 0
    max = 100
  } else {
    const dataMax = Math.max(...values, 0)
    min = 0
    max = dataMax === 0 ? 10 : Math.ceil(dataMax * 1.25)
  }

  const range = Math.max(1, max - min)

  const coords = points.map((point, index) => {
    const x = points.length === 1 ? padLeft + plotWidth / 2 : padLeft + (index * plotWidth) / (points.length - 1)
    const y = grade
      ? padTop + ((point.value - 1) / 4) * plotHeight
      : padTop + plotHeight - ((point.value - min) / range) * plotHeight
    return { x, y }
  })

  const title = grade
    ? `${metricLabel(`${metric}_rating`)} (A is best)`
    : metricLabel(metric === 'duplication' ? 'duplication_density' : metric === 'coverage' ? 'coverage' : metric)

  // Polyline path connecting heads
  const linePath = coords.map((c, i) => `${i === 0 ? 'M' : 'L'} ${c.x} ${c.y}`).join(' ')
  const areaPath =
    coords.length > 1
      ? `${linePath} L ${coords[coords.length - 1].x} ${baselineY} L ${coords[0].x} ${baselineY} Z`
      : ''

  // Tick labels
  const yTicks = grade
    ? [
        { label: 'A', y: padTop },
        { label: 'C', y: padTop + plotHeight / 2 },
        { label: 'E', y: baselineY },
      ]
    : [
        { label: formatTick(max, metric), y: padTop },
        { label: formatTick((max + min) / 2, metric), y: padTop + plotHeight / 2 },
        { label: formatTick(min, metric), y: baselineY },
      ]

  return (
    <div>
      {/* Seamless Chart Canvas */}
      <div className="relative px-4 pt-3 pb-1">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`${title} trend`}
          className="h-44 w-full overflow-visible"
        >
          <title>{title} trend</title>

          <defs>
            <linearGradient id="githubTrackGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-utility-blue-600)" stopOpacity="0.25" />
              <stop offset="100%" stopColor="var(--color-utility-blue-600)" stopOpacity="0.02" />
            </linearGradient>
          </defs>

          {/* Background horizontal guide lines */}
          {yTicks.map((tick, idx) => (
            <g key={idx}>
              <line
                x1={padLeft}
                y1={tick.y}
                x2={width - padRight}
                y2={tick.y}
                stroke="currentColor"
                strokeDasharray="4 4"
                className="text-secondary"
                strokeWidth="1"
              />
              <text
                x={padLeft - 10}
                y={tick.y + 3.5}
                textAnchor="end"
                className="fill-secondary font-mono font-bold text-[10px]"
              >
                {tick.label}
              </text>
            </g>
          ))}

          {/* Horizontal Timeline Rail */}
          <line
            x1={padLeft - 10}
            y1={baselineY}
            x2={width - padRight + 10}
            y2={baselineY}
            stroke="currentColor"
            className="text-secondary"
            strokeWidth="2"
            strokeLinecap="round"
          />

          {/* Stem Lines from Baseline up to each Node */}
          {coords.map((coord, idx) => (
            <g key={`stem-${points[idx].id}`}>
              <line
                x1={coord.x}
                y1={baselineY}
                x2={coord.x}
                y2={coord.y}
                stroke="var(--color-utility-blue-600)"
                strokeDasharray="3 3"
                strokeWidth="1.5"
              />
              {/* Baseline anchor node */}
              <circle
                cx={coord.x}
                cy={baselineY}
                r="3.5"
                fill="var(--color-utility-blue-600)"
              />
            </g>
          ))}

          {/* Shaded Area Fill */}
          {areaPath && <path d={areaPath} fill="url(#githubTrackGrad)" />}

          {/* Connecting Rail Line */}
          {coords.length > 1 && (
            <polyline
              fill="none"
              stroke="var(--color-utility-blue-600)"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              points={coords.map((point) => `${point.x},${point.y}`).join(' ')}
            />
          )}

          {/* X-Axis Date & Commit Ticks below baseline */}
          {coords.map((coord, index) => (
            <g key={`xtick-${points[index].id}`}>
              <text
                x={coord.x}
                y={baselineY + 14}
                textAnchor="middle"
                className="fill-primary font-bold font-mono text-[11px]"
              >
                {shortDate(points[index].label)}
              </text>
              {points[index].commit && (
                <text
                  x={coord.x}
                  y={baselineY + 26}
                  textAnchor="middle"
                  className="fill-tertiary font-mono text-[9.5px] font-medium"
                >
                  {points[index].commit}
                </text>
              )}
            </g>
          ))}

          {/* GitHub Milestone Nodes ("Con ruồi") with High-Contrast Value Badges */}
          {coords.map((coord, index) => {
            const p = points[index]
            return (
              <g key={p.id} className="cursor-pointer">
                {/* Outer Glow Halo */}
                <circle
                  cx={coord.x}
                  cy={coord.y}
                  r="8"
                  fill="var(--color-utility-blue-50)"
                  stroke="var(--color-utility-blue-600)"
                  strokeWidth="2.5"
                />

                {/* Inner Core */}
                <circle
                  cx={coord.x}
                  cy={coord.y}
                  r="3.5"
                  fill="var(--color-utility-blue-600)"
                >
                  <title>
                    {p.label}: {p.display}
                    {p.commit ? ` · ${p.commit}` : ''}
                  </title>
                </circle>

                {/* Top Callout Value Badge */}
                <g transform={`translate(${coord.x}, ${coord.y - 16})`}>
                  <rect
                    x="-24"
                    y="-11"
                    width="48"
                    height="18"
                    rx="4"
                    fill="var(--color-utility-blue-600)"
                    stroke="var(--color-utility-blue-700)"
                    strokeWidth="1"
                  />
                  <polygon
                    points="0,-1 -3,-4 3,-4"
                    fill="var(--color-utility-blue-600)"
                  />
                  <text
                    x="0"
                    y="-2"
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill="var(--color-text-white)"
                    className="font-mono font-bold text-[10px]"
                  >
                    {p.display}
                  </text>
                </g>
              </g>
            )
          })}
        </svg>
      </div>

      {/* Seamless History Data Table Strip */}
      <div className="border-t border-secondary">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-secondary bg-secondary text-secondary">
              <th className="px-4 py-2 font-bold">Analysis</th>
              {points.map((point) => (
                <th key={point.id} className="px-4 py-2 text-right font-semibold">
                  {shortDate(point.label)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <th className="px-4 py-2 font-semibold text-tertiary">{title}</th>
              {points.map((point) => (
                <td
                  key={point.id}
                  className="px-4 py-2 text-right font-mono font-bold tabular-nums text-primary"
                >
                  {point.display}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}

function formatTick(value: number, metric: MetricKey) {
  if (metric === 'coverage' || metric === 'duplication') {
    return `${Math.round(value)}%`
  }
  if (value >= 1000) {
    return `${(value / 1000).toFixed(1)}k`
  }
  return Math.round(value).toString()
}

type Direction = 'improving' | 'regressing' | 'unchanged'

function trendDirection(current: number, previous: number, metric: MetricKey): Direction {
  if (current === previous) return 'unchanged'
  const lowerIsBetter = metric !== 'coverage'
  return (lowerIsBetter ? current < previous : current > previous) ? 'improving' : 'regressing'
}

function DirectionBadge({ direction }: { direction: Direction }) {
  const meta =
    direction === 'improving'
      ? {
          icon: ArrowDownRight,
          label: 'Improving',
          cls: 'text-success-primary bg-success-primary border border-utility-green-300',
        }
      : direction === 'regressing'
        ? {
            icon: ArrowUpRight,
            label: 'Regressing',
            cls: 'text-error-primary bg-error-primary border border-error',
          }
        : {
            icon: ArrowRight,
            label: 'Unchanged',
            cls: 'text-tertiary bg-secondary border border-secondary',
          }

  const Icon = meta.icon
  return (
    <Pill className={cn('gap-1.5 font-bold text-xs px-2.5 py-0.5', meta.cls)}>
      <Icon className="size-3.5" aria-hidden="true" />
      {meta.label}
    </Pill>
  )
}

function ScopeButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'rounded-md px-2.5 py-1 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
        active
          ? 'bg-primary text-brand-secondary shadow-xs'
          : 'text-tertiary hover:bg-primary_hover hover:text-primary',
      )}
    >
      {children}
    </button>
  )
}

function AuditMetric({ label, value, delta }: { label: string; value: number; delta?: number }) {
  return (
    <div className="rounded-lg border border-secondary bg-primary p-2.5 shadow-2xs">
      <div className="text-xs font-semibold text-secondary">{label}</div>
      <div className="mt-0.5 font-mono text-lg font-bold tabular-nums text-primary">
        {value.toLocaleString()}
      </div>
      {delta !== undefined && (
        <div
          className={cn(
            'mt-0.5 font-mono text-[10px] font-semibold tabular-nums',
            delta > 0
              ? 'text-error-primary'
              : delta < 0
                ? 'text-success-primary'
                : 'text-tertiary',
          )}
        >
          {delta > 0 ? `+${delta}` : delta} vs previous
        </div>
      )}
    </div>
  )
}

function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function shortDate(formatted: string) {
  return formatted.split(',')[0]
}
