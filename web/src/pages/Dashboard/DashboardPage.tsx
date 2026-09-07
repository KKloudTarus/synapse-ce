import { useState } from 'react'
import type { FC } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, HelpCircle } from '@untitledui/icons'
import { ErrorState, Spinner } from '../../components/ui'
import { Tooltip, TooltipTrigger } from '../../components/base/tooltip/tooltip'
import { FindingsTrendChart, type ChartDatum } from '../../components/synapse/DashboardCharts'
import { useDashboardData } from './hooks/useDashboardData'
import { buildAttentionQueue, type AttentionType } from './hooks/attentionQueue'
import { Metric, MetricStrip } from '@/components/synapse/Metric'
import { ChartCard } from './components/ChartCard'
import { NeedsAttentionTable } from './components/NeedsAttentionTable'
import { PriorityAssetsTable } from './components/PriorityAssetsTable'
import { AssessmentActivityTable } from './components/AssessmentActivityTable'
import { cx } from '@/utils/cx'

type QueueFilter = 'all' | 'p1' | AttentionType

const QUEUE_FILTERS: [QueueFilter, string][] = [
  ['all', 'All'],
  ['p1', 'P1'],
  ['Scan failed', 'Scan failed'],
  ['Coverage gap', 'Coverage gaps'],
  ['Asset posture', 'Asset posture'],
  ['Not scanned', 'Not scanned'],
]

export const DashboardPage: FC = () => {
  const {
    data,
    error,
    fleet,
    analytics,
    analyticsError,
    rangeDays,
    setRangeDays,
    highRiskAssets,
    activeEngagements,
    coverageGaps,
    fleetDisabled,
    priorityAssets,
    assessmentQueue,
    assetNames,
  } = useDashboardData()

  const [queueFilter, setQueueFilter] = useState<QueueFilter>('all')

  if (error) {
    return (
      <div className="mx-auto max-w-[1600px]">
        <ErrorState message={error} />
      </div>
    )
  }

  if (!data) {
    return <Spinner label="Loading security operations…" />
  }

  const attention = buildAttentionQueue({ assets: data.assets, engagements: data.engagements, fleet, assetNames })
  const visibleAttention = queueFilter === 'all'
    ? attention
    : queueFilter === 'p1'
      ? attention.filter((item) => item.priority === 1)
      : attention.filter((item) => item.type === queueFilter)

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h1 className="text-2xl font-bold tracking-tight text-primary">Security Operations</h1>
        {analytics && (
          <span className="text-xs text-tertiary" title={analytics.generatedAt}>
            Analytics as of {new Date(analytics.generatedAt).toLocaleString()} · {data.assetTotal} {data.assetTotal === 1 ? 'asset' : 'assets'}
          </span>
        )}
      </header>

      {/* Action counters: each number is something the queue below or a linked page acts on. */}
      <MetricStrip ariaLabel="Security operations summary">
        <Metric label="Critical open" value={analytics ? analytics.activeFindingsBySeverity.critical ?? 0 : '—'} tone="critical" />
        <Metric label="High open" value={analytics ? analytics.activeFindingsBySeverity.high ?? 0 : '—'} tone="high" />
        <Metric label="High-risk assets" value={highRiskAssets} tone={highRiskAssets ? 'critical' : 'muted'} />
        <Metric label="Active engagements" value={activeEngagements} />
        <Metric
          label="Coverage gaps"
          value={fleetDisabled ? '—' : (coverageGaps ?? 'N/A')}
          hint={
            fleetDisabled
              ? 'Fleet is disabled. Set SYNAPSE_FLEET_ENABLED=true to measure agent coverage.'
              : 'Assets missing an expected fleet-agent capability (process, network, file, or privilege telemetry).'
          }
          tone={fleetDisabled ? 'muted' : coverageGaps ? 'warning' : 'muted'}
        />
        <Metric label="Needs attention" value={attention.length} tone={attention.length ? 'warning' : 'muted'} />
      </MetricStrip>

      {/* The queue is the page: what to act on. Full width so the issue and the next action are never
          clipped, with a filter row so the counters above become something an operator can act on. */}
      <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
        <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-secondary px-5 py-3">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-semibold text-primary">Needs attention</h3>
            <span className="font-mono text-xs tabular-nums text-quaternary">
              {visibleAttention.length === attention.length ? `${attention.length} ${attention.length === 1 ? 'item' : 'items'}` : `${visibleAttention.length} of ${attention.length}`}
            </span>
          </div>
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter the attention queue">
            {QUEUE_FILTERS.map(([value, label]) => {
              const n = value === 'all' ? attention.length : value === 'p1' ? attention.filter((i) => i.priority === 1).length : attention.filter((i) => i.type === value).length
              return (
                <button
                  key={value}
                  type="button"
                  aria-pressed={queueFilter === value}
                  onClick={() => setQueueFilter(value)}
                  className={cx(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-colors',
                    queueFilter === value ? 'bg-secondary text-primary ring-1 ring-inset ring-border' : 'text-tertiary hover:bg-secondary',
                  )}
                >
                  {label}<span className="ml-1 font-mono tabular-nums opacity-70">{n}</span>
                </button>
              )
            })}
          </div>
        </header>
        <div className="flex-1">
          <NeedsAttentionTable items={visibleAttention} loaded={Boolean(data)} onClear={queueFilter === 'all' ? undefined : () => setQueueFilter('all')} />
        </div>
      </section>

      {analyticsError && <ErrorState message={analyticsError} />}
      {!analytics && !analyticsError && <Spinner label="Loading operations analytics…" className="min-h-64" />}

      {analytics && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <ChartCard
            title="Findings Over Time"
            description="New publishable findings grouped by UTC day and severity."
            tooltip={
              <>
                {analytics.findingsWithoutTimestamp > 0 && (
                  <Tooltip
                    title="Excluded findings"
                    description={`${analytics.findingsWithoutTimestamp} finding${analytics.findingsWithoutTimestamp === 1 ? '' : 's'} excluded from the trend because no creation timestamp is available.`}
                    arrow
                  >
                    <TooltipTrigger aria-label="Excluded findings info">
                      <HelpCircle className="size-4 text-fg-quaternary hover:text-fg-secondary cursor-help" />
                    </TooltipTrigger>
                  </Tooltip>
                )}
                {!analytics.externalFindingsIncluded && (
                  <Tooltip title="Scope Note" description="Third-party findings are not included." arrow>
                    <TooltipTrigger aria-label="Third-party findings note">
                      <HelpCircle className="size-4 text-fg-quaternary hover:text-fg-secondary cursor-help" />
                    </TooltipTrigger>
                  </Tooltip>
                )}
              </>
            }
            action={<RangeSelector value={rangeDays} onChange={setRangeDays} />}
            className="lg:col-span-3"
          >
            <FindingsTrendChart points={analytics.findingsOverTime} series={severityChart({})} />
          </ChartCard>

          <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs lg:col-span-1">
            <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-3.5">
              <h3 className="text-sm font-semibold text-primary">Priority Assets</h3>
              <LinkArrow to="/assets" label="View All" />
            </header>
            <div className="flex-1">
              <PriorityAssetsTable assets={priorityAssets} hasTotalAssets={data.assets.length > 0} />
            </div>
          </section>
        </div>
      )}

      {/* Who is assessing what — secondary to the queue, so it sits below the trend. */}
      <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
        <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-3.5">
          <h3 className="text-sm font-semibold text-primary">Assessment Activity</h3>
          <LinkArrow to="/engagements" label="View All" />
        </header>
        <div className="flex-1">
          <AssessmentActivityTable engagements={assessmentQueue} assetNames={assetNames} />
        </div>
      </section>
    </div>
  )
}

function LinkArrow({ to, label }: { to: string; label: string }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1 text-xs font-semibold text-brand-secondary hover:text-brand-primary"
    >
      <span className="hidden sm:inline">{label}</span>
      <ArrowRight className="size-3.5" aria-hidden="true" />
    </Link>
  )
}

function RangeSelector({ value, onChange }: { value: number; onChange: (value: number) => void }) {
  return (
    <div className="flex rounded-lg border border-secondary bg-secondary p-1" aria-label="Finding trend range">
      {[7, 30, 90].map((days) => (
        <button
          key={days}
          type="button"
          onClick={() => onChange(days)}
          className={cx(
            'rounded-md px-3 py-1 text-xs font-semibold transition-colors sm:px-3.5 sm:py-1.5 sm:text-sm',
            value === days
              ? 'bg-primary text-primary shadow-xs'
              : 'text-secondary hover:text-primary hover:bg-secondary',
          )}
        >
          {days}d
        </button>
      ))}
    </div>
  )
}

function severityChart(counts: Record<string, number>): ChartDatum[] {
  return [
    chartItem('critical', 'Critical', counts, 'var(--color-utility-red-500)'),
    chartItem('high', 'High', counts, 'var(--color-utility-orange-500)'),
    chartItem('medium', 'Medium', counts, 'var(--color-utility-yellow-500)'),
    chartItem('low', 'Low', counts, 'var(--color-utility-blue-500)'),
  ]
}

function chartItem(key: string, label: string, counts: Record<string, number>, color: string): ChartDatum {
  return { key, label, value: counts[key] ?? 0, color }
}
