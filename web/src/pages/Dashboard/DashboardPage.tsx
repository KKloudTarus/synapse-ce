import type { FC } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  HelpCircle,
  Package,
  Shield01,
  Signal01,
} from '@untitledui/icons'
import { ErrorState, Spinner } from '../../components/ui'
import { Tooltip, TooltipTrigger } from '../../components/base/tooltip/tooltip'
import {
  DonutChart,
  FindingsTrendChart,
  RadarChart,
  type ChartDatum,
} from '../../components/synapse/DashboardCharts'
import { useDashboardData } from './hooks/useDashboardData'
import { StatCard } from './components/StatCard'
import { ChartCard } from './components/ChartCard'
import { PriorityAssetsTable } from './components/PriorityAssetsTable'
import { AssessmentActivityTable } from './components/AssessmentActivityTable'
import { cx } from '@/utils/cx'

export const DashboardPage: FC = () => {
  const {
    data,
    error,
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

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      {/* Header Section */}
      <header className="flex items-end justify-between gap-4 pb-2">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            Security Operations
          </h1>
        </div>
      </header>

      {/* KPI Stat Cards Row */}
      <section aria-label="Security operations summary" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          icon={Package}
          label="Total Assets"
          value={data.assetTotal}
          tone="info"
        />
        <StatCard
          icon={Shield01}
          label="High-risk Assets"
          value={highRiskAssets}
          tone={highRiskAssets ? 'critical' : 'accent'}
        />
        <StatCard
          icon={Activity}
          label="Active Engagements"
          value={activeEngagements}
          tone="brand"
        />
        <StatCard
          icon={Signal01}
          label="Coverage Gaps"
          value={fleetDisabled ? 'Fleet disabled' : (coverageGaps ?? 'N/A')}
          hint={fleetDisabled ? 'Set SYNAPSE_FLEET_ENABLED=true to measure agent coverage.' : undefined}
          valueClassName={fleetDisabled ? 'text-lg sm:text-xl' : undefined}
          tone={fleetDisabled ? 'muted' : coverageGaps ? 'high' : 'accent'}
        />
      </section>

      {/* Telemetry / Hero Chart Section + Activity Feed */}
      {analyticsError && <ErrorState message={analyticsError} />}
      {!analytics && !analyticsError && <Spinner label="Loading operations analytics…" className="min-h-64" />}

      {analytics && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <ChartCard
            title="Findings Over Time"
            description="New publishable findings grouped by UTC day and severity."
            tooltip={
              analytics.findingsWithoutTimestamp > 0 ? (
                <Tooltip
                  title="Excluded findings"
                  description={`${analytics.findingsWithoutTimestamp} finding${analytics.findingsWithoutTimestamp === 1 ? '' : 's'} excluded from the trend because no creation timestamp is available.`}
                  arrow
                >
                  <TooltipTrigger aria-label="Excluded findings info">
                    <HelpCircle className="size-4 text-fg-quaternary hover:text-fg-secondary cursor-help" />
                  </TooltipTrigger>
                </Tooltip>
              ) : undefined
            }
            action={<RangeSelector value={rangeDays} onChange={setRangeDays} />}
            className="lg:col-span-3"
          >
            <FindingsTrendChart points={analytics.findingsOverTime} series={severityChart({}, false)} />
          </ChartCard>

          {/* Activity Feed — right panel */}
          <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs lg:col-span-1">
            <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4">
              <h3 className="text-sm font-semibold text-primary">Assessment Activity</h3>
              <LinkArrow to="/engagements" label="View All" />
            </header>
            <div className="flex-1">
              <AssessmentActivityTable engagements={assessmentQueue} assetNames={assetNames} />
            </div>
          </section>
        </div>
      )}

      {/* Posture + Finding Risk + Priority — matching Findings/Activity row proportions */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:col-span-3">
          {analytics && (
            <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
              <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4">
                <h3 className="text-sm font-semibold text-primary">Asset Security Posture</h3>
              </header>
              <div className="flex flex-1 items-center justify-center p-5">
                <RadarChart title="Asset Security Posture" data={postureChart(analytics.assetPosture)} />
              </div>
            </section>
          )}

          {analytics && (
            <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
              <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4">
                <div className="flex items-center gap-1.5">
                  <h3 className="text-sm font-semibold text-primary">Active Finding Risk Mix</h3>
                  {!analytics.externalFindingsIncluded && (
                    <Tooltip
                      title="Scope Note"
                      description="Third-party findings are not included."
                      arrow
                    >
                      <TooltipTrigger aria-label="Third-party findings note">
                        <HelpCircle className="size-4 text-fg-quaternary hover:text-fg-secondary cursor-help" />
                      </TooltipTrigger>
                    </Tooltip>
                  )}
                </div>
              </header>
              <div className="flex flex-1 items-center justify-center p-5">
                <DonutChart
                  title="Active Finding Risk Mix"
                  centerLabel="Active"
                  data={severityChart(analytics.activeFindingsBySeverity, true)}
                />
              </div>
            </section>
          )}
        </div>

        <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs lg:col-span-1">
          <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4">
            <h3 className="text-sm font-semibold text-primary">Priority Assets</h3>
            <LinkArrow to="/assets" label="View All" />
          </header>
          <div className="flex-1">
            <PriorityAssetsTable assets={priorityAssets} hasTotalAssets={data.assets.length > 0} />
          </div>
        </section>
      </div>
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

function postureChart(counts: Record<string, number>): ChartDatum[] {
  return [
    chartItem('critical', 'Critical', counts, 'var(--color-utility-red-500)'),
    chartItem('high_risk', 'High Risk', counts, 'var(--color-utility-orange-500)'),
    chartItem('attention', 'Attention', counts, 'var(--color-utility-yellow-500)'),
    chartItem('unknown', 'Unknown', counts, 'var(--color-utility-neutral-400)'),
    chartItem('good', 'Good', counts, 'var(--color-utility-green-500)'),
  ]
}

function severityChart(counts: Record<string, number>, includeUnknown: boolean): ChartDatum[] {
  const rows = [
    chartItem('critical', 'Critical', counts, 'var(--color-utility-red-500)'),
    chartItem('high', 'High', counts, 'var(--color-utility-orange-500)'),
    chartItem('medium', 'Medium', counts, 'var(--color-utility-yellow-500)'),
    chartItem('low', 'Low', counts, 'var(--color-utility-blue-500)'),
  ]
  if (includeUnknown) {
    rows.push(
      chartItem('info', 'Info', counts, 'var(--color-utility-indigo-500)'),
      chartItem('unknown', 'Unknown', counts, 'var(--color-utility-neutral-400)'),
    )
  }
  return rows
}

function chartItem(key: string, label: string, counts: Record<string, number>, color: string): ChartDatum {
  return { key, label, value: counts[key] ?? 0, color }
}
