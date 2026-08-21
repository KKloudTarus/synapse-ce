import type { FC } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  LayoutGrid01,
  Package,
  Shield01,
  Signal01,
  Target01,
} from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { ErrorState, Spinner } from '../../components/ui'
import {
  DonutChart,
  FindingsTrendChart,
  HorizontalBarChart,
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
    fleetError,
    analytics,
    analyticsError,
    rangeDays,
    setRangeDays,
    highRiskAssets,
    activeEngagements,
    unassignedEngagements,
    coverageGaps,
    priorityAssets,
    assessmentQueue,
    assetNames,
  } = useDashboardData()

  const fleetUnavailable = fleetError !== null

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
      <header className="overflow-hidden rounded-2xl border border-border bg-hero px-5 py-6 sm:px-7 sm:py-7">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <div>
            <p className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-secondary">
              <LayoutGrid01 className="size-4" aria-hidden="true" />
              Command center
            </p>
            <h1 className="text-3xl font-bold tracking-tight text-primary sm:text-4xl">
              Security Operations
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-secondary sm:text-base">
              Monitor Asset posture, assessment activity, and coverage gaps from one operational workspace.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to="/engagements/new">
              <Button color="primary" iconLeading={Target01}>
                New Engagement
              </Button>
            </Link>
            <Link to="/assets">
              <Button color="secondary" iconLeading={Package}>
                Asset inventory
              </Button>
            </Link>
            <Link to="/code-quality">
              <Button color="secondary" iconLeading={Activity}>
                Code security
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* KPI Stat Cards Row */}
      <section aria-label="Security operations summary" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard
          icon={Package}
          label="Total assets"
          value={data.assetTotal}
          hint="Managed inventory"
        />
        <StatCard
          icon={Shield01}
          label="High-risk assets"
          value={highRiskAssets}
          hint="Critical or high risk"
          tone={highRiskAssets ? 'critical' : 'accent'}
        />
        <StatCard
          icon={Activity}
          label="Active engagements"
          value={activeEngagements}
          hint={`${data.engagements.length} total assessments`}
          tone="brand"
        />
        <StatCard
          icon={Signal01}
          label="Coverage gaps"
          value={coverageGaps ?? '—'}
          hint={fleetUnavailable ? 'Fleet telemetry unavailable' : 'All non-covered states'}
          tone={coverageGaps ? 'high' : 'accent'}
        />
        <StatCard
          icon={AlertTriangle}
          label="Unassigned"
          value={unassignedEngagements}
          hint="Engagements without Asset"
          tone={unassignedEngagements ? 'medium' : 'accent'}
          className="col-span-2 lg:col-span-1"
        />
      </section>

      {/* Telemetry Section */}
      <section aria-labelledby="analytics-title">
        <SectionHeading
          eyebrow="Telemetry"
          title="Operations analytics"
          description="Live distribution across Asset posture, finding risk, and security inventory."
          id="analytics-title"
        />

        {analyticsError && <ErrorState message={analyticsError} />}
        {!analytics && !analyticsError && <Spinner label="Loading operations analytics…" className="min-h-64" />}

        {analytics && (
          <div className="grid gap-4 xl:grid-cols-2">
            <ChartCard
              title="Asset Security Posture"
              description="Current posture derived from findings and coverage."
              action={<LinkArrow to="/assets" label="View inventory" />}
            >
              <DonutChart
                title="Asset Security Posture"
                centerLabel="Assets"
                data={postureChart(analytics.assetPosture)}
              />
            </ChartCard>

            <ChartCard
              title="Findings Over Time"
              description="New publishable findings grouped by UTC day and severity."
              action={<RangeSelector value={rangeDays} onChange={setRangeDays} />}
            >
              <FindingsTrendChart points={analytics.findingsOverTime} series={severityChart({}, false)} />
              {analytics.findingsWithoutTimestamp > 0 && (
                <p className="mt-2 text-xs text-utility-yellow-600 dark:text-utility-yellow-400">
                  {analytics.findingsWithoutTimestamp} finding
                  {analytics.findingsWithoutTimestamp === 1 ? '' : 's'} excluded from the trend because no
                  creation timestamp is available.
                </p>
              )}
            </ChartCard>

            <ChartCard
              title="Active Finding Risk Mix"
              description="Open, triage, and confirmed actionable findings."
              action={<LinkArrow to="/assets" label="Review Assets" />}
            >
              <DonutChart
                title="Active Finding Risk Mix"
                centerLabel="Active"
                data={severityChart(analytics.activeFindingsBySeverity, true)}
              />
              {!analytics.externalFindingsIncluded && (
                <p className="mt-2 text-xs text-utility-yellow-600 dark:text-utility-yellow-400">
                  External finding storage is unavailable; third-party findings are not included.
                </p>
              )}
            </ChartCard>

            <ChartCard
              title="Assets by Criticality"
              description="Managed Assets grouped by business criticality."
              action={<LinkArrow to="/assets" label="View inventory" />}
            >
              <HorizontalBarChart
                title="Assets by Criticality"
                data={criticalityChart(analytics.assetsByCriticality)}
              />
            </ChartCard>
          </div>
        )}
      </section>

      {/* Escalation Section */}
      <section aria-labelledby="priority-title">
        <SectionHeading
          eyebrow="Escalation"
          title="Prioritized work"
          description="Assets needing review and the latest assessment queue."
          id="priority-title"
        />
        <div className="grid gap-4 xl:grid-cols-2">
          <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
            <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4 sm:px-6">
              <h3 className="text-sm font-semibold text-primary">Priority Assets</h3>
              <LinkArrow to="/assets" label="All Assets" />
            </header>
            <div>
              <PriorityAssetsTable assets={priorityAssets} hasTotalAssets={data.assets.length > 0} />
            </div>
          </section>

          <section className="flex flex-col rounded-xl border border-secondary bg-primary shadow-xs">
            <header className="flex items-center justify-between gap-3 border-b border-secondary px-5 py-4 sm:px-6">
              <h3 className="text-sm font-semibold text-primary">Assessment activity</h3>
              <LinkArrow to="/engagements" label="All Engagements" />
            </header>
            <div>
              <AssessmentActivityTable engagements={assessmentQueue} assetNames={assetNames} />
            </div>
          </section>
        </div>
      </section>
    </div>
  )
}

function SectionHeading({
  eyebrow,
  title,
  description,
  id,
}: {
  eyebrow: string
  title: string
  description: string
  id: string
}) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-secondary">
          {eyebrow}
        </p>
        <h2 id={id} className="mt-1 text-xl font-bold tracking-tight text-primary">
          {title}
        </h2>
      </div>
      <p className="max-w-xl text-xs leading-5 text-secondary sm:text-sm">{description}</p>
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
    <div className="flex rounded-lg border border-secondary bg-secondary p-0.5" aria-label="Finding trend range">
      {[7, 30, 90].map((days) => (
        <button
          key={days}
          type="button"
          onClick={() => onChange(days)}
          className={cx(
            'rounded-md px-2 py-1 text-[10px] font-semibold transition-colors',
            value === days
              ? 'bg-primary text-primary shadow-xs'
              : 'text-secondary hover:text-primary hover:bg-primary/50',
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
    chartItem('critical', 'Critical', counts, 'var(--color-critical)'),
    chartItem('high_risk', 'High Risk', counts, 'var(--color-high)'),
    chartItem('attention', 'Attention', counts, 'var(--color-medium)'),
    chartItem('unknown', 'Unknown', counts, 'var(--color-subtlefg)'),
    chartItem('good', 'Good', counts, 'var(--color-accent)'),
  ]
}

function severityChart(counts: Record<string, number>, includeUnknown: boolean): ChartDatum[] {
  const rows = [
    chartItem('critical', 'Critical', counts, 'var(--color-critical)'),
    chartItem('high', 'High', counts, 'var(--color-high)'),
    chartItem('medium', 'Medium', counts, 'var(--color-medium)'),
    chartItem('low', 'Low', counts, 'var(--color-low)'),
  ]
  if (includeUnknown) {
    rows.push(
      chartItem('info', 'Info', counts, 'var(--color-infosev)'),
      chartItem('unknown', 'Unknown', counts, 'var(--color-subtlefg)'),
    )
  }
  return rows
}

function criticalityChart(counts: Record<string, number>): ChartDatum[] {
  return [
    chartItem('critical', 'Critical', counts, 'var(--color-critical)'),
    chartItem('high', 'High', counts, 'var(--color-high)'),
    chartItem('medium', 'Medium', counts, 'var(--color-medium)'),
    chartItem('low', 'Low', counts, 'var(--color-low)'),
  ]
}

function chartItem(key: string, label: string, counts: Record<string, number>, color: string): ChartDatum {
  return { key, label, value: counts[key] ?? 0, color }
}
