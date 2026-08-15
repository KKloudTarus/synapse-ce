import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CircleDot,
  Gauge,
  LayoutDashboard,
  RadioTower,
  ShieldAlert,
  Target,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Card, ErrorState, Spinner, cn } from '../components/ui'
import { DonutChart, FindingsTrendChart, HorizontalBarChart, type ChartDatum } from '../components/DashboardCharts'
import { api } from '../lib/api'
import type { BusinessAsset, DashboardSecurityOperations, Engagement, FleetCoverageSummary } from '../lib/types'
import { PostureBadge } from './Assets'
import { StatusPill } from './Engagements'

type DashboardData = {
  assets: BusinessAsset[]
  assetTotal: number
  engagements: Engagement[]
}

const ENGAGEMENT_ORDER = ['active', 'draft', 'completed', 'archived'] as const
const POSTURE_WEIGHT: Record<string, number> = { critical: 5, high_risk: 4, attention: 3, unknown: 2, good: 1 }
const CRITICALITY_WEIGHT: Record<BusinessAsset['criticality'], number> = { critical: 4, high: 3, medium: 2, low: 1 }

export function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fleet, setFleet] = useState<FleetCoverageSummary | null>(null)
  const [fleetUnavailable, setFleetUnavailable] = useState(false)
  const [analytics, setAnalytics] = useState<DashboardSecurityOperations | null>(null)
  const [analyticsError, setAnalyticsError] = useState<string | null>(null)
  const [rangeDays, setRangeDays] = useState(30)

  useEffect(() => {
    let active = true
    setError(null)

    Promise.all([loadAllAssets(), api.listEngagements()])
      .then(([assetResult, engagements]) => {
        if (active) setData({ ...assetResult, engagements })
      })
      .catch((nextError) => {
        if (active) setError(nextError instanceof Error ? nextError.message : 'Failed to load dashboard')
      })

    api.fleetCoverageSummary()
      .then((summary) => {
        if (active) setFleet(summary)
      })
      .catch(() => {
        if (active) setFleetUnavailable(true)
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    let active = true
    setAnalytics(null)
    setAnalyticsError(null)
    api.dashboardSecurityOperations(rangeDays)
      .then((summary) => {
        if (active) setAnalytics(summary)
      })
      .catch((nextError) => {
        if (active) setAnalyticsError(nextError instanceof Error ? nextError.message : 'Failed to load dashboard analytics')
      })
    return () => {
      active = false
    }
  }, [rangeDays])

  if (error) return <div className="mx-auto max-w-[1600px]"><ErrorState message={error} /></div>
  if (!data) return <Spinner label="Loading security operations…" />

  const assetNames = Object.fromEntries(data.assets.map((asset) => [asset.id, asset.name]))
  const highRiskAssets = data.assets.filter((asset) => ['critical', 'high_risk'].includes(asset.posture ?? 'unknown')).length
  const activeEngagements = data.engagements.filter((engagement) => engagement.status.toLowerCase() === 'active').length
  const unassignedEngagements = data.engagements.filter((engagement) => !engagement.businessAssetId).length
  const coverageGaps = fleet ? Object.entries(fleet.rowsByVerdict).reduce((total, [verdict, count]) => total + (verdict === 'covered' ? 0 : count), 0) : null
  const priorityAssets = [...data.assets]
    .filter((asset) => (asset.posture ?? 'unknown') !== 'good' && asset.lifecycle !== 'retired')
    .sort((left, right) => {
      const postureDelta = (POSTURE_WEIGHT[right.posture ?? 'unknown'] ?? 0) - (POSTURE_WEIGHT[left.posture ?? 'unknown'] ?? 0)
      return postureDelta || CRITICALITY_WEIGHT[right.criticality] - CRITICALITY_WEIGHT[left.criticality] || left.name.localeCompare(right.name)
    })
    .slice(0, 6)
  const assessmentQueue = [...data.engagements]
    .sort((left, right) => {
      const leftStatus = ENGAGEMENT_ORDER.indexOf(left.status.toLowerCase() as (typeof ENGAGEMENT_ORDER)[number])
      const rightStatus = ENGAGEMENT_ORDER.indexOf(right.status.toLowerCase() as (typeof ENGAGEMENT_ORDER)[number])
      return (leftStatus < 0 ? ENGAGEMENT_ORDER.length : leftStatus) - (rightStatus < 0 ? ENGAGEMENT_ORDER.length : rightStatus)
        || Date.parse(right.createdAt ?? '') - Date.parse(left.createdAt ?? '')
    })
    .slice(0, 6)

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="bg-hero overflow-hidden rounded-2xl border border-border px-5 py-6 sm:px-7 sm:py-7">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <div>
            <p className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-branddim">
              <LayoutDashboard className="size-4" aria-hidden="true" />Command center
            </p>
            <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Security Operations</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-mutedfg sm:text-base">
              Monitor Asset posture, assessment activity, and coverage gaps from one operational workspace.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <QuickLink to="/engagements/new" label="New Engagement" icon={Target} />
            <QuickLink to="/assets" label="Asset inventory" icon={Boxes} />
            <QuickLink to="/code-quality" label="Code security" icon={Gauge} />
          </div>
        </div>
      </header>

      <section aria-label="Security operations summary" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <MetricCard icon={Boxes} label="Total assets" value={data.assetTotal} hint="Managed inventory" />
        <MetricCard icon={ShieldAlert} label="High-risk assets" value={highRiskAssets} hint="Critical or high risk" tone={highRiskAssets ? 'critical' : 'accent'} />
        <MetricCard icon={Activity} label="Active engagements" value={activeEngagements} hint={`${data.engagements.length} total assessments`} tone="brand" />
        <MetricCard icon={RadioTower} label="Coverage gaps" value={coverageGaps ?? '—'} hint={fleetUnavailable ? 'Fleet telemetry unavailable' : 'All non-covered states'} tone={coverageGaps ? 'high' : 'accent'} />
        <MetricCard icon={AlertTriangle} label="Unassigned" value={unassignedEngagements} hint="Engagements without Asset" tone={unassignedEngagements ? 'medium' : 'accent'} className="col-span-2 lg:col-span-1" />
      </section>

      <section aria-labelledby="analytics-title">
        <SectionHeading eyebrow="Telemetry" title="Operations analytics" description="Live distribution across Asset posture, finding risk, and security inventory." id="analytics-title" />
        {analyticsError && <ErrorState message={analyticsError} />}
        {!analytics && !analyticsError && <Spinner label="Loading operations analytics…" className="min-h-64" />}
        {analytics && (
          <div className="grid gap-4 xl:grid-cols-2">
            <ChartCard title="Asset Security Posture" description="Current posture derived from findings and coverage." action={<LinkArrow to="/assets" label="View inventory" />}>
              <DonutChart title="Asset Security Posture" centerLabel="Assets" data={postureChart(analytics.assetPosture)} />
            </ChartCard>

            <ChartCard title="Findings Over Time" description="New publishable findings grouped by UTC day and severity." action={<RangeSelector value={rangeDays} onChange={setRangeDays} />}>
              <FindingsTrendChart points={analytics.findingsOverTime} series={severityChart({}, false)} />
              {analytics.findingsWithoutTimestamp > 0 && <p className="mt-2 text-xs text-medium">{analytics.findingsWithoutTimestamp} finding{analytics.findingsWithoutTimestamp === 1 ? '' : 's'} excluded from the trend because no creation timestamp is available.</p>}
            </ChartCard>

            <ChartCard title="Active Finding Risk Mix" description="Open, triage, and confirmed actionable findings." action={<LinkArrow to="/assets" label="Review Assets" />}>
              <DonutChart title="Active Finding Risk Mix" centerLabel="Active" data={severityChart(analytics.activeFindingsBySeverity, true)} />
              {!analytics.externalFindingsIncluded && <p className="mt-2 text-xs text-medium">External finding storage is unavailable; third-party findings are not included.</p>}
            </ChartCard>

            <ChartCard title="Assets by Criticality" description="Managed Assets grouped by business criticality." action={<LinkArrow to="/assets" label="View inventory" />}>
              <HorizontalBarChart title="Assets by Criticality" data={criticalityChart(analytics.assetsByCriticality)} />
            </ChartCard>
          </div>
        )}
      </section>

      <section aria-labelledby="priority-title">
        <SectionHeading eyebrow="Escalation" title="Prioritized work" description="Assets needing review and the latest assessment queue." id="priority-title" />
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Priority Assets" actions={<LinkArrow to="/assets" label="All Assets" />} bodyClass="p-0">
            {priorityAssets.length > 0 ? (
              <div className="divide-y divide-border">
                {priorityAssets.map((asset) => <PriorityAsset key={asset.id} asset={asset} />)}
              </div>
            ) : (
              <QueueEmpty icon={CheckCircle2} title="No priority Assets" hint={data.assets.length ? 'All loaded Assets report good posture.' : 'Create an Asset to begin posture tracking.'} />
            )}
          </Card>

          <Card title="Assessment activity" actions={<LinkArrow to="/engagements" label="All Engagements" />} bodyClass="p-0">
            {assessmentQueue.length > 0 ? (
              <div className="divide-y divide-border">
                {assessmentQueue.map((engagement) => <AssessmentRow key={engagement.id} engagement={engagement} assetName={assetNames[engagement.businessAssetId]} />)}
              </div>
            ) : (
              <QueueEmpty icon={Target} title="No Engagements yet" hint="Create an Engagement to define an authorized assessment scope." />
            )}
          </Card>
        </div>
      </section>
    </div>
  )
}

async function loadAllAssets(): Promise<{ assets: BusinessAsset[]; assetTotal: number }> {
  const first = await api.listBusinessAssets('limit=200')
  if (first.total <= first.items.length) return { assets: first.items, assetTotal: first.total }
  const offsets = Array.from({ length: Math.ceil(first.total / 200) - 1 }, (_, index) => (index + 1) * 200)
  const pages = await Promise.all(offsets.map((offset) => api.listBusinessAssets(`limit=200&offset=${offset}`)))
  return { assets: [first.items, ...pages.map((page) => page.items)].flat(), assetTotal: first.total }
}

function QuickLink({ to, label, icon: Icon }: { to: string; label: string; icon: LucideIcon }) {
  return (
    <Link to={to} className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-borderstrong bg-card/80 px-3.5 text-sm font-semibold text-foreground shadow-sm transition hover:border-brand/40 hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
      <Icon className="size-4 text-branddim" aria-hidden="true" />{label}
    </Link>
  )
}

function MetricCard({ icon: Icon, label, value, hint, tone = 'muted', className }: { icon: LucideIcon; label: string; value: number | string; hint: string; tone?: 'muted' | 'brand' | 'critical' | 'high' | 'medium' | 'accent'; className?: string }) {
  const iconTone = {
    muted: 'bg-muted text-mutedfg',
    brand: 'bg-brand/10 text-branddim',
    critical: 'bg-critical/10 text-critical',
    high: 'bg-high/10 text-high',
    medium: 'bg-medium/10 text-medium',
    accent: 'bg-accent/10 text-accent',
  }[tone]
  return (
    <div aria-label={`${label}: ${value}`} className={cn('card-sheen elev rounded-xl border border-border bg-card p-4', className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-2xl font-bold tabular-nums sm:text-3xl">{typeof value === 'number' ? value.toLocaleString() : value}</div>
          <div className="mt-1 text-xs font-semibold sm:text-sm">{label}</div>
        </div>
        <span className={cn('flex size-9 shrink-0 items-center justify-center rounded-lg', iconTone)}><Icon className="size-4" aria-hidden="true" /></span>
      </div>
      <p className="mt-3 truncate text-xs text-subtlefg" title={hint}>{hint}</p>
    </div>
  )
}

function SectionHeading({ eyebrow, title, description, id }: { eyebrow: string; title: string; description: string; id: string }) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-branddim">{eyebrow}</p>
        <h2 id={id} className="mt-1 text-xl font-bold tracking-tight">{title}</h2>
      </div>
      <p className="max-w-xl text-xs leading-5 text-mutedfg sm:text-sm">{description}</p>
    </div>
  )
}

function LinkArrow({ to, label }: { to: string; label: string }) {
  return <Link to={to} className="inline-flex items-center gap-1 text-xs font-semibold text-branddim hover:text-brand"><span className="hidden sm:inline">{label}</span><ArrowRight className="size-3.5" aria-hidden="true" /></Link>
}

function PriorityAsset({ asset }: { asset: BusinessAsset }) {
  return (
    <Link to={`/assets/${encodeURIComponent(asset.id)}`} className="group grid gap-3 p-4 transition-colors hover:bg-elevated sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:px-5">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="truncate font-semibold group-hover:text-branddim">{asset.name}</h3>
          <CriticalityBadge value={asset.criticality} />
        </div>
        <p className="mt-1 truncate text-xs text-mutedfg">{asset.owner || 'Owner not set'} · {labelize(asset.lifecycle)}</p>
      </div>
      <PostureBadge rating={asset.posture ?? 'unknown'} />
    </Link>
  )
}

function AssessmentRow({ engagement, assetName }: { engagement: Engagement; assetName?: string }) {
  return (
    <Link to={`/engagements/${encodeURIComponent(engagement.id)}`} className="group grid gap-3 p-4 transition-colors hover:bg-elevated sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:px-5">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="truncate font-semibold group-hover:text-branddim">{engagement.name || 'Untitled Engagement'}</h3>
          <StatusPill status={engagement.status} />
        </div>
        <p className="mt-1 truncate text-xs text-mutedfg">{assetName || (engagement.businessAssetId ? engagement.businessAssetId : 'Unassigned Asset')}</p>
      </div>
      <div className="flex items-center gap-2 text-xs text-subtlefg">
        <Target className="size-3.5" aria-hidden="true" />{engagement.inScope.length} in scope
      </div>
    </Link>
  )
}

function QueueEmpty({ icon: Icon, title, hint }: { icon: LucideIcon; title: string; hint: string }) {
  return (
    <div className="flex min-h-52 flex-col items-center justify-center px-6 text-center">
      <span className="flex size-10 items-center justify-center rounded-full bg-muted text-mutedfg"><Icon className="size-5" /></span>
      <p className="mt-3 text-sm font-medium">{title}</p>
      <p className="mt-1 max-w-sm text-xs leading-5 text-mutedfg">{hint}</p>
    </div>
  )
}

function CriticalityBadge({ value }: { value: BusinessAsset['criticality'] }) {
  const tone = value === 'critical' ? 'text-critical' : value === 'high' ? 'text-high' : value === 'medium' ? 'text-medium' : 'text-low'
  return <span className={cn('inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide', tone)}><CircleDot className="size-3" />{value}</span>
}

function labelize(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function ChartCard({ title, description, action, children }: { title: string; description: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <Card title={<div><span className="block">{title}</span><span aria-hidden="true" className="mt-1 block text-xs font-normal text-subtlefg">{description}</span></div>} actions={action} bodyClass="p-5 sm:p-6">
      {children}
    </Card>
  )
}

function RangeSelector({ value, onChange }: { value: number; onChange: (value: number) => void }) {
  return (
    <div className="flex rounded-lg border border-border bg-bg p-0.5" aria-label="Finding trend range">
      {[7, 30, 90].map((days) => <button key={days} type="button" onClick={() => onChange(days)} className={cn('rounded-md px-2 py-1 text-[10px] font-semibold transition-colors', value === days ? 'bg-brand text-brandfg' : 'text-mutedfg hover:text-foreground')}>{days}d</button>)}
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
  if (includeUnknown) rows.push(chartItem('info', 'Info', counts, 'var(--color-infosev)'), chartItem('unknown', 'Unknown', counts, 'var(--color-subtlefg)'))
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
