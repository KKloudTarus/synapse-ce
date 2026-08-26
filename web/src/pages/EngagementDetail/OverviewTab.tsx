import {
  AlertCircle,
  BarChart01,
  Calendar,
  CheckCircle,
  ChevronRight,
  Clock,
  Code01,
  CpuChip01,
  Database01,
  Dataflow03,
  File06,
  LayoutGrid01,
  Package,
  Route,
  Scale01,
  Shield01,
  ShieldTick,
  ShieldZap,
  Sliders04,
  Target04,
  Tool01,
} from '@untitledui/icons'
import { type ComponentType, type ReactNode, useMemo } from 'react'
import { Card, EmptyState, Pill, SevBadge, Spinner, cn } from '../../components/ui'
import { sevBg, sevRank, sevText } from '../../lib/severity'
import type { Finding, ScanJob, ScanResult, Severity } from '../../lib/types'
import { countEdges, fmtDuration } from './VulnsTab'
import type { Tab } from './index'

export const TABS: { id: Tab; label: string; icon: typeof LayoutGrid01; countKey?: keyof TabCounts }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid01 },
  { id: 'findings', label: 'Findings', icon: ShieldZap, countKey: 'findings' },
  { id: 'sla', label: 'Remediation SLA', icon: Calendar },
  { id: 'components', label: 'Packages', icon: Package, countKey: 'components' },
  { id: 'vulns', label: 'Vulnerabilities', icon: ShieldZap, countKey: 'vulns' },
  { id: 'licenses', label: 'Licenses', icon: Scale01, countKey: 'licenses' },
  { id: 'graph', label: 'Graph', icon: Dataflow03 },
  { id: 'threats', label: 'Threat Model', icon: Route },
  { id: 'quality', label: 'Code Quality', icon: BarChart01 },
  { id: 'recon', label: 'Recon', icon: Target04 },
  { id: 'agent', label: 'Agent', icon: CpuChip01 },
  { id: 'reviews', label: 'Awaiting review', icon: Shield01 },
  { id: 'evidence', label: 'Evidence', icon: ShieldTick },
  { id: 'settings', label: 'Settings', icon: Sliders04 },
]

export interface TabCounts {
  findings: number
  components: number
  vulns: number
  licenses: number
}

export function TabBar({ tab, setTab, counts }: { tab: Tab; setTab: (t: Tab) => void; counts: TabCounts }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-secondary">
      {TABS.map(({ id, label, icon: Icon, countKey }) => {
        const active = tab === id
        const count = countKey ? counts[countKey] : undefined
        return (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap rounded-t-md border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-solid',
              active ? 'border-brand-solid text-brand-secondary' : 'border-transparent text-tertiary hover:text-primary',
            )}
          >
            <Icon className="size-4" />
            <span>{label}</span>
            {count !== undefined && count > 0 && (
              <span className="rounded-full bg-brand-primary px-1.5 py-0.2 text-xs font-bold tabular-nums text-brand-secondary">
                {count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

export function OverviewTab({
  findings,
  scan,
  job,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  job: ScanJob | null
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  if (!scan) {
    return (
      <EmptyState
        icon={LayoutGrid01}
        title="No scan yet"
        hint="Run a scan above to see risk analysis, remediation priorities, and software composition."
      />
    )
  }
  const open = findings ?? []
  return (
    <div className="space-y-4">
      {/* Zone 1: Health + Quality + Provenance Strip */}
      <ScanHealth scan={scan} job={job} />

      {/* Zone 2: Risk Analysis & Remediation Priorities */}
      <RiskAnalysisZone
        findings={open}
        scan={scan}
        loading={findings === null}
        onSelectSeverity={onSelectSeverity}
        onGoTab={onGoTab}
      />

      {/* Zone 3: Composition & Provenance */}
      <CompositionProvenanceCard scan={scan} onGoTab={onGoTab} />
    </div>
  )
}

/* ==========================================================================
   ZONE 1: Health + Quality + Provenance Strip
   ========================================================================== */

export function ScanHealth({ scan, job }: { scan: ScanResult; job: ScanJob | null }) {
  const status = job?.status ?? 'succeeded'
  const statusLabelText = status === 'running' ? 'Running' : status === 'failed' ? 'Failed' : 'Complete'
  const statusTone = status === 'running' ? 'brand' : status === 'failed' ? 'critical' : 'accent'
  const confident = scan.completeness.confident
  const q = scan.findingQuality
  const m = scan.manifest
  const repro = m.reproScore
  const reproTone = repro >= 85 ? 'accent' : repro >= 60 ? 'medium' : 'critical'

  return (
    <Card bodyClass="p-0" className="overflow-hidden shadow-xs">
      {/* 6-Cell Stat Strip: Label on top, Value on bottom */}
      <div className="grid grid-cols-2 divide-y divide-secondary sm:grid-cols-3 sm:divide-y-0 sm:divide-x lg:grid-cols-6">
        <HealthStat icon={CheckCircle} label="Status" value={statusLabelText} tone={statusTone} />
        <HealthStat
          icon={Clock}
          label="Duration"
          value={status === 'running' ? 'in progress' : fmtDuration(job?.startedAt ?? null, job?.finishedAt ?? null)}
        />
        <HealthStat
          icon={BarChart01}
          label="Confidence"
          value={confident ? 'High' : 'Partial'}
          tone={confident ? 'accent' : 'medium'}
        />
        <HealthStat
          icon={ShieldZap}
          label="Raw findings"
          value={q.rawFindings}
          hint={`Total uncurated scanner findings (${q.background} bg, ${q.production} prod, ${q.development} dev, ${q.exampleTest} test)`}
        />
        <HealthStat
          icon={ShieldTick}
          label="Actionable"
          value={q.actionable}
          tone="accent"
          hint="Actionable findings prioritized for remediation"
        />
        <HealthStat
          icon={Target04}
          label="Repro %"
          value={`${repro}%`}
          tone={reproTone}
          hint={`Reproducibility score: ${m.pinnedInputs.length} pinned, ${m.unpinnedInputs.length} live inputs`}
        />
      </div>
    </Card>
  )
}

export function HealthStat({
  icon: Icon,
  label,
  value,
  tone,
  hint,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  value: ReactNode
  tone?: 'accent' | 'critical' | 'medium' | 'brand'
  hint?: string
}) {
  const toneText =
    tone === 'accent'
      ? 'text-success-primary'
      : tone === 'critical'
        ? 'text-error-primary'
        : tone === 'medium'
          ? 'text-warning-primary'
          : tone === 'brand'
            ? 'text-brand-secondary'
            : 'text-primary'

  return (
    <div className="px-4 py-3" title={hint ?? (typeof value === 'string' ? value : undefined)}>
      <div className="flex items-center gap-1.5 text-xs font-semibold text-secondary">
        <Icon className="size-3.5 text-fg-tertiary" />
        <span>{label}</span>
      </div>
      <div className={cn('mt-1 truncate font-mono text-xl font-bold tabular-nums', toneText)}>{value}</div>
    </div>
  )
}

/* ==========================================================================
   ZONE 2: Risk Analysis & Remediation Priorities
   ========================================================================== */

export function RiskAnalysisZone({
  findings,
  scan,
  loading,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[]
  scan: ScanResult
  loading: boolean
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  const tp = findings.filter((f) => f.class !== 'first_party_historical')
  const critical = tp.filter((f) => f.severity === 'critical').length
  const high = tp.filter((f) => f.severity === 'high').length
  const denied = scan.licenses.filter((l) => l.verdict === 'deny').length
  const componentsAtRisk = new Set(
    scan.vulnerabilities.filter((v) => !v.unversioned).map((v) => v.component),
  ).size

  const targets = useMemo(() => remediationTargets(scan), [scan])

  return (
    <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-12">
      {/* Left 7 cols: Risk Priorities & Top Remediation Targets */}
      <div className="flex flex-col lg:col-span-7">
        <Card
          title="Remediation Priorities & Targets"
          actions={
            targets.length > 0 && (
              <button
                onClick={() => onGoTab('findings')}
                className="inline-flex items-center gap-1 text-xs font-semibold text-brand-secondary transition-colors hover:text-brand-solid focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
              >
                <span>All findings</span>
                <ChevronRight className="size-3" />
              </button>
            )
          }
          className="h-full flex flex-col shadow-xs"
          bodyClass="p-4 flex-1 flex flex-col justify-between gap-4"
        >
          {/* Top Row: 4 Horizontal Mini Attention Metric Cards */}
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            <AttentionCard
              label="Critical"
              value={critical}
              tone="critical"
              onClick={() => onSelectSeverity('critical')}
            />
            <AttentionCard
              label="High"
              value={high}
              tone="high"
              onClick={() => onSelectSeverity('high')}
            />
            <AttentionCard
              label="Lic. violations"
              value={denied}
              tone={denied > 0 ? 'high' : 'purple'}
              onClick={() => onGoTab('licenses')}
            />
            <AttentionCard
              label="Pkgs at risk"
              value={componentsAtRisk}
              tone={componentsAtRisk > 0 ? 'low' : 'success'}
              onClick={() => onGoTab('components')}
            />
          </div>

          {/* Bottom Section: Remediation Target List */}
          <div className="flex-1 flex flex-col justify-start">
            <div className="mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                Top remediation packages
              </span>
            </div>

            {targets.length === 0 ? (
              <div className="flex flex-1 flex-col items-center justify-center rounded-lg border border-secondary bg-secondary p-4 text-center">
                <CheckCircle className="mx-auto size-5 text-success-primary" />
                <p className="mt-1 text-xs font-medium text-secondary">
                  No vulnerable packages: nothing to remediate.
                </p>
              </div>
            ) : (
              <ol className="space-y-2">
                {targets.map((t, i) => (
                  <li
                    key={t.component}
                    className="flex items-center justify-between gap-3 rounded-lg border border-secondary bg-primary p-2.5 shadow-2xs transition-colors hover:border-brand-solid"
                  >
                    <div className="flex min-w-0 items-center gap-2.5">
                      <span className="flex size-5 shrink-0 items-center justify-center rounded bg-secondary font-mono text-xs font-bold text-tertiary">
                        {i + 1}
                      </span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span
                            className="truncate text-xs font-semibold text-primary"
                            title={`${t.component}@${t.version}`}
                          >
                            {t.component}
                          </span>
                          {t.hasFix && (
                            <Pill className="border border-utility-green-300 bg-success-primary px-1 py-0.2 text-[10px] font-bold text-success-primary">
                              fix
                            </Pill>
                          )}
                        </div>
                        <div className="mt-0.5 text-[11px] text-tertiary">
                          <span className="font-medium text-secondary">
                            {t.count} finding{t.count === 1 ? '' : 's'}
                          </span>
                          {t.maxEpss > 0 && (
                            <span className="font-mono text-quaternary">
                              {' '}· EPSS {(t.maxEpss * 100).toFixed(0)}%
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {t.critical > 0 && <CountBadge n={t.critical} sev="critical" />}
                      {t.high > 0 && <CountBadge n={t.high} sev="high" />}
                      {t.critical === 0 && t.high === 0 && <SevBadge sev={t.top} />}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </Card>
      </div>

      {/* Right 5 cols: Findings by Severity (Ring Activity Gauge) */}
      <div className="flex flex-col lg:col-span-5">
        <VulnDistribution
          findings={findings}
          loading={loading}
          onSelectSeverity={onSelectSeverity}
        />
      </div>
    </div>
  )
}

const RING_RADII = [114, 100, 86, 72, 58]
const RING_STROKE_WIDTH = 7

export function FindingsActivityGauge({
  findings,
  onSelectSeverity,
}: {
  findings: Finding[]
  onSelectSeverity: (s: Severity | 'all') => void
}) {
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
  const counts = severities.map((sev) => ({
    sev,
    count: findings.filter((f) => f.severity === sev).length,
    label: sev.charAt(0).toUpperCase() + sev.slice(1),
    dot:
      sev === 'critical'
        ? 'bg-utility-red-600'
        : sev === 'high'
          ? 'bg-utility-orange-600'
          : sev === 'medium'
            ? 'bg-utility-yellow-600'
            : sev === 'low'
              ? 'bg-utility-blue-600'
              : 'bg-utility-gray-600',
    colorHex:
      sev === 'critical'
        ? '#D92D20'
        : sev === 'high'
          ? '#F79009'
          : sev === 'medium'
            ? '#FDB022'
            : sev === 'low'
              ? '#1570EF'
              : '#98A2B3',
  }))
  const total = findings.length
  const maxVal = Math.max(...counts.map((c) => c.count), 1)

  return (
    <div className="flex flex-col items-center justify-between gap-3 h-full py-1">
      {/* Activity Rings Graphic */}
      <div className="relative flex items-center justify-center pt-1">
        <svg
          viewBox="0 0 260 260"
          className="size-52 sm:size-56"
          aria-label={`Findings by severity activity gauge: ${total} total findings`}
        >
          {counts.map(({ sev, count, colorHex }, idx) => {
            const r = RING_RADII[idx]
            const circumference = 2 * Math.PI * r
            const ratio = count > 0 ? (count / maxVal) * 0.85 : 0
            const strokeDash = count > 0 ? Math.max(circumference * 0.04, circumference * ratio) : 0

            return (
              <g key={sev}>
                {/* Background track ring */}
                <circle
                  cx="130"
                  cy="130"
                  r={r}
                  fill="none"
                  stroke="#F2F4F7"
                  strokeWidth={RING_STROKE_WIDTH}
                  className="stroke-utility-gray-100"
                />
                {/* Value arc */}
                {count > 0 && (
                  <circle
                    cx="130"
                    cy="130"
                    r={r}
                    fill="none"
                    stroke={colorHex}
                    strokeWidth={RING_STROKE_WIDTH}
                    strokeLinecap="round"
                    strokeDasharray={`${strokeDash} ${circumference}`}
                    strokeDashoffset={0}
                    transform="rotate(-90 130 130)"
                  />
                )}
              </g>
            )
          })}
        </svg>

        {/* Center Total Counter */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xs font-bold uppercase tracking-wider text-secondary">Total</span>
          <span className="font-mono text-3xl font-bold tabular-nums text-primary mt-0.5">{total}</span>
        </div>
      </div>

      {/* Legend Rows at Bottom */}
      <div className="flex w-full flex-wrap items-center justify-center gap-1.5 border-t border-secondary pt-3">
        {counts.map(({ sev, count, dot, label }) => (
          <button
            key={sev}
            type="button"
            onClick={() => onSelectSeverity(sev)}
            disabled={count === 0}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
              count > 0
                ? 'cursor-pointer text-secondary hover:bg-secondary hover:text-primary font-medium'
                : 'cursor-default text-quaternary',
            )}
            title={`${count} ${label} findings`}
          >
            <span className={cn('size-2 shrink-0 rounded-full', dot)} />
            <span className="text-xs capitalize">{label}</span>
            <span className="font-mono text-xs font-bold tabular-nums text-primary">{count}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

export function VulnDistribution({
  findings,
  loading,
  onSelectSeverity,
}: {
  findings: Finding[]
  loading: boolean
  onSelectSeverity: (s: Severity | 'all') => void
}) {
  return (
    <Card
      title="Findings by severity"
      className="h-full flex flex-col shadow-xs"
      bodyClass="p-4 flex-1 flex flex-col justify-between"
    >
      {loading ? (
        <Spinner />
      ) : findings.length === 0 ? (
        <CardEmpty icon={CheckCircle} text="No findings promoted from this scan." />
      ) : (
        <FindingsActivityGauge findings={findings} onSelectSeverity={onSelectSeverity} />
      )}
    </Card>
  )
}

export function AttentionCard({
  label,
  value,
  tone,
  onClick,
}: {
  label: string
  value: number
  tone: 'critical' | 'high' | 'medium' | 'low' | 'success' | 'purple' | 'neutral'
  onClick: () => void
}) {
  const toneConfig = {
    critical: {
      bar: 'bg-utility-red-600',
      text: 'text-error-primary',
      border: 'border-error',
      bg: 'bg-error-primary',
      chevron: 'text-error-primary',
    },
    high: {
      bar: 'bg-utility-orange-600',
      text: 'text-warning-primary',
      border: 'border-utility-orange-300',
      bg: 'bg-warning-primary',
      chevron: 'text-warning-primary',
    },
    medium: {
      bar: 'bg-utility-yellow-600',
      text: 'text-warning-primary',
      border: 'border-utility-yellow-300',
      bg: 'bg-warning-primary',
      chevron: 'text-warning-primary',
    },
    low: {
      bar: 'bg-utility-blue-600',
      text: 'text-utility-blue-700',
      border: 'border-utility-blue-200',
      bg: 'bg-utility-blue-50',
      chevron: 'text-utility-blue-700',
    },
    success: {
      bar: 'bg-utility-green-600',
      text: 'text-success-primary',
      border: 'border-utility-green-300',
      bg: 'bg-success-primary',
      chevron: 'text-success-primary',
    },
    purple: {
      bar: 'bg-utility-purple-600',
      text: 'text-utility-purple-700',
      border: 'border-utility-purple-200',
      bg: 'bg-utility-purple-50',
      chevron: 'text-utility-purple-700',
    },
    neutral: {
      bar: 'bg-brand-solid',
      text: 'text-brand-secondary',
      border: 'border-brand-solid',
      bg: 'bg-brand-primary',
      chevron: 'text-brand-secondary',
    },
  }[tone]

  return (
    <button
      onClick={onClick}
      className={cn(
        'group relative flex flex-col justify-between overflow-hidden rounded-lg border p-2.5 shadow-2xs transition-all',
        toneConfig.border,
        toneConfig.bg,
        'hover:shadow-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
      )}
    >
      <div className={cn('absolute inset-x-0 top-0 h-0.5', toneConfig.bar)} />
      <div className="flex items-center justify-between w-full">
        <span className={cn('truncate text-[11px] font-bold', toneConfig.text)}>{label}</span>
        <ChevronRight className={cn('size-3 shrink-0 transition-transform group-hover:translate-x-0.5', toneConfig.chevron)} />
      </div>
      <div className="my-1 flex items-center justify-center w-full">
        <span className={cn('font-mono text-2xl sm:text-3xl font-extrabold tabular-nums', toneConfig.text)}>{value}</span>
      </div>
    </button>
  )
}

export interface RemTarget {
  component: string
  version: string
  count: number
  critical: number
  high: number
  top: Severity
  maxEpss: number
  hasFix: boolean
}

export function remediationTargets(scan: ScanResult): RemTarget[] {
  const map = new Map<string, RemTarget>()
  for (const v of scan.vulnerabilities) {
    if (v.unversioned) continue
    const cur =
      map.get(v.component) ??
      ({
        component: v.component,
        version: v.version,
        count: 0,
        critical: 0,
        high: 0,
        top: 'unknown' as Severity,
        maxEpss: 0,
        hasFix: false,
      } satisfies RemTarget)
    cur.count++
    if (v.severity === 'critical') cur.critical++
    if (v.severity === 'high') cur.high++
    if (sevRank(v.severity) > sevRank(cur.top)) cur.top = v.severity
    if (v.epss > cur.maxEpss) cur.maxEpss = v.epss
    if (v.fixedVersion) cur.hasFix = true
    map.set(v.component, cur)
  }
  return [...map.values()]
    .sort(
      (a, b) =>
        b.critical - a.critical ||
        sevRank(b.top) - sevRank(a.top) ||
        b.count - a.count ||
        b.maxEpss - a.maxEpss,
    )
    .slice(0, 5)
}

export function CountBadge({ n, sev }: { n: number; sev: Severity }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] font-bold tabular-nums',
        sev === 'critical'
          ? 'border-error bg-error-primary text-error-primary'
          : 'border-utility-orange-300 bg-warning-primary text-warning-primary',
      )}
    >
      {n} {sev === 'critical' ? 'crit' : 'high'}
    </span>
  )
}

/* ==========================================================================
   ZONE 3: Composition & Provenance (2-Column Balanced Compact Layout)
   ========================================================================== */

const LANG_COLORS = [
  'bg-utility-blue-600',
  'bg-utility-green-600',
  'bg-utility-orange-600',
  'bg-utility-pink-600',
  'bg-brand-solid',
  'bg-utility-gray-600',
]

export function CompositionProvenanceCard({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const langs = scan.languages.slice().sort((a, b) => b.percent - a.percent)
  const m = scan.manifest

  return (
    <Card title="Composition & Provenance" className="shadow-xs" bodyClass="p-4">
      <div className="grid grid-cols-1 items-stretch divide-y divide-secondary lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
        {/* Col 1 (6 cols): Codebase Languages & Inventory Summary */}
        <div className="flex flex-col justify-between space-y-4 pb-4 lg:col-span-6 lg:pb-0 lg:pr-5">
          {/* Languages Section */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                Languages
              </span>
              <span className="text-[11px] text-tertiary">
                {langs.length} detected
              </span>
            </div>

            {langs.length === 0 ? (
              <p className="text-xs text-quaternary">No source languages detected.</p>
            ) : (
              <div className="space-y-2">
                {/* Multi-segment Language Distribution Bar */}
                <div className="flex h-2 w-full overflow-hidden rounded-full bg-secondary">
                  {langs.slice(0, 6).map((l, idx) => (
                    <div
                      key={l.name}
                      className={cn('h-full transition-all', LANG_COLORS[idx % LANG_COLORS.length])}
                      style={{ width: `${Math.max(1, l.percent)}%` }}
                      title={`${l.name}: ${l.percent.toFixed(1)}%`}
                    />
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {langs.slice(0, 6).map((l, idx) => (
                    <div key={l.name} className="flex items-center gap-1.5 text-xs">
                      <span className={cn('size-2 rounded-full shrink-0', LANG_COLORS[idx % LANG_COLORS.length])} />
                      <span className="truncate font-medium text-primary">{l.name}</span>
                      <span className="font-mono font-bold tabular-nums text-secondary">{l.percent.toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Inventory Counts Section */}
          <div className="border-t border-secondary pt-3">
            <div className="mb-2 text-xs font-bold uppercase tracking-wider text-secondary">
              Inventory Counts
            </div>
            <div className="grid grid-cols-3 gap-2">
              <CompTile
                icon={Package}
                label="packages"
                value={scan.components.length}
                tone="blue"
                onClick={() => onGoTab('components')}
              />
              <CompTile
                icon={Scale01}
                label="licenses"
                value={scan.licenses.length}
                tone="purple"
                onClick={() => onGoTab('licenses')}
              />
              <CompTile
                icon={Dataflow03}
                label="dep. edges"
                value={countEdges(scan)}
                tone="green"
                onClick={() => onGoTab('graph')}
              />
            </div>
          </div>
        </div>

        {/* Col 2 (6 cols): Tool Versions & Integrity Metadata */}
        <div className="flex flex-col justify-between pt-4 lg:col-span-6 lg:pt-0 lg:pl-5">
          <div>
            <div className="mb-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-secondary">
                Tool Versions &amp; Integrity
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {Object.entries(scan.toolVersions).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                  <span className="flex items-center gap-1.5 text-tertiary">
                    <Tool01 className="size-3.5 text-fg-tertiary" />
                    <span>{k}</span>
                  </span>
                  <span className="truncate font-mono font-bold tabular-nums text-primary">{v}</span>
                </div>
              ))}
              <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                <span className="flex items-center gap-1.5 text-tertiary">
                  <Database01 className="size-3.5 text-fg-tertiary" />
                  <span>vuln DB</span>
                </span>
                <span className="truncate font-mono font-bold text-primary">{scan.vulnDBSnapshot || '0'}</span>
              </div>
              {m.sbomSha256 && (
                <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
                  <span className="flex items-center gap-1.5 text-tertiary">
                    <File06 className="size-3.5 text-fg-tertiary" />
                    <span>SBOM sha</span>
                  </span>
                  <span className="truncate font-mono font-bold text-primary" title={m.sbomSha256}>
                    {m.sbomSha256.slice(0, 12)}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}

export function CompTile({
  icon: Icon,
  label,
  value,
  tone = 'blue',
  onClick,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  value: number
  tone?: 'blue' | 'purple' | 'green'
  onClick: () => void
}) {
  const toneStyles = {
    blue: {
      border: 'border-utility-blue-200',
      bg: 'bg-utility-blue-50',
      text: 'text-utility-blue-700',
      icon: 'text-utility-blue-600',
    },
    purple: {
      border: 'border-utility-purple-200',
      bg: 'bg-utility-purple-50',
      text: 'text-utility-purple-700',
      icon: 'text-utility-purple-600',
    },
    green: {
      border: 'border-utility-green-300',
      bg: 'bg-success-primary',
      text: 'text-success-primary',
      icon: 'text-fg-success-primary',
    },
  }[tone]

  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 rounded-lg border px-2.5 py-2 transition-all shadow-2xs hover:shadow-xs',
        toneStyles.border,
        toneStyles.bg,
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid',
      )}
    >
      <Icon className={cn('size-4 shrink-0', toneStyles.icon)} />
      <div className="min-w-0 text-left">
        <div className={cn('font-mono text-sm font-bold tabular-nums', toneStyles.text)}>{value}</div>
        <div className={cn('text-[10px] font-bold uppercase tracking-wider', toneStyles.text)}>{label}</div>
      </div>
    </button>
  )
}

export function CardEmpty({ icon: Icon, text }: { icon: ComponentType<{ className?: string }>; text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Icon className="size-6 text-fg-quaternary" />
      <p className="text-xs font-medium text-tertiary">{text}</p>
    </div>
  )
}
