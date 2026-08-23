import {
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
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap rounded-t-md border-b-2 px-3.5 py-2.5 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40',
              active ? 'border-brand text-primary' : 'border-transparent text-tertiary hover:text-primary',
            )}
          >
            <Icon className="size-4" />
            {label}
            {count !== undefined && count > 0 && (
              <span className="rounded-full bg-brand-primary px-1.5 text-xs font-medium tabular-nums text-brand-secondary">
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
        hint="Run a scan above – this overview will show what’s risky, what to fix first, and where it came from."
      />
    )
  }
  const open = findings ?? []
  return (
    <div className="space-y-4">
      {/* Zone 1: Health + Quality + Provenance Strip (1 dòng stat cards) */}
      <ScanHealth scan={scan} job={job} />

      {/* Zone 2: Risk Analysis (What Needs Attention + Remediation + Severity Chart) */}
      <RiskAnalysisZone
        findings={open}
        scan={scan}
        loading={findings === null}
        onSelectSeverity={onSelectSeverity}
        onGoTab={onGoTab}
      />

      {/* Zone 3: Composition + Provenance (1 card 3-column) */}
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
  const byP = q.byPriority || {}
  const source = (scan.vulnDBSnapshot.split('@')[0] || 'osv.dev').replace(/\.dev$/, '').toUpperCase()
  const lockfileCount = scan.completeness.lockfiles.length

  return (
    <Card bodyClass="p-0">
      {/* 6-Cell Stat Strip */}
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

      {/* Finding Quality + Lockfiles Detail Row */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 border-t border-secondary bg-secondary/30 px-4 py-2 text-xs text-tertiary">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <span className="font-semibold text-secondary">Quality:</span>
          <span>
            {q.background} bg · {q.production} prod · {q.development} dev · {q.exampleTest} test
          </span>
          <span className="text-quaternary">|</span>
          <div className="flex items-center gap-2">
            {[1, 2, 3, 4, 5].map((p) =>
              byP[String(p)] ? (
                <span key={p} className="font-mono tabular-nums">
                  <span
                    className={cn(
                      'font-semibold',
                      p <= 2 ? 'text-critical' : p === 3 ? 'text-medium' : 'text-quaternary',
                    )}
                  >
                    P{p}
                  </span>
                  :{byP[String(p)]}
                </span>
              ) : null,
            )}
          </div>
          <span className="text-quaternary">|</span>
          <span className="text-quaternary">
            ver cov {q.versionCoveragePct.toFixed(0)}% · path cov {q.pathCoveragePct.toFixed(0)}%
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-quaternary">
          <span title={scan.completeness.lockfiles.join(', ')}>
            Lockfiles: <span className="font-mono text-tertiary">{lockfileCount}</span>
          </span>
          <span>
            Source: <span className="font-mono text-tertiary">{source}</span>
          </span>
        </div>
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
      ? 'text-accent'
      : tone === 'critical'
        ? 'text-critical'
        : tone === 'medium'
          ? 'text-medium'
          : tone === 'brand'
            ? 'text-brand-secondary'
            : 'text-primary'
  return (
    <div className="px-4 py-3" title={hint ?? (typeof value === 'string' ? value : undefined)}>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-tertiary">
        <Icon className="size-3.5" />
        {label}
      </div>
      <div className={cn('mt-1 truncate text-lg font-semibold tabular-nums', toneText)}>{value}</div>
    </div>
  )
}



/* ==========================================================================
   ZONE 2: Risk Analysis (Attention + Remediation + Severity Chart)
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
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      {/* Left 4 cols: Top Remediation Targets */}
      <div className="lg:col-span-4">
        <Card
          title="Top remediation targets"
          actions={
            targets.length > 0 && (
              <button
                onClick={() => onGoTab('findings')}
                className="rounded text-xs font-medium text-brand-secondary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
              >
                All findings →
              </button>
            )
          }
          className="h-full flex flex-col"
          bodyClass="p-4 flex-1"
        >
          {targets.length === 0 ? (
            <CardEmpty icon={CheckCircle} text="No vulnerable packages – nothing to remediate." />
          ) : (
            <ol className="space-y-1">
              {targets.map((t, i) => (
                <li key={t.component} className="flex items-center gap-2 rounded-lg py-1">
                  <span className="w-4 shrink-0 text-center font-mono text-xs text-quaternary">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-sm font-medium text-primary" title={`${t.component}@${t.version}`}>
                        {t.component}
                      </span>
                      {t.hasFix && <Pill className="bg-accent/12 text-accent ring-1 ring-inset ring-accent/25">fix</Pill>}
                    </div>
                    <div className="mt-0.5 text-xs text-tertiary">
                      {t.count} finding{t.count === 1 ? '' : 's'}
                      {t.maxEpss > 0 && <span className="text-quaternary"> · EPSS {(t.maxEpss * 100).toFixed(0)}%</span>}
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
        </Card>
      </div>

      {/* Middle 3 cols: Attention Cards (Critical, High, Lic. violations, Pkgs at risk) */}
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 lg:col-span-3 lg:flex lg:flex-col lg:justify-between">
        <AttentionCard
          label="Critical"
          value={critical}
          tone="critical"
          onClick={() => onSelectSeverity('critical')}
        />
        <AttentionCard label="High" value={high} tone="high" onClick={() => onSelectSeverity('high')} />
        <AttentionCard
          label="Lic. violations"
          value={denied}
          tone={denied > 0 ? 'medium' : 'neutral'}
          onClick={() => onGoTab('licenses')}
        />
        <AttentionCard
          label="Pkgs at risk"
          value={componentsAtRisk}
          tone={componentsAtRisk > 0 ? 'low' : 'neutral'}
          onClick={() => onGoTab('components')}
        />
      </div>

      {/* Right 5 cols: Findings by Severity (Activity Gauge) */}
      <div className="lg:col-span-5">
        <VulnDistribution
          findings={findings}
          loading={loading}
          onSelectSeverity={onSelectSeverity}
        />
      </div>
    </div>
  )
}

const RING_RADII = [118, 104, 90, 76, 62]
const RING_STROKE_WIDTH = 6

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
      sev === 'low'
        ? 'bg-utility-blue-500'
        : sev === 'info'
          ? 'bg-utility-gray-400'
          : sevBg[sev] ?? 'bg-secondary',
    stroke:
      sev === 'low'
        ? 'text-utility-blue-500'
        : sev === 'info'
          ? 'text-utility-gray-400'
          : sevText[sev] ?? 'text-tertiary',
  }))
  const total = findings.length
  const maxVal = Math.max(...counts.map((c) => c.count), 1)

  return (
    <div className="flex flex-col items-center justify-between gap-4 h-full py-1">
      {/* Activity Rings Graphic */}
      <div className="relative flex items-center justify-center pt-2">
        <svg
          viewBox="0 0 260 260"
          className="size-56 sm:size-60"
          aria-label={`Findings by severity activity gauge: ${total} total findings`}
        >
          {counts.map(({ sev, count, stroke }, idx) => {
            const r = RING_RADII[idx]
            const circumference = 2 * Math.PI * r
            // Scale arc so the peak severity fills ~85% of the circle, showing clear progression
            const ratio = count > 0 ? (count / maxVal) * 0.85 : 0
            const strokeDash = count > 0 ? Math.max(circumference * 0.04, circumference * ratio) : 0

            return (
              <g key={sev} className="transition-all duration-500">
                {/* Background track ring - subtle and light */}
                <circle
                  cx="130"
                  cy="130"
                  r={r}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={RING_STROKE_WIDTH}
                  className="text-secondary/20 dark:text-secondary/35"
                />
                {/* Value arc */}
                {count > 0 && (
                  <circle
                    cx="130"
                    cy="130"
                    r={r}
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={RING_STROKE_WIDTH}
                    strokeLinecap="round"
                    strokeDasharray={`${strokeDash} ${circumference}`}
                    strokeDashoffset={0}
                    className={cn('transition-all duration-700 ease-out', stroke)}
                    transform="rotate(-90 130 130)"
                  />
                )}
              </g>
            )
          })}
        </svg>

        {/* Center Total Counter */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xs font-semibold uppercase tracking-wider text-tertiary">Total</span>
          <span className="font-mono text-4xl font-bold tabular-nums text-primary mt-1">{total}</span>
        </div>
      </div>

      {/* Legend Rows at Bottom */}
      <div className="flex w-full flex-wrap items-center justify-center gap-2 border-t border-secondary/60 pt-3">
        {counts.map(({ sev, count, dot, label }) => (
          <button
            key={sev}
            type="button"
            onClick={() => onSelectSeverity(sev)}
            disabled={count === 0}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
              count > 0
                ? 'cursor-pointer text-secondary hover:bg-secondary hover:text-primary'
                : 'cursor-default text-quaternary opacity-40',
            )}
            title={`${count} ${label} findings`}
          >
            <span className={cn('size-2 shrink-0 rounded-full ring-[0.5px] ring-black/10 ring-inset', dot)} />
            <span className="text-xs font-medium capitalize">{label}</span>
            <span className="font-mono text-xs font-semibold tabular-nums text-primary">{count}</span>
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
    <Card title="Findings by severity" className="h-full">
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
  tone: 'critical' | 'high' | 'medium' | 'low' | 'neutral'
  onClick: () => void
}) {
  const zero = value === 0

  const toneConfig = {
    critical: {
      bar: 'bg-critical',
      text: 'text-critical',
      chevron: 'text-critical/60 group-hover:text-critical',
      hoverBorder: 'hover:border-critical/40',
    },
    high: {
      bar: 'bg-high',
      text: 'text-high',
      chevron: 'text-high/60 group-hover:text-high',
      hoverBorder: 'hover:border-high/40',
    },
    medium: {
      bar: 'bg-medium',
      text: 'text-medium',
      chevron: 'text-medium/60 group-hover:text-medium',
      hoverBorder: 'hover:border-medium/40',
    },
    low: {
      bar: 'bg-utility-blue-500',
      text: 'text-utility-blue-500',
      chevron: 'text-utility-blue-500/60 group-hover:text-utility-blue-500',
      hoverBorder: 'hover:border-utility-blue-500/40',
    },
    neutral: {
      bar: 'bg-secondary',
      text: 'text-primary',
      chevron: 'text-quaternary group-hover:text-primary',
      hoverBorder: 'hover:border-primary',
    },
  }[tone]

  const valText = zero ? 'text-quaternary' : toneConfig.text
  const labelText = zero ? 'text-tertiary' : toneConfig.text

  return (
    <button
      onClick={onClick}
      className={cn(
        'group relative flex flex-1 flex-col justify-between overflow-hidden rounded-xl border border-secondary bg-primary px-4 py-3 text-left shadow-xs transition-all',
        toneConfig.hoverBorder,
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
      )}
    >
      <div className={cn('absolute inset-x-0 top-0 h-0.5', toneConfig.bar)} />
      <div className="flex items-center justify-between">
        <span className={cn('truncate text-xs font-semibold', labelText)}>{label}</span>
        <ChevronRight
          className={cn('size-3.5 shrink-0 transition-transform group-hover:translate-x-0.5', toneConfig.chevron)}
        />
      </div>
      <div className="my-auto flex items-center justify-center py-1">
        <span className={cn('font-mono text-4xl font-bold tracking-tight tabular-nums', valText)}>{value}</span>
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
    if (v.unversioned) continue // first-party historical: not a remediation target
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
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ring-1 ring-inset',
        sev === 'critical' ? 'bg-critical/10 text-critical ring-critical/25' : 'bg-high/10 text-high ring-high/25',
      )}
    >
      {n} {sev === 'critical' ? 'crit' : 'high'}
    </span>
  )
}



/* ==========================================================================
   ZONE 3: Composition + Provenance (1 card 3-column)
   ========================================================================== */

export function CompositionProvenanceCard({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const langs = scan.languages.slice().sort((a, b) => b.percent - a.percent)
  const m = scan.manifest

  return (
    <Card title="Composition & Provenance">
      <div className="grid grid-cols-1 divide-y divide-secondary lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
        {/* Col 1: Languages (4 cols) */}
        <div className="pb-4 lg:col-span-4 lg:pb-0 lg:pr-6">
          <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-wide text-tertiary">Languages</div>
          {langs.length === 0 ? (
            <p className="text-sm text-quaternary">No source languages detected.</p>
          ) : (
            <div className="space-y-2">
              {langs.slice(0, 6).map((l) => (
                <div key={l.name} className="flex items-center gap-2 text-sm">
                  <Code01 className="size-3.5 text-tertiary" />
                  <span className="flex-1 text-primary">{l.name}</span>
                  <span className="font-mono text-xs tabular-nums text-tertiary">{l.percent.toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Col 2: Package / License / Edge Counts (3 cols) */}
        <div className="py-4 lg:col-span-3 lg:py-0 lg:px-5">
          <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-wide text-tertiary">Inventory Counts</div>
          <div className="grid grid-cols-3 gap-2">
            <CompTile
              icon={Package}
              label="packages"
              value={scan.components.length}
              onClick={() => onGoTab('components')}
            />
            <CompTile
              icon={Scale01}
              label="licenses"
              value={scan.licenses.length}
              onClick={() => onGoTab('licenses')}
            />
            <CompTile
              icon={Dataflow03}
              label="dep. edges"
              value={countEdges(scan)}
              onClick={() => onGoTab('graph')}
            />
          </div>
        </div>

        {/* Col 3: Tool Versions + Vuln DB + SBOM Sha (5 cols) */}
        <div className="pt-4 lg:col-span-5 lg:pt-0 lg:pl-6">
          <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-wide text-tertiary">
            <span>Tool Versions & Integrity</span>
          </div>
          <div className="space-y-1.5 text-sm">
            {Object.entries(scan.toolVersions).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between gap-3 border-b border-secondary/60 pb-1">
                <span className="flex items-center gap-1.5 text-xs text-tertiary">
                  <Tool01 className="size-3 text-quaternary" />
                  {k}
                </span>
                <span className="truncate font-mono text-xs tabular-nums text-primary">{v}</span>
              </div>
            ))}
            <div className="flex items-center justify-between gap-3 border-b border-secondary/60 pb-1">
              <span className="flex items-center gap-1.5 text-xs text-tertiary">
                <Database01 className="size-3 text-quaternary" />
                vuln DB
              </span>
              <span className="truncate font-mono text-xs text-primary">{scan.vulnDBSnapshot || '–'}</span>
            </div>
            {m.sbomSha256 && (
              <div className="flex items-center justify-between gap-3 border-b border-secondary/60 pb-1">
                <span className="flex items-center gap-1.5 text-xs text-tertiary">
                  <File06 className="size-3 text-quaternary" />
                  SBOM sha
                </span>
                <span className="truncate font-mono text-xs text-primary" title={m.sbomSha256}>
                  {m.sbomSha256.slice(0, 12)}
                </span>
              </div>
            )}
            {(m.pinnedInputs.length > 0 || m.unpinnedInputs.length > 0) && (
              <div className="pt-1 text-[11px] text-tertiary">
                {m.pinnedInputs.length > 0 && (
                  <div>
                    pinned: <span className="font-mono text-primary">{m.pinnedInputs.join(', ')}</span>
                  </div>
                )}
                {m.unpinnedInputs.length > 0 && (
                  <div className="mt-0.5">
                    live: <span className="font-mono text-medium">{m.unpinnedInputs.join(', ')}</span>
                  </div>
                )}
              </div>
            )}
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
  onClick,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  value: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center justify-center gap-1 rounded-lg border border-secondary bg-primary py-3 transition-colors hover:border-primary hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
    >
      <Icon className="size-4 text-tertiary" />
      <span className="font-mono text-lg font-semibold tabular-nums text-primary">{value}</span>
      <span className="text-[11px] text-tertiary">{label}</span>
    </button>
  )
}



export function CardEmpty({ icon: Icon, text }: { icon: ComponentType<{ className?: string }>; text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Icon className="size-6 text-quaternary" />
      <p className="text-sm text-tertiary">{text}</p>
    </div>
  )
}
