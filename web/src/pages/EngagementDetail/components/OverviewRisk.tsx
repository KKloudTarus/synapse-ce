import { CheckCircle, ChevronRight } from '@untitledui/icons'
import { useMemo } from 'react'
import { Card, Pill, SevBadge, Spinner, cn } from '../../../components/ui'
import { sevRank } from '../../../lib/severity'
import type { Finding, ScanResult, Severity } from '../../../lib/types'
import type { Tab } from '../index'
import { CardEmpty } from './OverviewComposition'

const RING_RADII = [114, 100, 86, 72, 58]
const RING_STROKE_WIDTH = 7

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
              : 'bg-utility-neutral-600',
    // SVG stroke as a semantic utility class (same ramp as `dot`), so it remaps in dark mode instead of a
    // hardcoded hex.
    strokeClass:
      sev === 'critical'
        ? 'stroke-utility-red-600'
        : sev === 'high'
          ? 'stroke-utility-orange-600'
          : sev === 'medium'
            ? 'stroke-utility-yellow-600'
            : sev === 'low'
              ? 'stroke-utility-blue-600'
              : 'stroke-utility-neutral-600',
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
          {counts.map(({ sev, count, strokeClass }, idx) => {
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
                  strokeWidth={RING_STROKE_WIDTH}
                  className="stroke-utility-neutral-100"
                />
                {/* Value arc */}
                {count > 0 && (
                  <circle
                    cx="130"
                    cy="130"
                    r={r}
                    fill="none"
                    className={strokeClass}
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
