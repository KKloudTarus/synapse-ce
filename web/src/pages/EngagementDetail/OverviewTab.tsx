import { Bot, Boxes, Bug, CalendarClock, CheckCircle2, ChevronRight, Clock, Code2, Database, FileClock, Gauge, GaugeCircle, LayoutDashboard, Network, Radar, Scale, ShieldAlert, ShieldCheck, ShieldQuestion, SlidersHorizontal, Waypoints, Wrench } from 'lucide-react'
import { ReactNode, useMemo } from 'react'
import { Card, EmptyState, Pill, SevBadge, Spinner, cn } from '../../components/ui'
import { SEVERITY_ORDER, sevFill, sevRank, sevText } from '../../lib/severity'
import type { Finding, ScanJob, ScanResult, Severity } from '../../lib/types'
import { countEdges, fmtDuration } from './VulnsTab'
import type { Tab } from './index'

export const TABS: { id: Tab; label: string; icon: typeof LayoutDashboard; countKey?: keyof TabCounts }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: ShieldAlert, countKey: 'findings' },
  { id: 'sla', label: 'Remediation SLA', icon: CalendarClock },
  { id: 'components', label: 'Packages', icon: Boxes, countKey: 'components' },
  { id: 'vulns', label: 'Vulnerabilities', icon: Bug, countKey: 'vulns' },
  { id: 'licenses', label: 'Licenses', icon: Scale, countKey: 'licenses' },
  { id: 'graph', label: 'Graph', icon: Network },
  { id: 'threats', label: 'Threat Model', icon: Waypoints },
  { id: 'quality', label: 'Code Quality', icon: Gauge },
  { id: 'recon', label: 'Recon', icon: Radar },
  { id: 'agent', label: 'Agent', icon: Bot },
  { id: 'reviews', label: 'Awaiting review', icon: ShieldQuestion },
  { id: 'evidence', label: 'Evidence', icon: ShieldCheck },
  { id: 'settings', label: 'Settings', icon: SlidersHorizontal },
]

export interface TabCounts {
  findings: number
  components: number
  vulns: number
  licenses: number
}

export function TabBar({ tab, setTab, counts }: { tab: Tab; setTab: (t: Tab) => void; counts: TabCounts }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-border">
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
              active ? 'border-brand text-foreground' : 'border-transparent text-mutedfg hover:text-foreground',
            )}
          >
            <Icon className="size-4" />
            {label}
            {count !== undefined && count > 0 && (
              <span className="rounded-full bg-brand/15 px-1.5 text-xs font-medium tabular-nums text-branddim">
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
        icon={LayoutDashboard}
        title="No scan yet"
        hint="Run a scan above – this overview will show what’s risky, what to fix first, and where it came from."
      />
    )
  }
  const open = findings ?? []
  return (
    <div className="space-y-6">
      <ScanHealth scan={scan} job={job} />
      <FindingQualityStrip scan={scan} />
      <WhatNeedsAttention findings={open} scan={scan} onSelectSeverity={onSelectSeverity} onGoTab={onGoTab} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RemediationTargets scan={scan} onGoTab={onGoTab} />
        <VulnDistribution findings={open} loading={findings === null} onSelectSeverity={onSelectSeverity} />
      </div>
      <ProjectComposition scan={scan} onGoTab={onGoTab} />
      <ProvenanceCard scan={scan} />
    </div>
  )
}

export function FindingQualityStrip({ scan }: { scan: ScanResult }) {
  const q = scan.findingQuality
  if (q.rawFindings === 0) return null
  const byP = q.byPriority || {}
  return (
    <Card title="Finding quality">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <QualityTile label="Raw findings" value={q.rawFindings} />
        <QualityTile label="Actionable" value={q.actionable} accent />
        <QualityTile label="Background" value={q.background} muted />
        <QualityTile label="Production" value={q.production} />
        <QualityTile label="Development" value={q.development} muted />
        <QualityTile label="Example/Test" value={q.exampleTest} muted />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-mutedfg">
        <span>Risk priority:</span>
        {[1, 2, 3, 4, 5].map((p) =>
          byP[String(p)] ? (
            <span key={p} className="font-mono tabular-nums">
              <span className={cn('font-semibold', p <= 2 ? 'text-critical' : p === 3 ? 'text-medium' : 'text-subtlefg')}>
                P{p}
              </span>
              : {byP[String(p)]}
            </span>
          ) : null,
        )}
        <span className="text-subtlefg">
          · version cov {q.versionCoveragePct.toFixed(0)}% · path cov {q.pathCoveragePct.toFixed(0)}%
        </span>
      </div>
    </Card>
  )
}

export function QualityTile({ label, value, accent, muted }: { label: string; value: number; accent?: boolean; muted?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-bg py-2.5 text-center">
      <div
        className={cn(
          'font-mono text-xl font-semibold tabular-nums',
          accent ? 'text-accent' : muted ? 'text-subtlefg' : 'text-foreground',
        )}
      >
        {value}
      </div>
      <div className="text-[11px] text-mutedfg">{label}</div>
    </div>
  )
}

export function ScanHealth({ scan, job }: { scan: ScanResult; job: ScanJob | null }) {
  const status = job?.status ?? 'succeeded'
  const statusLabelText = status === 'running' ? 'Running' : status === 'failed' ? 'Failed' : 'Complete'
  const statusTone = status === 'running' ? 'brand' : status === 'failed' ? 'critical' : 'accent'
  const confident = scan.completeness.confident
  const source = (scan.vulnDBSnapshot.split('@')[0] || 'osv.dev').replace(/\.dev$/, '').toUpperCase()
  return (
    <Card title="Scan health" bodyClass="p-0">
      <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-3 lg:grid-cols-5 lg:divide-y-0">
        <HealthStat icon={CheckCircle2} label="Status" value={statusLabelText} tone={statusTone} />
        <HealthStat
          icon={Clock}
          label="Duration"
          value={status === 'running' ? 'in progress' : fmtDuration(job?.startedAt ?? null, job?.finishedAt ?? null)}
        />
        <HealthStat
          icon={GaugeCircle}
          label="Confidence"
          value={confident ? 'High' : 'Partial'}
          tone={confident ? 'accent' : 'medium'}
        />
        <HealthStat
          icon={FileClock}
          label="Lockfiles"
          value={scan.completeness.lockfiles.length || '0'}
          tone={scan.completeness.lockfiles.length === 0 ? 'medium' : undefined}
          hint={scan.completeness.lockfiles.join(', ')}
        />
        <HealthStat icon={Database} label="Sources" value={source} />
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
  icon: typeof Clock
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
            ? 'text-brand'
            : 'text-foreground'
  return (
    <div className="px-5 py-4" title={hint ?? (typeof value === 'string' ? value : undefined)}>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-mutedfg">
        <Icon className="size-3.5" />
        {label}
      </div>
      <div className={cn('mt-1 truncate text-lg font-semibold tabular-nums', toneText)}>{value}</div>
    </div>
  )
}

export function WhatNeedsAttention({
  findings,
  scan,
  onSelectSeverity,
  onGoTab,
}: {
  findings: Finding[]
  scan: ScanResult
  onSelectSeverity: (s: Severity | 'all') => void
  onGoTab: (t: Tab) => void
}) {
  // Count only actionable third-party findings – first-party historical advisories
  // (unversioned own modules) never inflate the headline risk.
  const tp = findings.filter((f) => f.class !== 'first_party_historical')
  const critical = tp.filter((f) => f.severity === 'critical').length
  const high = tp.filter((f) => f.severity === 'high').length
  const denied = scan.licenses.filter((l) => l.verdict === 'deny').length
  const componentsAtRisk = new Set(
    scan.vulnerabilities.filter((v) => !v.unversioned).map((v) => v.component),
  ).size
  return (
    <section>
      <h2 className="mb-3 text-sm font-semibold text-foreground">What needs attention</h2>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <AttentionCard
          label="Critical findings"
          value={critical}
          tone="critical"
          onClick={() => onSelectSeverity('critical')}
        />
        <AttentionCard label="High findings" value={high} tone="high" onClick={() => onSelectSeverity('high')} />
        <AttentionCard
          label="License violations"
          value={denied}
          tone={denied > 0 ? 'critical' : 'neutral'}
          onClick={() => onGoTab('licenses')}
        />
        <AttentionCard
          label="Packages at risk"
          value={componentsAtRisk}
          tone="neutral"
          onClick={() => onGoTab('components')}
        />
      </div>
    </section>
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
  tone: 'critical' | 'high' | 'neutral'
  onClick: () => void
}) {
  const zero = value === 0
  const accentBar = tone === 'critical' ? 'bg-critical' : tone === 'high' ? 'bg-high' : 'bg-border'
  const valText = zero
    ? 'text-subtlefg'
    : tone === 'critical'
      ? 'text-critical'
      : tone === 'high'
        ? 'text-high'
        : 'text-foreground'
  return (
    <button
      onClick={onClick}
      className={cn(
        'lift elev group relative overflow-hidden rounded-xl border border-border bg-card p-4 text-left transition-colors hover:border-borderstrong',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
      )}
    >
      <div className={cn('absolute inset-x-0 top-0 h-0.5', accentBar)} />
      <div className="flex items-center justify-between">
        <span className="text-xs text-mutedfg">{label}</span>
        <ChevronRight className="size-4 text-subtlefg transition-transform group-hover:translate-x-0.5" />
      </div>
      <div className={cn('mt-2 font-mono text-3xl font-semibold tabular-nums', valText)}>{value}</div>
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

export function RemediationTargets({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const targets = useMemo(() => remediationTargets(scan), [scan])
  return (
    <Card
      title="Top remediation targets"
      actions={
        targets.length > 0 && (
          <button
            onClick={() => onGoTab('findings')}
            className="rounded text-xs text-branddim transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
          >
            All findings →
          </button>
        )
      }
    >
      {targets.length === 0 ? (
        <CardEmpty icon={CheckCircle2} text="No vulnerable packages – nothing to remediate." />
      ) : (
        <ol className="space-y-2.5">
          {targets.map((t, i) => (
            <li key={t.component} className="flex items-center gap-3">
              <span className="w-4 shrink-0 text-center font-mono text-xs text-subtlefg">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium text-foreground" title={`${t.component}@${t.version}`}>
                    {t.component}
                  </span>
                  {t.hasFix && <Pill className="bg-accent/12 text-accent ring-1 ring-inset ring-accent/25">fix</Pill>}
                </div>
                <div className="mt-0.5 text-xs text-mutedfg">
                  {t.count} finding{t.count === 1 ? '' : 's'}
                  {t.maxEpss > 0 && <span className="text-subtlefg"> · EPSS {(t.maxEpss * 100).toFixed(0)}%</span>}
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
  )
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

export function VulnDistribution({
  findings,
  loading,
  onSelectSeverity,
}: {
  findings: Finding[]
  loading: boolean
  onSelectSeverity: (s: Severity | 'all') => void
}) {
  const rows = SEVERITY_ORDER.map((sev) => ({ sev, count: findings.filter((f) => f.severity === sev).length })).filter(
    (r) => r.count > 0 || ['critical', 'high', 'medium', 'low'].includes(r.sev),
  )
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <Card title="Findings by severity">
      {loading ? (
        <Spinner />
      ) : findings.length === 0 ? (
        <CardEmpty icon={CheckCircle2} text="No findings promoted from this scan." />
      ) : (
        <div className="space-y-2">
          {rows.map(({ sev, count }) => (
            <button
              key={sev}
              onClick={() => onSelectSeverity(sev)}
              disabled={count === 0}
              className={cn(
                'flex w-full items-center gap-3 rounded-md px-1.5 py-1 text-left transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                count > 0 ? 'hover:bg-elevated' : 'cursor-default opacity-60',
              )}
            >
              <span className={cn('w-16 text-[11px] font-semibold uppercase tracking-wide', sevText[sev])}>{sev}</span>
              <div className="h-2 flex-1 overflow-hidden rounded bg-elevated">
                <div className={cn('bar-grow h-full rounded', sevFill[sev])} style={{ width: `${(count / max) * 100}%` }} />
              </div>
              <span className="w-7 text-right font-mono text-sm tabular-nums text-mutedfg">{count}</span>
            </button>
          ))}
        </div>
      )}
    </Card>
  )
}

export function ProjectComposition({ scan, onGoTab }: { scan: ScanResult; onGoTab: (t: Tab) => void }) {
  const langs = scan.languages.slice().sort((a, b) => b.percent - a.percent)
  return (
    <Card title="Project composition">
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-mutedfg">Languages</div>
          {langs.length === 0 ? (
            <p className="text-sm text-subtlefg">No source languages detected.</p>
          ) : (
            <div className="space-y-2">
              {langs.slice(0, 6).map((l) => (
                <div key={l.name} className="flex items-center gap-2 text-sm">
                  <Code2 className="size-3.5 text-mutedfg" />
                  <span className="flex-1">{l.name}</span>
                  <span className="font-mono text-xs tabular-nums text-mutedfg">{l.percent.toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="grid grid-cols-3 gap-2">
          <CompTile icon={Boxes} label="packages" value={scan.components.length} onClick={() => onGoTab('components')} />
          <CompTile icon={Scale} label="licenses" value={scan.licenses.length} onClick={() => onGoTab('licenses')} />
          <CompTile icon={Network} label="dep. edges" value={countEdges(scan)} onClick={() => onGoTab('graph')} />
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
  icon: typeof Boxes
  label: string
  value: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center justify-center gap-1 rounded-lg border border-border bg-bg py-3 transition-colors hover:border-borderstrong hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
    >
      <Icon className="size-4 text-mutedfg" />
      <span className="font-mono text-lg font-semibold tabular-nums text-foreground">{value}</span>
      <span className="text-[11px] text-mutedfg">{label}</span>
    </button>
  )
}

export function ProvenanceCard({ scan }: { scan: ScanResult }) {
  const m = scan.manifest
  const repro = m.reproScore
  const tone = repro >= 85 ? 'text-accent' : repro >= 60 ? 'text-medium' : 'text-critical'
  return (
    <Card title="Provenance & reproducibility">
      {/* Reproducibility score: how much of the result is version-pinned. */}
      <div className="mb-4 flex items-center justify-between rounded-lg border border-border bg-bg p-3">
        <div>
          <div className="text-xs text-mutedfg">Reproducibility</div>
          <div className={cn('font-mono text-2xl font-semibold tabular-nums', tone)}>{repro}%</div>
        </div>
        <div className="max-w-[60%] text-right text-[11px] text-mutedfg">
          {m.pinnedInputs.length > 0 && (
            <div>
              pinned: <span className="text-foreground">{m.pinnedInputs.join(', ')}</span>
            </div>
          )}
          {m.unpinnedInputs.length > 0 && (
            <div className="mt-0.5">
              live: <span className="text-medium">{m.unpinnedInputs.join(', ')}</span>
            </div>
          )}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        {Object.entries(scan.toolVersions).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
            <span className="flex items-center gap-1.5 text-mutedfg">
              <Wrench className="size-3 text-subtlefg" />
              {k}
            </span>
            <span className="truncate font-mono text-xs tabular-nums">{v}</span>
          </div>
        ))}
        <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
          <span className="flex items-center gap-1.5 text-mutedfg">
            <Database className="size-3 text-subtlefg" />
            vuln DB
          </span>
          <span className="truncate font-mono text-xs">{scan.vulnDBSnapshot || '–'}</span>
        </div>
        {m.sbomSha256 && (
          <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5">
            <span className="flex items-center gap-1.5 text-mutedfg">
              <FileClock className="size-3 text-subtlefg" />
              SBOM sha256
            </span>
            <span className="truncate font-mono text-xs" title={m.sbomSha256}>
              {m.sbomSha256.slice(0, 12)}
            </span>
          </div>
        )}
      </div>
    </Card>
  )
}

export function CardEmpty({ icon: Icon, text }: { icon: typeof Boxes; text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Icon className="size-6 text-subtlefg" />
      <p className="text-sm text-mutedfg">{text}</p>
    </div>
  )
}
