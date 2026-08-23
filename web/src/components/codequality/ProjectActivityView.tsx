import { Activity, ArrowDownRight, ArrowRight, ArrowUpRight, ChevronDown, GitCommit } from 'lucide-react'
import { useState } from 'react'
import type { ProjectAnalysis } from '../../lib/types'
import { Button, Card, EmptyState, Pill, Select, cn } from '../ui'
import { GateEvidence, GateStatus, gradeNumber, metricLabel } from './qualityPresentation'

type Mode = 'overall' | 'new'
type MetricKey = 'issues' | 'security' | 'reliability' | 'maintainability' | 'duplication' | 'coverage' | 'critical' | 'high'
type Props = { analyses: ProjectAnalysis[]; hasOlder?: boolean; loadingOlder?: boolean; onLoadOlder?: () => void }
const overallMetrics: { value: MetricKey; label: string }[] = [{ value: 'issues', label: 'Total issues' }, { value: 'security', label: 'Security rating' }, { value: 'reliability', label: 'Reliability rating' }, { value: 'maintainability', label: 'Maintainability rating' }, { value: 'duplication', label: 'Duplication density' }, { value: 'coverage', label: 'Line coverage' }]
const newMetrics: { value: MetricKey; label: string }[] = [{ value: 'issues', label: 'New issues' }, { value: 'critical', label: 'New critical' }, { value: 'high', label: 'New high' }, { value: 'security', label: 'New Code security rating' }, { value: 'reliability', label: 'New Code reliability rating' }]

export function ProjectActivityView({ analyses, hasOlder = false, loadingOlder = false, onLoadOlder }: Props) {
  const [mode, setMode] = useState<Mode>('overall'); const [metric, setMetric] = useState<MetricKey>('issues'); const [expanded, setExpanded] = useState<string | null>(analyses[0]?.id ?? null)
  if (analyses.length === 0) return <Card title="Activity"><EmptyState icon={Activity} title="No analysis history yet" hint="Each successful analysis will appear here as an immutable decision record." /></Card>
  const options = mode === 'overall' ? overallMetrics : newMetrics
  const chronological = [...analyses].reverse()
  const points = chronological.map((analysis) => pointOf(analysis, mode, metric)).filter((point): point is TrendPoint => point !== null)
  const latestPoint = pointOf(analyses[0], mode, metric); const previousPoint = pointOf(analyses[1], mode, metric)
  const direction = latestPoint && previousPoint ? trendDirection(latestPoint.value, previousPoint.value, metric) : null
  function changeMode(next: Mode) { setMode(next); setMetric('issues') }
  return <section className="space-y-6" aria-label="Project activity">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><h2 className="text-xl font-semibold text-primary">Analysis activity</h2><p className="mt-1 max-w-2xl text-sm text-tertiary">Audit immutable gate decisions and compare each successful analysis with its immediate predecessor.</p></div><div className="flex rounded-lg border border-secondary bg-secondary p-1" aria-label="Activity scope"><ScopeButton active={mode === 'overall'} onClick={() => changeMode('overall')}>Overall</ScopeButton><ScopeButton active={mode === 'new'} onClick={() => changeMode('new')}>New Code</ScopeButton></div></div>
    <Card title="Quality trend" actions={direction && <DirectionBadge direction={direction} />}><div className="mb-4 max-w-xs"><Select value={metric} onValueChange={(value) => setMetric(value as MetricKey)} ariaLabel="Trend metric" options={options} /></div>{metric === 'coverage' && points.length === 0 ? <p className="rounded-lg border border-dashed border-secondary bg-primary px-4 py-6 text-sm text-tertiary">Line coverage is unavailable because no coverage artifact was supplied.</p> : ['security', 'reliability', 'maintainability'].includes(metric) && points.length === 0 ? <p className="rounded-lg border border-dashed border-secondary bg-primary px-4 py-6 text-sm text-tertiary">Rating is unavailable because the analysis did not provide a grade.</p> : <Trend metric={metric} points={points} />}{mode === 'overall' && metric !== 'coverage' && !analyses.some((analysis) => analysis.coverage) && <p className="mt-4 text-sm text-tertiary">Line coverage is unavailable because no coverage artifact was supplied.</p>}</Card>
    <Card title="Analysis timeline" actions={<Pill>{analyses.length} loaded</Pill>} bodyClass="p-0"><ol className="divide-y divide-secondary">{analyses.map((analysis, index) => { const open = expanded === analysis.id; const first = index === analyses.length - 1 && !hasOlder; return <li key={analysis.id}><button type="button" className="flex w-full flex-wrap items-center justify-between gap-4 px-5 py-4 text-left hover:bg-secondary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/60" aria-expanded={open} onClick={() => setExpanded(open ? null : analysis.id)}><div className="flex min-w-0 items-start gap-3"><span className={cn('mt-1 inline-flex size-8 shrink-0 items-center justify-center rounded-full border', analysis.gate.passed ? 'border-low/25 bg-low/10 text-low' : 'border-critical/25 bg-critical/10 text-critical')}><GitCommit className="size-4" aria-hidden="true" /></span><div className="min-w-0"><div className="font-medium text-primary">{formatDate(analysis.createdAt)} {first && <span className="ml-1 text-xs font-normal text-tertiary">· first analysis</span>}</div><div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-tertiary"><span>{analysis.sourceRef || 'source ref unavailable'}</span>{analysis.sourceCommit && <span>{analysis.sourceCommit.slice(0, 12)}</span>}<span>· {analysis.gateInfo.name || 'Quality gate'}</span></div></div></div><div className="flex items-center gap-3"><GateStatus passed={analysis.gate.passed} /><ChevronDown className={cn('size-4 text-tertiary transition-transform', open && 'rotate-180')} aria-hidden="true" /></div></button>{open && <div className="border-t border-secondary bg-secondary/20 px-5 py-5"><div className="grid gap-5 xl:grid-cols-[1.15fr_1fr]"><GateEvidence compact gate={analysis.gate} info={analysis.gateInfo} /><div><h3 className="font-semibold text-primary">Changes in this analysis</h3><div className="mt-4 grid grid-cols-2 gap-3"><AuditMetric label="Total issues" value={analysis.issues.total} delta={analysis.delta?.issues.total} /><AuditMetric label="New issues" value={analysis.newCode.counts.total} /><AuditMetric label="New critical" value={analysis.newCode.counts.bySeverity.critical ?? 0} /><AuditMetric label="New high" value={analysis.newCode.counts.bySeverity.high ?? 0} /></div>{analysis.delta ? <p className="mt-3 text-xs text-tertiary">Signed changes are compared with analysis {analysis.newCode.previousId.slice(0, 12)}.</p> : <p className="mt-3 text-xs text-tertiary">Baseline analysis: no previous successful result exists, so no delta is shown.</p>}</div></div></div>}</li> })}</ol>{hasOlder && onLoadOlder && <div className="border-t border-secondary p-4 text-center"><Button variant="secondary" loading={loadingOlder} disabled={loadingOlder} onClick={onLoadOlder}>Load older analyses</Button></div>}</Card>
  </section>
}

type TrendPoint = { id: string; label: string; commit: string; value: number; display: string }
function pointOf(analysis: ProjectAnalysis | undefined, mode: Mode, metric: MetricKey): TrendPoint | null {
  if (!analysis) return null
  const rating = mode === 'overall' ? analysis.rating : analysis.newCode.rating; let value: number; let display: string
  switch (metric) {
    case 'issues': value = mode === 'overall' ? analysis.issues.total : analysis.newCode.counts.total; display = value.toLocaleString(); break
    case 'critical': value = analysis.newCode.counts.bySeverity.critical ?? 0; display = value.toLocaleString(); break
    case 'high': value = analysis.newCode.counts.bySeverity.high ?? 0; display = value.toLocaleString(); break
    case 'security': { const grade = gradeNumber(rating.security); if (grade === undefined) return null; value = grade; display = rating.security; break }
    case 'reliability': { const grade = gradeNumber(rating.reliability); if (grade === undefined) return null; value = grade; display = rating.reliability; break }
    case 'maintainability': { const maintainability = mode === 'new' ? analysis.newCode.rating.maintainability : analysis.rating.maintainability; if (!maintainability) return null; const grade = gradeNumber(maintainability); if (grade === undefined) return null; value = grade; display = maintainability; break }
    case 'duplication': if (!analysis.duplication) return null; value = analysis.duplication.totalLines ? 100 * analysis.duplication.duplicatedLines / analysis.duplication.totalLines : 0; display = `${value.toFixed(1)}%`; break
    case 'coverage': if (!analysis.coverage) return null; value = analysis.coverage.totalLines ? 100 * analysis.coverage.coveredLines / analysis.coverage.totalLines : 0; display = `${value.toFixed(1)}%`; break
  }
  return { id: analysis.id, label: formatDate(analysis.createdAt), commit: analysis.sourceCommit.slice(0, 12), value, display }
}

function Trend({ metric, points }: { metric: MetricKey; points: TrendPoint[] }) {
  const width = 760; const height = 180; const grade = ['security', 'reliability', 'maintainability'].includes(metric); const values = points.map((point) => point.value); const min = grade ? 1 : Math.min(0, ...values); const max = grade ? 5 : Math.max(1, ...values); const range = Math.max(1, max - min); const coords = points.map((point, index) => ({ x: points.length === 1 ? width / 2 : 18 + index * (width - 36) / (points.length - 1), y: height - 18 - ((point.value - min) / range) * (height - 36) }))
  const title = grade ? `${metricLabel(`${metric}_rating`)} (A is best)` : metricLabel(metric === 'duplication' ? 'duplication_density' : metric === 'coverage' ? 'coverage' : metric)
  return <div><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} trend`} className="h-52 w-full overflow-visible"><title>{title} trend</title>{coords.length > 1 && <polyline fill="none" stroke="currentColor" strokeWidth="3" points={coords.map((point) => `${point.x},${point.y}`).join(' ')} className="text-brand" />}{coords.map((point, index) => <circle key={points[index].id} cx={point.x} cy={point.y} r="6" fill="currentColor" className="text-brand"><title>{points[index].label}: {points[index].display}{points[index].commit ? ` · ${points[index].commit}` : ''}</title></circle>)}</svg><div className="overflow-x-auto"><table className="w-full min-w-[36rem] text-left text-xs"><thead><tr className="border-b border-secondary text-quaternary"><th className="pb-2 font-medium">Analysis</th>{points.map((point) => <th key={point.id} className="pb-2 text-right font-medium">{shortDate(point.label)}</th>)}</tr></thead><tbody><tr><th className="pt-2 font-medium text-tertiary">{title}</th>{points.map((point) => <td key={point.id} className="pt-2 text-right font-mono tabular-nums text-primary">{point.display}</td>)}</tr></tbody></table></div></div>
}

type Direction = 'improving' | 'regressing' | 'unchanged'
function trendDirection(current: number, previous: number, metric: MetricKey): Direction { if (current === previous) return 'unchanged'; const lowerIsBetter = metric !== 'coverage'; return (lowerIsBetter ? current < previous : current > previous) ? 'improving' : 'regressing' }
function DirectionBadge({ direction }: { direction: Direction }) { const meta = direction === 'improving' ? { icon: ArrowDownRight, label: 'Improving', cls: 'text-low bg-low/10' } : direction === 'regressing' ? { icon: ArrowUpRight, label: 'Regressing', cls: 'text-critical bg-critical/10' } : { icon: ArrowRight, label: 'Unchanged', cls: 'text-tertiary bg-secondary' }; const Icon = meta.icon; return <Pill className={meta.cls}><Icon className="size-3" aria-hidden="true" />{meta.label}</Pill> }
function ScopeButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'rounded-md px-3 py-1.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
        active ? 'bg-primary text-brand-secondary shadow-xs' : 'text-tertiary hover:text-primary',
      )}
    >
      {children}
    </button>
  )
}
function AuditMetric({ label, value, delta }: { label: string; value: number; delta?: number }) { return <div className="rounded-lg border border-secondary bg-primary px-3 py-2 shadow-xs"><div className="font-mono tabular-nums text-lg font-semibold text-primary">{value.toLocaleString()}</div><div className="text-xs text-tertiary">{label}</div>{delta !== undefined && <div className="mt-1 tabular-nums text-[10px] text-quaternary">{delta > 0 ? '+' : ''}{delta} vs previous</div>}</div> }
function formatDate(value: string) { return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) }
function shortDate(formatted: string) { return formatted.split(',')[0] }
