import { CheckCircle2, XCircle } from 'lucide-react'
import type { Grade, ProjectGateInfo, ProjectGateResult } from '../../lib/types'
import { Pill, cn } from '../ui'

export const metricLabels: Record<string, string> = {
  new_critical: 'New critical issues', new_high: 'New high issues', new_medium: 'New medium issues', new_secret: 'New secrets',
  new_vulnerability: 'New vulnerabilities', new_issues: 'New issues', total_critical: 'Total critical issues', coverage: 'Line coverage',
  duplication_density: 'Duplication density', security_rating: 'Security rating', reliability_rating: 'Reliability rating', maintainability_rating: 'Maintainability rating',
  security_hotspots_reviewed: 'Security Hotspots Reviewed', new_security_hotspots_reviewed: 'New Security Hotspots Reviewed',
  new_coverage: 'New Code coverage', new_duplication: 'New Code duplication',
}

export function metricLabel(metric: string) { return metricLabels[metric] ?? metric.replaceAll('_', ' ') }
export function metricValue(metric: string, value: number) {
  if (metric === 'coverage' || metric === 'duplication_density' || metric.endsWith('_reviewed')) return `${value.toFixed(1)}%`
  if (metric.endsWith('_rating')) return gradeFromNumber(value)
  return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2)
}
export function gradeFromNumber(value: number): Grade { return (['A', 'B', 'C', 'D', 'E'][Math.min(5, Math.max(1, Math.round(value))) - 1] ?? 'E') as Grade }
export function gradeNumber(grade: Grade) { return grade === '?' ? undefined : ({ A: 1, B: 2, C: 3, D: 4, E: 5 })[grade] }
export function gradeTone(grade: Grade) { return grade === 'A' || grade === 'B' ? 'border-low/25 bg-low/10 text-low' : grade === 'C' ? 'border-medium/25 bg-medium/10 text-medium' : grade === '?' ? 'border-border bg-elevated text-mutedfg' : 'border-critical/25 bg-critical/10 text-critical' }

export function GradeBadge({ label, grade, compact = false }: { label: string; grade: Grade; compact?: boolean }) {
  return <div className={cn('flex items-center gap-3 rounded-lg border border-border bg-bg', compact ? 'px-3 py-2' : 'px-4 py-3')}><span className={cn('inline-flex shrink-0 items-center justify-center rounded-lg border font-mono font-semibold', compact ? 'size-9 text-lg' : 'size-12 text-2xl', gradeTone(grade))} aria-label={`${label} rating ${grade}`}>{grade}</span><div className="min-w-0"><div className="truncate text-sm font-medium">{label}</div><div className="text-xs text-mutedfg">Grade {grade}</div></div></div>
}

export function GateStatus({ passed }: { passed: boolean }) {
  return <Pill className={passed ? 'bg-low/15 text-low ring-1 ring-inset ring-low/20' : 'bg-critical/15 text-critical ring-1 ring-inset ring-critical/20'}>{passed ? <CheckCircle2 className="size-3" aria-hidden="true" /> : <XCircle className="size-3" aria-hidden="true" />}{passed ? 'Gate passed' : 'Gate failed'}</Pill>
}

export function GateEvidence({ gate, info, compact = false }: { gate: ProjectGateResult; info: ProjectGateInfo; compact?: boolean }) {
  const results = [...gate.results].sort((a, b) => Number(a.passed) - Number(b.passed))
  return <div>
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="font-semibold">{info.name || 'Quality gate'}</h3><p className="mt-0.5 text-xs capitalize text-mutedfg">{info.source ? `${info.source} policy` : 'Recorded policy'}{info.key ? ` · ${info.key}` : ''}</p></div><GateStatus passed={gate.passed} /></div>
    <ul className={cn('mt-4 grid gap-2', compact ? 'grid-cols-1' : 'md:grid-cols-2')}>
      {results.map((result, index) => <li key={`${result.condition.metric}-${index}`} className={cn('rounded-lg border px-3 py-2.5', result.passed ? 'border-border bg-bg' : 'border-critical/30 bg-critical/5')}><div className="flex items-start justify-between gap-3"><div><div className="text-sm font-medium">{metricLabel(result.condition.metric)}</div><div className="mt-1 font-mono tabular-nums text-xs text-mutedfg">actual {metricValue(result.condition.metric, result.actual)} {result.condition.op} threshold {metricValue(result.condition.metric, result.condition.threshold)}</div></div>{result.passed ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-low" aria-label="Passed" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-critical" aria-label="Failed" />}</div></li>)}
    </ul>
  </div>
}
