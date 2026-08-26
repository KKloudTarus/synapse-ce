import { CheckCircle as CheckCircle2, XCircle } from '@untitledui/icons'
import type { Grade, ProjectGateInfo, ProjectGateResult } from '../../lib/types'
import { Pill, cn } from '../ui'

export const metricLabels: Record<string, string> = {
  new_critical: 'New critical issues',
  new_high: 'New high issues',
  new_medium: 'New medium issues',
  new_secret: 'New secrets',
  new_vulnerability: 'New vulnerabilities',
  new_issues: 'New issues',
  total_critical: 'Total critical issues',
  coverage: 'Line coverage',
  duplication_density: 'Duplication density',
  security_rating: 'Security rating',
  reliability_rating: 'Reliability rating',
  maintainability_rating: 'Maintainability rating',
  security_hotspots_reviewed: 'Security Hotspots Reviewed',
  new_security_hotspots_reviewed: 'New Security Hotspots Reviewed',
  new_coverage: 'New Code coverage',
  new_duplication: 'New Code duplication',
}

export function metricLabel(metric: string) {
  return metricLabels[metric] ?? metric.replaceAll('_', ' ')
}

export function metricValue(metric: string, value: number) {
  if (metric === 'coverage' || metric === 'duplication_density' || metric.endsWith('_reviewed')) {
    return `${value.toFixed(1)}%`
  }
  if (metric.endsWith('_rating')) {
    return gradeFromNumber(value)
  }
  return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2)
}

export function gradeFromNumber(value: number): Grade {
  return (['A', 'B', 'C', 'D', 'E'][Math.min(5, Math.max(1, Math.round(value))) - 1] ?? 'E') as Grade
}

export function gradeNumber(grade: Grade) {
  return grade === '?' ? undefined : { A: 1, B: 2, C: 3, D: 4, E: 5 }[grade]
}

export function gradeTone(grade: Grade) {
  return grade === 'A'
    ? 'border-utility-green-400 bg-success-primary text-success-primary'
    : grade === 'B'
      ? 'border-utility-green-500 bg-success-secondary text-utility-green-600 dark:text-utility-green-400'
      : grade === 'C'
        ? 'border-warning-primary bg-warning-primary text-warning-primary'
        : grade === 'D'
          ? 'border-utility-orange-500 bg-utility-orange-50 text-utility-orange-600 dark:text-utility-orange-400'
          : grade === '?'
            ? 'border-secondary bg-secondary text-tertiary'
            : 'border-error bg-error-primary text-error-primary'
}

export function GradeBadge({
  label,
  grade,
  compact = false,
}: {
  label: string
  grade: Grade
  compact?: boolean
}) {
  return (
    <div
      className={cn(
        'flex items-center gap-2.5 rounded-lg border border-secondary bg-primary shadow-2xs',
        compact ? 'px-2.5 py-1.5' : 'px-3 py-2',
      )}
    >
      <span
        className={cn(
          'inline-flex shrink-0 items-center justify-center rounded-md border font-mono font-bold shadow-2xs',
          compact ? 'size-7 text-sm' : 'size-8 text-base',
          gradeTone(grade),
        )}
        aria-label={`${label} rating ${grade}`}
      >
        {grade}
      </span>
      <div className="min-w-0">
        <div className="truncate text-xs font-semibold text-primary">{label}</div>
        <div className="text-[10px] text-tertiary">Grade {grade}</div>
      </div>
    </div>
  )
}

export function GateStatus({ passed }: { passed: boolean }) {
  return (
    <Pill
      className={cn(
        'font-bold text-xs px-2.5 py-0.5',
        passed
          ? 'bg-success-primary text-success-primary border border-utility-green-400'
          : 'bg-error-primary text-error-primary border border-error',
      )}
    >
      {passed ? (
        <CheckCircle2 className="size-3.5 text-fg-success-primary" aria-hidden="true" />
      ) : (
        <XCircle className="size-3.5 text-fg-error-primary" aria-hidden="true" />
      )}
      <span>{passed ? 'Gate passed' : 'Gate failed'}</span>
    </Pill>
  )
}

export function GateEvidence({
  gate,
  info,
}: {
  gate: ProjectGateResult
  info: ProjectGateInfo
  compact?: boolean
}) {
  const results = [...gate.results].sort((a, b) => Number(a.passed) - Number(b.passed))

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-secondary pb-2.5">
        <div>
          <span className="text-sm font-bold text-primary">{info.name || 'Quality gate'}</span>
        </div>
        <GateStatus passed={gate.passed} />
      </div>

      <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
        {results.map((result, index) => {
          const isPassed = result.passed
          const actualFormatted = metricValue(result.condition.metric, result.actual)
          const thresholdFormatted = metricValue(result.condition.metric, result.condition.threshold)

          return (
            <div
              key={`${result.condition.metric}-${index}`}
              className={cn(
                'flex items-center justify-between gap-2.5 rounded-lg border px-3.5 py-2.5 text-xs transition-all shadow-2xs',
                isPassed
                  ? 'border-utility-green-300 bg-success-primary hover:bg-success-secondary'
                  : 'border-error bg-error-primary hover:bg-error-secondary',
              )}
            >
              <div className="min-w-0 flex-1 truncate">
                <div className="text-xs font-bold text-primary truncate">
                  {metricLabel(result.condition.metric)}
                </div>
                <div className="flex items-center gap-1.5 font-mono text-xs tabular-nums mt-1">
                  <span className={cn('font-black text-sm', isPassed ? 'text-success-primary' : 'text-error-primary')}>
                    {actualFormatted}
                  </span>
                  <span className="text-tertiary text-[11px]">
                    ({result.condition.op} {thresholdFormatted})
                  </span>
                </div>
              </div>

              {isPassed ? (
                <CheckCircle2 className="size-4.5 shrink-0 text-fg-success-primary" aria-label="Passed" />
              ) : (
                <XCircle className="size-4.5 shrink-0 text-fg-error-primary" aria-label="Failed" />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
