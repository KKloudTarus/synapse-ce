import { AlertTriangle, CheckCircle, XCircle } from '@untitledui/icons'
import type { ProjectOverviewGate } from '../../../lib/projectOverview'
import {
  formatGateEvidenceValue,
  gateMetricLabel,
  gateSourceLabel,
} from '../../../lib/projectOverviewPresentation'
import { Card, Pill, cn } from '../../ui'

export function QualityGateBanner({ gate }: { gate: ProjectOverviewGate }) {
  const passed = gate.status === 'passed'
  const incomplete = gate.status === 'incomplete'
  const source = gateSourceLabel(gate.source)
  const gateName = gate.name ?? 'Recorded quality gate'
  const tone = passed
    ? {
        card: 'border-utility-green-300 bg-success-primary',
        text: 'text-success-primary',
        pill: 'border-utility-green-400 bg-primary text-fg-success-primary',
        label: 'Passed',
        icon: CheckCircle,
      }
    : incomplete
      ? {
          card: 'border-warning-primary bg-warning-primary',
          text: 'text-warning-primary',
          pill: 'border-warning-primary bg-primary text-fg-warning-primary',
          label: 'Incomplete',
          icon: AlertTriangle,
        }
      : {
          card: 'border-error bg-error-primary',
          text: 'text-error-primary',
          pill: 'border-error bg-primary text-fg-error-primary',
          label: 'Failed',
          icon: XCircle,
        }
  const Icon = tone.icon
  return (
    <Card className={cn(tone.card, 'shadow-xs')}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon className={cn('size-5', tone.text)} aria-hidden="true" />
            <h2 className={cn('text-xl font-bold tracking-tight', tone.text)}>Quality Gate {tone.label}</h2>
          </div>
          <p className="mt-1 text-xs font-medium text-secondary">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={cn(tone.pill, 'font-bold')}>{tone.label}</Pill>
      </div>
      {incomplete && (
        <p className="mt-4 text-sm text-primary">
          Analysis was incomplete, so this quality gate cannot be used as a passing result.
        </p>
      )}
      {gate.status === 'failed' && (
        <div className="mt-4">
          <p className="text-xs font-bold uppercase tracking-wider text-secondary">
            {gate.failedConditions.length} {gate.failedConditions.length === 1 ? 'condition' : 'conditions'} failed
          </p>
          <ol className="mt-2.5 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {gate.failedConditions.map((condition, index) => (
              <li
                key={`${condition.metric}-${index}`}
                className="flex flex-col justify-between rounded-xl border border-error bg-primary p-3 shadow-2xs transition-all hover:border-error"
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                  <AlertTriangle className="size-3.5 text-fg-error-primary shrink-0" aria-hidden="true" />
                  <span className="truncate">{gateMetricLabel(condition.metric)}</span>
                </div>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-1.5">
                  <span className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-bold bg-primary text-error-primary border border-error">
                    Actual: {formatGateEvidenceValue(condition.metric, condition.actual)}
                  </span>
                  <span className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] text-secondary bg-secondary border border-secondary">
                    Target: {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                  </span>
                </div>
                {/* Screen reader and test compatibility string */}
                <div className="sr-only">
                  {formatGateEvidenceValue(condition.metric, condition.actual)} — expected {condition.operator} {formatGateEvidenceValue(condition.metric, condition.threshold)}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </Card>
  )
}
