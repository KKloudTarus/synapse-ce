import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
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
    ? { card: 'border-low/30 bg-low/5', text: 'text-low', pill: 'bg-low/15 text-low ring-1 ring-inset ring-low/20', label: 'Passed', icon: CheckCircle2 }
    : incomplete
      ? { card: 'border-medium/30 bg-medium/5', text: 'text-medium', pill: 'bg-medium/15 text-medium ring-1 ring-inset ring-medium/20', label: 'Incomplete', icon: AlertTriangle }
      : { card: 'border-critical/30 bg-critical/5', text: 'text-critical', pill: 'bg-critical/15 text-critical ring-1 ring-inset ring-critical/20', label: 'Failed', icon: XCircle }
  const Icon = tone.icon
  return (
    <Card className={tone.card}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon className={cn('size-5', tone.text)} aria-hidden="true" />
            <h2 className={cn('text-xl font-semibold', tone.text)}>Quality Gate {tone.label}</h2>
          </div>
          <p className="mt-1 text-sm text-mutedfg">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={tone.pill}>{tone.label}</Pill>
      </div>
      {incomplete && (
        <p className="mt-5 text-sm text-foreground">
          Analysis was incomplete, so this quality gate cannot be used as a passing result.
        </p>
      )}
      {gate.status === 'failed' && (
        <div className="mt-5">
          <p className="text-sm font-medium text-foreground">
            {gate.failedConditions.length} {gate.failedConditions.length === 1 ? 'condition' : 'conditions'} failed
          </p>
          <ol className="mt-3 grid gap-2">
            {gate.failedConditions.map((condition, index) => (
              <li key={`${condition.metric}-${index}`} className="rounded-lg border border-critical/25 bg-bg px-4 py-3">
                <div className="text-sm font-medium">{gateMetricLabel(condition.metric)}</div>
                <div className="mt-1 font-mono text-xs tabular-nums text-mutedfg">
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
