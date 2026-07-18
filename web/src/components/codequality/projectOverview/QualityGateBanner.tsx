import { CheckCircle2, XCircle } from 'lucide-react'
import type { ProjectOverviewGate } from '../../../lib/projectOverview'
import {
  formatGateEvidenceValue,
  gateMetricLabel,
  gateSourceLabel,
} from '../../../lib/projectOverviewPresentation'
import { Card, Pill, cn } from '../../ui'

export function QualityGateBanner({ gate }: { gate: ProjectOverviewGate }) {
  const passed = gate.status === 'passed'
  const source = gateSourceLabel(gate.source)
  const gateName = gate.name ?? 'Recorded quality gate'
  return (
    <Card className={passed ? 'border-low/30 bg-low/5' : 'border-critical/30 bg-critical/5'}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            {passed ? <CheckCircle2 className="size-5 text-low" aria-hidden="true" /> : <XCircle className="size-5 text-critical" aria-hidden="true" />}
            <h2 className={cn('text-xl font-semibold', passed ? 'text-low' : 'text-critical')}>
              Quality Gate {passed ? 'Passed' : 'Failed'}
            </h2>
          </div>
          <p className="mt-1 text-sm text-mutedfg">
            {gateName}{source ? ` · ${source}` : ''}
          </p>
        </div>
        <Pill className={passed ? 'bg-low/15 text-low ring-1 ring-inset ring-low/20' : 'bg-critical/15 text-critical ring-1 ring-inset ring-critical/20'}>
          {passed ? 'Passed' : 'Failed'}
        </Pill>
      </div>
      {!passed && (
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
