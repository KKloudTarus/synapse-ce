import { BarChart01, CheckCircle, Clock, ShieldTick, ShieldZap, Target04 } from '@untitledui/icons'
import { type ComponentType, type ReactNode } from 'react'
import { Card, cn } from '../../../components/ui'
import type { ScanJob, ScanResult } from '../../../lib/types'
import { fmtDuration } from '../VulnsTab'

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

export function ScanHealth({ scan, job }: { scan: ScanResult; job: ScanJob | null }) {
  const status = job?.status ?? 'succeeded'
  const statusLabelText = status === 'running' ? 'Running' : status === 'failed' ? 'Failed' : 'Finished'
  const statusTone = status === 'running' ? 'brand' : status === 'failed' ? 'critical' : 'accent'
  // A current job owns its coverage. A cached result cannot describe a newer job.
  const coverage = (job ? job.engineCoverage : scan.engineCoverage) ?? { status: 'unknown' as const, required: 0, completed: 0 }
  const coverageTone = coverage.status === 'complete' ? 'accent' : coverage.status === 'partial' ? 'medium' : 'critical'
  const confident = scan.completeness.confident
  const q = scan.findingQuality
  const m = scan.manifest
  const repro = m.reproScore
  const reproTone = repro >= 85 ? 'accent' : repro >= 60 ? 'medium' : 'critical'

  return (
    <Card bodyClass="p-0" className="overflow-hidden shadow-xs">
      <div className="grid grid-cols-2 divide-y divide-secondary sm:grid-cols-3 sm:divide-y-0 sm:divide-x lg:grid-cols-7">
        <HealthStat icon={CheckCircle} label="Status" value={statusLabelText} tone={statusTone} />
        <HealthStat
          icon={Clock}
          label="Duration"
          value={status === 'running' ? 'in progress' : fmtDuration(job?.startedAt ?? null, job?.finishedAt ?? null)}
        />
        <HealthStat
          icon={BarChart01}
          label="Dependencies"
          value={confident ? 'High' : 'Partial'}
          tone={confident ? 'accent' : 'medium'}
          hint="Dependency resolution confidence; this does not describe required-engine coverage"
        />
        <HealthStat
          icon={ShieldTick}
          label="Coverage"
          value={coverage.status}
          tone={coverageTone}
          hint={`${coverage.completed}/${coverage.required} required engines completed`}
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
      {scan.executionMode ? <div className="border-t border-secondary px-4 py-2 text-xs text-secondary">
        Current execution mode: <span className="font-semibold text-primary">{scan.executionMode}</span>
        {scan.includesPreviousResults ? <span> · Includes retained findings from a previous result; current coverage does not establish whole-assessment coverage.</span> : null}
      </div> : null}
    </Card>
  )
}
