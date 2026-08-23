import { type ComponentType, type ReactNode } from 'react'
import { CheckDone01, CpuChip01, Shield01, Stars01 } from '@untitledui/icons'
import type { AITriage } from '../../lib/types'
import { cn } from '../ui'

type TriageFlags = Pick<AITriage, 'suspectedFP' | 'verified' | 'gateExempt' | 'reviewRequired'>

export function AITriageBadges({ triage }: { triage: TriageFlags }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5" aria-label="AI triage status">
      {triage.suspectedFP && (
        <Badge icon={Stars01} className="bg-brand-primary text-brand-secondary ring-brand/30">
          Suspected FP
        </Badge>
      )}
      {triage.verified && (
        <Badge icon={CheckDone01} className="bg-accent/10 text-accent ring-accent/30">
          Verified
        </Badge>
      )}
      {triage.gateExempt && (
        <Badge icon={CpuChip01} className="bg-medium/10 text-medium ring-medium/30">
          Gate exempt
        </Badge>
      )}
      {triage.reviewRequired && (
        <Badge icon={Shield01} className="bg-critical/10 text-critical ring-critical/30">
          Review required
        </Badge>
      )}
    </span>
  )
}

function Badge({
  icon: Icon,
  className,
  children,
}: {
  icon: ComponentType<{ className?: string }>
  className: string
  children: ReactNode
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset',
        className,
      )}
    >
      <Icon className="size-3" aria-hidden="true" />
      {children}
    </span>
  )
}
