import { Bot, CheckCheck, ShieldQuestion, Sparkles } from 'lucide-react'
import type { ReactNode } from 'react'
import type { AITriage } from '../lib/types'
import { cn } from './ui'

type TriageFlags = Pick<AITriage, 'suspectedFP' | 'verified' | 'gateExempt' | 'reviewRequired'>

export function AITriageBadges({ triage }: { triage: TriageFlags }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5" aria-label="AI triage status">
      {triage.suspectedFP && <Badge icon={Sparkles} className="bg-brand/10 text-branddim ring-brand/25">Suspected FP</Badge>}
      {triage.verified && <Badge icon={CheckCheck} className="bg-accent/10 text-accent ring-accent/25">Verified</Badge>}
      {triage.gateExempt && <Badge icon={Bot} className="bg-medium/10 text-medium ring-medium/25">Gate exempt</Badge>}
      {triage.reviewRequired && <Badge icon={ShieldQuestion} className="bg-critical/10 text-critical ring-critical/25">Review required</Badge>}
    </span>
  )
}

function Badge({ icon: Icon, className, children }: { icon: typeof Bot; className: string; children: ReactNode }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset', className)}>
      <Icon className="size-3" aria-hidden="true" />{children}
    </span>
  )
}
