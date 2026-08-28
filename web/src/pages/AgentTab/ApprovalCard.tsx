import { AlertTriangle, CheckCircle, Eye, XClose, Zap } from '@untitledui/icons'
import type { ComponentType } from 'react'
import { useState } from 'react'
import { Button, cn } from '../../components/ui'
import type { PendingApproval } from '../../lib/types'

const riskClass: Record<string, string> = {
  read: 'bg-accent/10 text-accent ring-accent/25',
  active: 'bg-high/10 text-high ring-high/25',
  intrusive: 'bg-critical/10 text-critical ring-critical/25',
}
const riskIcon: Record<string, ComponentType<{ className?: string }>> = { read: Eye, active: Zap, intrusive: AlertTriangle }

export function ApprovalCard({ approval, onDecide }: { approval: PendingApproval; onDecide: (id: string, approve: boolean) => void }) {
  const [busy, setBusy] = useState(false)
  async function act(approve: boolean) {
    setBusy(true)
    try {
      await onDecide(approval.id, approve)
    } finally {
      setBusy(false)
    }
  }
  const RiskIcon = riskIcon[approval.risk] ?? AlertTriangle
  return (
    <div className="rounded-lg border border-secondary bg-primary p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="font-mono text-sm text-primary">{approval.action}</span>
        <span
          className={cn(
            'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 ring-inset',
            riskClass[approval.risk] ?? 'bg-info/15 text-tertiary ring-info/25',
          )}
        >
          <RiskIcon className="size-3" /> {approval.risk}
        </span>
      </div>
      <div className="mb-1 text-xs text-tertiary">
        Target: <span className="font-mono text-primary">{approval.target}</span>
      </div>
      <div className="mb-2 overflow-x-auto rounded-md border border-secondary bg-secondary p-2 font-mono text-xs text-primary">
        {approval.argv.join(' ')}
      </div>
      {approval.rationale && <p className="mb-2 text-xs italic text-quaternary">"{approval.rationale}"</p>}
      <div className="flex justify-end gap-2">
        <Button variant="secondary" disabled={busy} onClick={() => act(false)} className="px-2.5 py-1">
          <XClose className="size-4" /> Deny
        </Button>
        <Button loading={busy} onClick={() => act(true)} className="px-2.5 py-1">
          <CheckCircle className="size-4" /> Approve
        </Button>
      </div>
    </div>
  )
}
