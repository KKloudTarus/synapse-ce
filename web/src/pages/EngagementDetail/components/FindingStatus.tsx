import { AlertTriangle, Loading01 } from '@untitledui/icons'
import { useState } from 'react'
import { Select, cn } from '../../../components/ui'
import { ApiError, api } from '../../../lib/api'
import { statusLabel } from '../../../lib/format'
import type { Finding } from '../../../lib/types'

export const FINDING_STATUSES = ['open', 'triage', 'confirmed', 'false_positive', 'remediated']

export const STATUS_DOT: Record<string, string> = {
  open: 'bg-utility-neutral-400',
  triage: 'bg-utility-orange-500',
  confirmed: 'bg-utility-red-500',
  false_positive: 'bg-utility-neutral-300',
  remediated: 'bg-utility-green-500',
}

export const STATUS_TEXT: Record<string, string> = {
  open: 'text-secondary',
  triage: 'text-warning-primary',
  confirmed: 'text-error-primary',
  false_positive: 'text-tertiary',
  remediated: 'text-success-primary',
}

export function StatusLabel({ status }: { status: string }) {
  return (
    <span className={cn('flex items-center gap-2 font-medium', STATUS_TEXT[status] ?? 'text-tertiary')}>
      <span className={cn('size-2 shrink-0 rounded-full', STATUS_DOT[status] ?? 'bg-utility-neutral-400')} />
      {statusLabel(status)}
    </span>
  )
}

export function FindingStatusControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'failed' | 'conflict'>('')

  async function change(status: string) {
    if (status === finding.status) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.updateFindingStatus(engagementId, finding.id, status, finding.version))
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select
        value={finding.status}
        onValueChange={change}
        disabled={busy}
        size="sm"
        ariaLabel={`Triage status for ${finding.title}`}
        className="min-w-[9.5rem]"
        options={FINDING_STATUSES.map((s) => ({ value: s, label: <StatusLabel status={s} /> }))}
      />
      {busy && <Loading01 className="size-3.5 shrink-0 animate-spin text-tertiary" />}
      {note === 'failed' && <span className="text-xs text-error-primary">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-warning-primary">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}
