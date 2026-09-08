import { useState } from 'react'
import { GitCommit, Link01, ShieldTick } from '@untitledui/icons'
import { Card, EmptyState, ErrorState, InfoNote, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { DetectionProvenanceCurrent, DetectionProvenanceTransition } from '../../lib/api'

function statusTone(status: string): string {
  switch (status) {
    case 'complete':
      return 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25'
    case 'broken':
      return 'bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25'
    case 'expired':
      return 'bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25'
    default:
      return 'bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25'
  }
}

const KIND_LABEL: Record<string, string> = {
  received: 'Received',
  telemetry_durable: 'Telemetry durable',
  commitment_pending: 'Commitment pending',
  commitment_sealed: 'Commitment sealed',
  acknowledged: 'Acknowledged',
  expired: 'Expired',
  broken: 'Broken',
}

function formatWhen(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function TransitionChain({ engagementId, detectionId }: { engagementId: string; detectionId: string }) {
  const { data, loading, error } = useFetch<DetectionProvenanceTransition[]>(() => api.detectionProvenanceTransitions(engagementId, detectionId), { deps: [engagementId, detectionId] })
  if (loading && !data) return <div className="px-4 py-3 text-xs text-tertiary">Loading transitions…</div>
  if (error) return <div className="px-4 py-3"><ErrorState message={error} /></div>
  if (!data || data.length === 0) return <div className="px-4 py-3 text-xs text-tertiary">No transitions recorded.</div>
  return (
    <ol className="space-y-2 px-4 py-3">
      {data.map((t) => (
        <li key={`${t.sequence}-${t.hash}`} className="relative border-l border-secondary pl-4">
          <span className="absolute -left-[5px] top-1.5 size-2 rounded-full bg-brand-solid" aria-hidden />
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="font-mono text-xs tabular-nums text-quaternary">#{t.sequence}</span>
            <span className="text-sm font-medium text-primary">{KIND_LABEL[t.kind] ?? t.kind}</span>
            <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium capitalize', statusTone(t.status))}>{t.status}</span>
            <span className="text-xs tabular-nums text-tertiary">{formatWhen(t.occurredAt)}</span>
          </div>
          {t.reason && <p className="mt-0.5 text-xs text-tertiary">{t.reason}</p>}
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[11px] text-quaternary">
            <span className="inline-flex items-center gap-1" title={`hash ${t.hash}`}><GitCommit className="size-3" aria-hidden /> {t.hash ? t.hash.slice(0, 16) : '—'}…</span>
            {t.previousHash && <span className="inline-flex items-center gap-1" title={`previous ${t.previousHash}`}><Link01 className="size-3" aria-hidden /> prev {t.previousHash.slice(0, 12)}…</span>}
            {t.assetId && <span>asset {t.assetId}</span>}
            {t.agentId && <span>agent {t.agentId}</span>}
          </div>
        </li>
      ))}
    </ol>
  )
}

function ProvenanceRow({ engagementId, row }: { engagementId: string; row: DetectionProvenanceCurrent }) {
  const [open, setOpen] = useState(false)
  return (
    <li className="rounded-lg border border-secondary bg-primary">
      <button type="button" className="flex w-full flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-3 text-left" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <div className="flex min-w-0 items-center gap-2">
          <ShieldTick className="size-4 shrink-0 text-tertiary" aria-hidden />
          <span className="truncate font-mono text-sm text-primary" title={row.detectionId}>{row.detectionId}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', statusTone(row.status))}>{row.status}</span>
          <span className="text-xs text-tertiary">{formatWhen(row.updatedAt)}</span>
          <span className="text-xs text-quaternary">{open ? 'Hide chain' : 'Show chain'}</span>
        </div>
      </button>
      {open && <div className="border-t border-secondary"><TransitionChain engagementId={engagementId} detectionId={row.detectionId} /></div>}
    </li>
  )
}

export function DetectionProvenanceTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error } = useFetch<DetectionProvenanceCurrent[]>(() => api.detectionProvenance(engagementId), { deps: [engagementId] })
  return (
    <Card
      title="Detection provenance"
      titleClassName="flex items-center gap-2"
      actions={
        <InfoNote label="What is this">
          Every sealed detection carries a hash-chained lifecycle: received, telemetry durable, commitment
          pending, commitment sealed, acknowledged. A broken chain is surfaced here rather than trusted. Open
          a detection to see its ordered transitions and their hashes.
        </InfoNote>
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-6"><Spinner /></div>
      ) : error ? (
        <ErrorState message={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState icon={ShieldTick} title="No detection provenance yet" hint="Provenance appears once agents deliver sealed detections for this engagement." />
      ) : (
        <ul className="space-y-2" role="list">
          {data.map((row) => <ProvenanceRow key={row.detectionId} engagementId={engagementId} row={row} />)}
        </ul>
      )}
    </Card>
  )
}

export default DetectionProvenanceTab
