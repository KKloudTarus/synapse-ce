import { useState } from 'react'
import { Download01, Lock01, Trash01 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { CurrentUser, LegalHold, PrivacyExportBundle } from '../../lib/types'
import { Button, Card, ErrorState, Field, Input, Pill, cn } from '../../components/ui'
import { useFetch, useMutation } from '../../hooks'

const REVIEW_ROLES = ['admin', 'reviewer']

function fmtTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso)
  if (Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1) return '—'
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function isActive(h: LegalHold): boolean {
  const t = new Date(h.releasedAt)
  return !h.releasedAt || Number.isNaN(t.getTime()) || t.getUTCFullYear() <= 1
}

export function DataGovernanceTab({ engagementId }: { engagementId: string }) {
  const { data: me } = useFetch<CurrentUser | null>(() => api.me().catch(() => null), { deps: [] })
  const canReview = REVIEW_ROLES.includes(me?.role ?? '')

  return (
    <div className="max-w-3xl space-y-5">
      <LegalHoldCard engagementId={engagementId} canReview={canReview} />
      <DataExportCard engagementId={engagementId} />
      <DataDeletionCard engagementId={engagementId} canReview={canReview} />
    </div>
  )
}

function LegalHoldCard({ engagementId, canReview }: { engagementId: string; canReview: boolean }) {
  const { data, loading, refetch } = useFetch<LegalHold[]>(() => api.listLegalHolds().catch(() => []), { deps: [engagementId] })
  const [reason, setReason] = useState('')

  const hold = (data ?? []).find((h) => h.engagementId === engagementId && isActive(h)) ?? null

  const place = useMutation((r: string) => api.placeLegalHold(engagementId, r), { onSuccess: () => { setReason(''); refetch() } })
  const release = useMutation(() => api.releaseLegalHold(engagementId), { onSuccess: () => refetch() })

  return (
    <Card title="Legal hold">
      <p className="mb-3 text-sm text-tertiary">
        An active hold preserves this engagement’s detection data against retention expiry and on-demand deletion.
      </p>

      {loading && !data ? (
        <p className="text-sm text-tertiary">Loading…</p>
      ) : hold ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md bg-high/10 px-2 py-0.5 text-xs font-semibold text-high ring-1 ring-inset ring-high/30">
              <Lock01 className="size-3.5" /> Active hold
            </span>
            <span className="text-xs text-tertiary">placed by {hold.placedBy || 'unknown'} · {fmtTime(hold.placedAt)}</span>
          </div>
          <p className="text-sm text-primary"><span className="text-tertiary">Reason:</span> {hold.reason}</p>
          {(place.error || release.error) && <ErrorState message={place.error || release.error || ''} />}
          {canReview ? (
            <Button variant="secondary" loading={release.loading} onClick={() => release.mutate(undefined)}>Release hold</Button>
          ) : (
            <p className="text-xs text-tertiary">Review permission is required to release the hold.</p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-secondary">No active hold.</p>
          {(place.error || release.error) && <ErrorState message={place.error || release.error || ''} />}
          {canReview ? (
            <Field label="Place a hold">
              <div className="flex gap-2">
                <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (e.g. litigation matter #123)" disabled={place.loading} />
                <Button variant="secondary" disabled={!reason.trim() || place.loading} loading={place.loading} onClick={() => place.mutate(reason.trim())}>
                  Place hold
                </Button>
              </div>
            </Field>
          ) : (
            <p className="text-xs text-tertiary">Review permission is required to place a hold.</p>
          )}
        </div>
      )}
    </Card>
  )
}

function DataExportCard({ engagementId }: { engagementId: string }) {
  const [bundle, setBundle] = useState<PrivacyExportBundle | null>(null)
  const gen = useMutation(() => api.privacyExport(engagementId), { onSuccess: (b) => setBundle(b) })

  function download() {
    if (!bundle) return
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `privacy-export-${engagementId}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card
      title="Data export"
      actions={
        <Button variant="secondary" className="px-2.5 py-1 text-xs" loading={gen.loading} onClick={() => gen.mutate(undefined)}>
          Generate export
        </Button>
      }
    >
      <p className="mb-3 text-sm text-tertiary">
        A read-only, audited subject-access / DPO bundle: the governance data the control plane holds for this engagement.
      </p>
      {gen.error && <ErrorState message={gen.error} />}
      {bundle && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Pill>{bundle.detectionCount} detections</Pill>
            <Pill>{bundle.legalHolds.length} legal hold{bundle.legalHolds.length === 1 ? '' : 's'}</Pill>
            <span className="text-xs text-tertiary">generated {fmtTime(bundle.generatedAt)}</span>
            <Button variant="secondary" className="ml-auto px-2.5 py-1 text-xs" onClick={download}>
              <Download01 className="size-4" /> Download JSON
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}

function DataDeletionCard({ engagementId, canReview }: { engagementId: string; canReview: boolean }) {
  const [reason, setReason] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [purged, setPurged] = useState<number | null>(null)

  const purge = useMutation((r: string) => api.purgeEngagementDetectionData(engagementId, r), {
    onSuccess: (res) => { setPurged(res.purged); setReason(''); setConfirming(false) },
  })

  return (
    <Card title="Danger zone — delete detection data" className="border-critical/30">
      <p className="mb-3 text-sm text-tertiary">
        Permanently deletes this engagement’s detection projection (right-to-erasure). It is refused while a legal
        hold is active, audited with the reason, and it never touches the immutable evidence chain — only the
        queryable projection. This cannot be undone.
      </p>

      {!canReview ? (
        <p className="text-sm text-tertiary">Review permission is required to delete detection data.</p>
      ) : (
        <div className="space-y-3">
          {purge.error && <ErrorState message={purge.error} />}
          {purged !== null && (
            <p className="text-sm text-accent">Deleted {purged} detection record{purged === 1 ? '' : 's'}.</p>
          )}
          <Field label="Reason (required, audited)">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. subject erasure request #456" disabled={purge.loading} />
          </Field>
          {!confirming ? (
            <Button variant="danger" disabled={!reason.trim()} onClick={() => setConfirming(true)}>
              <Trash01 className="size-4" /> Delete detection data
            </Button>
          ) : (
            <div className={cn('flex flex-wrap items-center gap-2 rounded-lg border border-critical/40 bg-critical/5 p-3')}>
              <span className="text-sm font-medium text-critical">Permanently delete this engagement’s detection projection?</span>
              <div className="ml-auto flex gap-2">
                <Button variant="secondary" onClick={() => setConfirming(false)} disabled={purge.loading}>Cancel</Button>
                <Button variant="danger" loading={purge.loading} onClick={() => purge.mutate(reason.trim())}>Confirm delete</Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

export default DataGovernanceTab
