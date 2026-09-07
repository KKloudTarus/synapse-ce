import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Check, CpuChip01, Edit03, FileX02, ShieldTick, X } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { WriteupDraft } from '../../lib/api'

function formatWhen(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString()
}

function stateTone(state: WriteupDraft['state']): string {
  switch (state) {
    case 'accepted':
      return 'bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25'
    case 'rejected':
      return 'bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25'
    default:
      return 'bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25'
  }
}

function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 8)}…` : id
}

function DraftCard({
  draft,
  onChanged,
}: {
  draft: WriteupDraft
  onChanged: (d: WriteupDraft) => void
}) {
  const [editing, setEditing] = useState(false)
  const [description, setDescription] = useState(draft.description)
  const [remediation, setRemediation] = useState(draft.remediation)
  const [busy, setBusy] = useState<'save' | 'accept' | 'reject' | null>(null)
  const { notify } = useToast()
  const proposed = draft.state === 'proposed'

  async function run(kind: 'save' | 'accept' | 'reject') {
    setBusy(kind)
    try {
      let updated: WriteupDraft
      if (kind === 'save') updated = await api.editWriteupDraft(draft.engagementId, draft.id, { description, remediation })
      else if (kind === 'accept') updated = await api.acceptWriteupDraft(draft.engagementId, draft.id)
      else updated = await api.rejectWriteupDraft(draft.engagementId, draft.id)
      onChanged(updated)
      if (kind === 'save') setEditing(false)
      notify(kind === 'save' ? 'Draft revised.' : kind === 'accept' ? 'Draft accepted.' : 'Draft rejected.', 'success')
    } catch (e) {
      notify(e instanceof Error ? e.message : `Failed to ${kind} draft`, 'error')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', stateTone(draft.state))}>
          {draft.state}
        </span>
        <span className="inline-flex items-center gap-1 text-xs text-tertiary">
          <CpuChip01 className="size-3.5 text-quaternary" aria-hidden /> proposed by <span className="font-mono text-secondary">{draft.proposedBy || 'agent'}</span>
        </span>
        <Link
          to={`/engagements/${encodeURIComponent(draft.engagementId)}/findings#finding-${encodeURIComponent(draft.findingId)}`}
          className="font-mono text-xs text-brand-secondary underline-offset-2 hover:underline"
          title="Open the finding this draft is about"
        >
          {shortId(draft.findingId)}
        </Link>
        {draft.decidedBy && (
          <span className="ml-auto text-xs text-tertiary">
            {draft.state} by <span className="text-secondary">{draft.decidedBy}</span>
            {formatWhen(draft.updatedAt) && <span className="text-quaternary"> · {formatWhen(draft.updatedAt)}</span>}
          </span>
        )}
      </div>

      {editing ? (
        <div className="mt-3 space-y-3">
          <label className="block">
            <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-tertiary">Description</span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
              aria-label="Draft description"
              className="input-inset w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary outline-none focus:border-brand focus:ring-2 focus:ring-brand/40"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-tertiary">Remediation</span>
            <textarea
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
              rows={4}
              aria-label="Draft remediation"
              className="input-inset w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary outline-none focus:border-brand focus:ring-2 focus:ring-brand/40"
            />
          </label>
          <div className="flex gap-2">
            <Button loading={busy === 'save'} onClick={() => run('save')} variant="secondary-color" className="px-3 py-1.5">
              <Check className="size-4" /> Save revision
            </Button>
            <Button
              variant="secondary"
              className="px-3 py-1.5"
              disabled={busy !== null}
              onClick={() => {
                setDescription(draft.description)
                setRemediation(draft.remediation)
                setEditing(false)
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div className="mt-3 space-y-3">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Description</span>
            <p className="mt-1 whitespace-pre-wrap text-sm text-secondary">{draft.description || <span className="text-quaternary">—</span>}</p>
          </div>
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Remediation</span>
            <p className="mt-1 whitespace-pre-wrap text-sm text-secondary">{draft.remediation || <span className="text-quaternary">—</span>}</p>
          </div>
        </div>
      )}

      {proposed && !editing && (
        <div className="mt-4 flex flex-wrap gap-2 border-t border-secondary pt-3">
          <Button variant="secondary-color" className="px-3 py-1.5" loading={busy === 'accept'} disabled={busy !== null} onClick={() => run('accept')}>
            <Check className="size-4" /> Accept
          </Button>
          <Button variant="secondary" className="px-3 py-1.5" disabled={busy !== null} onClick={() => setEditing(true)}>
            <Edit03 className="size-4" /> Edit
          </Button>
          <Button variant="secondary" className="px-3 py-1.5 text-error-primary" loading={busy === 'reject'} disabled={busy !== null} onClick={() => run('reject')}>
            <X className="size-4" /> Reject
          </Button>
        </div>
      )}
    </Card>
  )
}

export function WriteupDraftsTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error, refetch } = useFetch(() => api.listWriteupDrafts(engagementId), { deps: [engagementId] })
  const drafts = data ?? []
  const proposed = drafts.filter((d) => d.state === 'proposed').length

  if (loading) return <Spinner label="Loading write-up drafts…" />
  if (error) return <ErrorState message={error} />
  if (drafts.length === 0)
    return (
      <EmptyState
        icon={FileX02}
        title="No write-up drafts"
        hint="When an agent proposes finding description or remediation prose, it appears here for a reviewer to edit, accept, or reject."
      />
    )

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold text-primary">AI-proposed write-up drafts</h2>
        {proposed > 0 && <Pill className="bg-brand-primary/10 text-brand-secondary ring-1 ring-inset ring-brand/25">{proposed} awaiting sign-off</Pill>}
      </div>
      <p className="flex items-start gap-2 rounded-lg border border-secondary bg-secondary/20 p-3 text-xs text-tertiary">
        <ShieldTick className="mt-0.5 size-4 shrink-0 text-brand-secondary" aria-hidden />
        Separation of duties: the reviewer who accepts a draft must be someone other than the proposing
        agent. Accepting makes the draft eligible to be applied to its finding; it renders nothing on its own.
      </p>
      <div className="space-y-3">
        {drafts.map((d) => (
          <DraftCard key={d.id} draft={d} onChanged={() => refetch()} />
        ))}
      </div>
    </div>
  )
}

export default WriteupDraftsTab
