import { AlertTriangle, Loading01, MessageSquare01, RefreshCcw01, User01 } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { Button, Input, Select, cn } from '../../../components/ui'
import { useFetch } from '../../../hooks'
import { ApiError, api } from '../../../lib/api'
import type { Finding, FindingComment, Retest, RetestOutcome } from '../../../lib/types'

export function AssigneeControl({
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
  const [value, setValue] = useState(finding.assignee)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'saved' | 'failed' | 'conflict'>('')

  useEffect(() => {
    setValue(finding.assignee)
  }, [finding.assignee, finding.version])

  async function save() {
    if (value.trim() === finding.assignee) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.setFindingAssignee(engagementId, finding.id, value.trim(), finding.version))
      setNote('saved')
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
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-secondary">
        <User01 className="size-3.5 text-fg-tertiary" />
        <span>Assignee:</span>
      </div>
      <div className="flex items-center gap-2">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onBlur={save}
          placeholder="unassigned"
          aria-label={`Assignee for ${finding.title}`}
          className="h-8 max-w-[12rem] text-xs font-medium"
        />
        {busy && <Loading01 className="size-3.5 animate-spin text-tertiary" />}
        {note === 'saved' && <span className="text-xs font-bold text-success-primary">saved</span>}
        {note === 'failed' && <span className="text-xs font-bold text-error-primary">failed</span>}
        {note === 'conflict' && (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-warning-primary">
            <AlertTriangle className="size-3" /> reloaded
          </span>
        )}
      </div>
    </div>
  )
}

export const RETEST_OUTCOMES: { value: RetestOutcome; label: string }[] = [
  { value: 'remediated', label: 'Remediated' },
  { value: 'still_vulnerable', label: 'Still vulnerable' },
  { value: 'not_reproducible', label: 'Not reproducible' },
]

export function RetestOutcomeBadge({ outcome }: { outcome: RetestOutcome }) {
  const tone: Record<RetestOutcome, string> = {
    remediated: 'bg-success-primary text-success-primary border-utility-green-300',
    still_vulnerable: 'bg-error-primary text-error-primary border-error',
    not_reproducible: 'bg-secondary text-tertiary border-secondary',
  }
  const label: Record<RetestOutcome, string> = {
    remediated: 'Remediated',
    still_vulnerable: 'Still vuln',
    not_reproducible: 'Not repro',
  }
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase', tone[outcome])}>
      {label[outcome]}
    </span>
  )
}

export function RetestPanel({
  finding,
  engagementId,
  onUpdated,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
}) {
  const [list, setList] = useState<Retest[]>([])
  const [outcome, setOutcome] = useState<RetestOutcome>('remediated')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useFetch(
    () => api.findingRetests(engagementId, finding.id).then((r) => { setList(r); return r }).catch(() => [] as Retest[]),
    { deps: [engagementId, finding.id] },
  )

  async function submit() {
    setBusy(true)
    setErr(null)
    try {
      const { retest, finding: updated } = await api.recordRetest(engagementId, finding.id, outcome, note, finding.version)
      setList((prev) => [...prev, retest])
      setNote('')
      onUpdated(updated)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setErr('Finding changed: reload and retry.')
      else setErr(e instanceof Error ? e.message : 'Failed to record retest')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
        <RefreshCcw01 className="size-3.5 text-fg-tertiary" />
        <span>Retests &amp; Verification</span>
      </div>

      {list.length > 0 && (
        <ul className="space-y-1.5 rounded-lg border border-secondary bg-secondary p-2">
          {list.map((r) => (
            <li key={r.id} className="flex items-center gap-2 text-xs">
              <RetestOutcomeBadge outcome={r.outcome} />
              <span className="font-semibold text-primary">{r.tester}</span>
              {r.note && <span className="truncate text-tertiary">({r.note})</span>}
              <span className="ml-auto shrink-0 tabular-nums text-quaternary">
                {r.at ? new Date(r.at).toLocaleDateString() : ''}
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={outcome}
          onValueChange={(v) => setOutcome(v as RetestOutcome)}
          ariaLabel="Retest outcome"
          size="sm"
          options={RETEST_OUTCOMES.map((o) => ({ value: o.value, label: o.label }))}
        />
        <Input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="note (optional)"
          className="h-8 flex-1 text-xs"
        />
        <Button loading={busy} onClick={submit} className="h-8 px-3 text-xs font-semibold">
          Record
        </Button>
      </div>
      {err && <p className="text-xs text-error-primary">{err}</p>}
    </div>
  )
}

export function CommentsPanel({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [comments, setComments] = useState<FindingComment[] | null>(null)
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const { refetch: reload } = useFetch(
    () => api.findingComments(engagementId, findingId).then((c) => { setComments(c); return c }).catch(() => { setComments([]); return [] }),
    { deps: [engagementId, findingId] },
  )

  async function add() {
    if (!body.trim()) return
    setBusy(true)
    setErr(null)
    try {
      await api.addFindingComment(engagementId, findingId, body.trim())
      setBody('')
      reload()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to add comment')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
        <MessageSquare01 className="size-3.5 text-fg-tertiary" />
        <span>Comments</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto">
        {comments === null ? (
          <span className="text-xs text-quaternary">Loading...</span>
        ) : comments.length === 0 ? (
          <span className="text-xs text-quaternary">No comments yet.</span>
        ) : (
          comments.map((c) => (
            <div key={c.id} className="rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-primary">{c.author}</span>
                <span className="text-[11px] text-quaternary">
                  {c.createdAt ? new Date(c.createdAt).toLocaleString() : ''}
                </span>
              </div>
              <p className="mt-1 whitespace-pre-line text-secondary">{c.body}</p>
            </div>
          ))
        )}
      </div>

      <div className="flex items-center gap-2">
        <Input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing && !busy) add()
          }}
          placeholder="Add a comment..."
          aria-label="New comment"
          className="h-8 flex-1 text-xs"
        />
        <Button loading={busy} onClick={add} variant="secondary" className="h-8 px-3 text-xs font-semibold">
          Post
        </Button>
      </div>
      {err && <p className="mt-1 text-xs text-error-primary">{err}</p>}
    </div>
  )
}
