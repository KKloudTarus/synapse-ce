import { AlertTriangle, Loading01, MessageSquare01, RefreshCcw01, User01 } from '@untitledui/icons'
import { useEffect, useId, useRef, useState } from 'react'
import { Button, Input, Select, cn } from '../../../components/ui'
import { useFetch } from '../../../hooks'
import { ApiError, api } from '../../../lib/api'
import type { UserChoice } from '../../../lib/api/ownership'
import type { Finding, FindingComment, Retest, RetestOutcome } from '../../../lib/types'
import { UserPicker } from '../../Ownership/UserPicker'

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
  const [selectedID, setSelectedID] = useState(finding.assigneeUserId ?? '')
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'saved' | 'failed' | 'conflict'>('')

  useEffect(() => {
    setSelectedID(finding.assigneeUserId ?? '')
  }, [finding.assigneeUserId, finding.version])

  async function save(id: string) {
    if (id === (finding.assigneeUserId ?? '')) return
    setSelectedID(id)
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.setFindingAssignee(engagementId, finding.id, id, finding.version))
      setNote('saved')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
      setSelectedID(finding.assigneeUserId ?? '')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-secondary">
        <User01 className="size-3.5 text-fg-tertiary" />
        <span>Assignee</span>
        {busy && <Loading01 className="size-3.5 animate-spin text-tertiary" />}
        {note === 'saved' && <span className="text-xs font-bold text-success-primary">saved</span>}
        {note === 'failed' && <span className="text-xs font-bold text-error-primary">failed</span>}
        {note === 'conflict' && (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-warning-primary">
            <AlertTriangle className="size-3" /> reloaded
          </span>
        )}
      </div>
      <UserPicker team="" allowAll value={selectedID} onChange={(id)=>void save(id)} disabled={busy} />
      {finding.assignee && <p className="text-xs text-secondary">Stored assignee label: {finding.assignee}</p>}
      {finding.assignee && !finding.assigneeUserId && <p className="text-xs text-warning-primary">Legacy assignee label has no user binding. Choose a user above to enable personal routing.</p>}
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

  // The fetcher mirrors its result into `list` so submit() can append to it, which means a
  // different finding has to drop the copy: on failure the fetcher returns an empty array
  // without touching `list`, and the previous finding's retests would stay on screen under
  // this one's heading.
  useEffect(() => {
    setList([])
  }, [engagementId, finding.id])

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
  const requestGeneration = useRef(0)
  const [savedComments, setSavedComments] = useState<FindingComment[]>([])
  const [body, setBody] = useState('')
  const [mentions, setMentions] = useState<UserChoice[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    requestGeneration.current += 1
    setSavedComments([])
    setBody('')
    setMentions([])
    setErr(null)
    setBusy(false)
  }, [engagementId, findingId])

  const { data, loading, error: loadError, refetch: reload } = useFetch(
    () => api.findingComments(engagementId, findingId),
    { deps: [engagementId, findingId] },
  )
  const comments = data === null && savedComments.length === 0 ? null : [
    ...(data ?? []),
    ...savedComments.filter((saved) => !(data ?? []).some((comment) => comment.id === saved.id)),
  ]

  async function add() {
    if (!body.trim() || busy) return
    const generation = requestGeneration.current
    setBusy(true)
    setErr(null)
    try {
      const saved = await api.addFindingComment(engagementId, findingId, body.trim(), mentions.map((user) => user.id))
      if (generation !== requestGeneration.current) return
      if (saved.id) setSavedComments((previous) => [...previous, saved])
      setBody('')
      setMentions([])
      reload()
    } catch (e) {
      if (generation === requestGeneration.current) setErr(e instanceof Error ? e.message : 'Failed to add comment')
    } finally {
      if (generation === requestGeneration.current) setBusy(false)
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
        <MessageSquare01 className="size-3.5 text-fg-tertiary" />
        <span>Comments</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto">
        {comments === null && loading ? (
          <span className="text-xs text-quaternary">Loading...</span>
        ) : comments === null ? null : comments.length === 0 ? (
          !loadError && <span className="text-xs text-quaternary">No comments yet.</span>
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

      {loadError && <div role="alert" className="text-xs text-error-primary">
        <p>Could not load comments: {loadError}</p>
        <button type="button" onClick={reload} className="mt-1 font-semibold underline">Retry loading comments</button>
      </div>}
      <div className="flex items-center gap-2">
        <Input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing && !busy) add()
          }}
          placeholder="Add a comment..."
          aria-label="New comment"
          disabled={busy}
          className="h-8 flex-1 text-xs"
        />
        <Button loading={busy} onClick={add} variant="secondary" className="h-8 px-3 text-xs font-semibold">
          Post
        </Button>
      </div>
      <CommentMentionPicker selected={mentions} onChange={setMentions} disabled={busy} />
      {err && <p role="alert" className="mt-1 text-xs text-error-primary">{err}</p>}
    </div>
  )
}

function CommentMentionPicker({ selected, onChange, disabled }: { selected: UserChoice[]; onChange: (users: UserChoice[]) => void; disabled: boolean }) {
  const searchID = useId()
  const [query, setQuery] = useState('')
  const [options, setOptions] = useState<UserChoice[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError('')
    setOptions([])
    const timer = setTimeout(() => {
      let pending: ReturnType<typeof api.userChoices>
      try {
        pending = api.userChoices('', query, undefined, controller.signal, 'mention')
      } catch (cause) {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : 'Could not search users')
          setLoading(false)
        }
        return
      }
      void pending.then((page) => {
        if (!controller.signal.aborted) setOptions(page.items)
      }).catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not search users')
      }).finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    }, 200)
    return () => { controller.abort(); clearTimeout(timer) }
  }, [query])

  const selectedIDs = new Set(selected.map((user) => user.id))
  function add(user: UserChoice) {
    if (!selectedIDs.has(user.id) && selected.length < 10) onChange([...selected, user])
    setQuery('')
  }

  return (
    <div className="space-y-1.5">
      <label className="text-xs font-medium text-secondary" htmlFor={searchID}>Mention people (optional)</label>
      {selected.length > 0 && <div className="flex flex-wrap gap-1" aria-label="Selected mentions">
        {selected.map((user) => <span key={user.id} className="inline-flex items-center gap-1 rounded border border-secondary px-1.5 py-0.5 text-xs text-secondary">
          {user.name} <button type="button" className="text-primary underline" disabled={disabled} aria-label={`Remove ${user.name}`} onClick={() => onChange(selected.filter((candidate) => candidate.id !== user.id))}>Remove</button>
        </span>)}
      </div>}
      <Input id={searchID} value={query} disabled={disabled || selected.length >= 10} onChange={(event) => setQuery(event.target.value)} placeholder={selected.length >= 10 ? 'Maximum 10 mentions' : 'Search eligible users'} aria-label="Search eligible users to mention" className="h-8 text-xs" />
      {loading && <p className="text-xs text-tertiary" role="status">Searching users…</p>}
      {error && <p className="text-xs text-error-primary" role="alert">{error}</p>}
      {!loading && !error && options.length === 0 && <p className="text-xs text-tertiary">No eligible users found.</p>}
      {!loading && !error && options.filter((user) => !selectedIDs.has(user.id)).length > 0 && <ul className="max-h-28 overflow-y-auto rounded border border-secondary" aria-label="Eligible people to mention">
        {options.filter((user) => !selectedIDs.has(user.id)).map((user) => <li key={user.id}><button type="button" disabled={disabled} onClick={() => add(user)} className="w-full px-2 py-1 text-left text-xs text-primary hover:bg-primary_hover focus-visible:outline-2 focus-visible:outline-brand">{user.name} <span className="text-tertiary">({user.id})</span></button></li>)}
      </ul>}
    </div>
  )
}
