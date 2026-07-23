import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Bug, ShieldAlert, Wrench, X } from 'lucide-react'
import { useProjectRouteContext } from './CodeQualityProject'
import { api, ApiError } from '../lib/api'
import {
  canTransitionIssue,
  ISSUE_STATUSES,
  issueStatusLabel,
  type IssueListFilter,
  type IssuePage,
  type IssueStatus,
  type ProjectIssue,
  type RuleType,
} from '../lib/types'
import { Button, EmptyState, ErrorState, Field, Input, Pill, Select, SevBadge, Spinner } from '../components/ui'
import { projectCodePath } from '../lib/projectCodeNavigation'

const TYPE_OPTIONS: { value: RuleType; label: string }[] = [
  { value: 'bug', label: 'Bug' },
  { value: 'vulnerability', label: 'Vulnerability' },
  { value: 'code_smell', label: 'Code smell' },
]

function typeIcon(t: RuleType) {
  if (t === 'bug') return Bug
  if (t === 'vulnerability') return ShieldAlert
  return Wrench
}

export function ProjectIssuesPage() {
  const { projectKey } = useProjectRouteContext()
  const [params, setParams] = useSearchParams()

  const status = (params.get('status') as IssueStatus) || undefined
  const type = (params.get('type') as RuleType) || undefined
  const severity = (params.get('severity') as any) || undefined
  const language = params.get('language') || undefined
  const search = params.get('search') || undefined
  const newCode = params.get('new_code') === 'true'
  const selectedId = params.get('id')

  const filter = useMemo<IssueListFilter>(
    () => ({ status, type, severity, language, search, newCode, limit: 50 }),
    [status, type, severity, language, search, newCode],
  )

  const [page, setPage] = useState<IssuePage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    api.listProjectIssues(projectKey, filter)
      .then((res) => { if (active) setPage(res) })
      .catch((err) => { if (active) setError(err instanceof ApiError ? err.message : 'Failed to load issues') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [projectKey, filter, refresh])

  function patch(key: string, value: string | null) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const selected = page?.items.find((i) => i.id === selectedId) ?? null

  return (
    <div className="flex flex-col gap-4">
      {page?.summary && (
        <div className="flex flex-wrap items-center gap-6 rounded-xl border border-border bg-card p-4">
          <Stat label="Total" value={page.summary.total} />
          <Stat label="Open" value={page.summary.open} />
          <Stat label="Resolved" value={page.summary.resolved} />
          <label className="ml-auto flex items-center gap-2 text-sm text-mutedfg">
            <input type="checkbox" checked={newCode} onChange={(e) => patch('new_code', e.target.checked ? 'true' : null)}
              className="size-4 accent-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60" />
            New code only
          </label>
        </div>
      )}

      <div className="grid gap-3 rounded-xl border border-border bg-card p-3 md:grid-cols-[1fr_10rem_10rem_10rem]">
        <label className="relative">
          <span className="sr-only">Search issues</span>
          <Input value={search ?? ''} onChange={(e) => patch('search', e.target.value || null)} placeholder="Search title, rule, or location…" />
        </label>
        <Select value={type ?? 'all'} onValueChange={(v) => patch('type', v === 'all' ? null : v)} ariaLabel="Filter by type"
          options={[{ value: 'all', label: 'All types' }, ...TYPE_OPTIONS]} />
        <Select value={severity ?? 'all'} onValueChange={(v) => patch('severity', v === 'all' ? null : v)} ariaLabel="Filter by severity"
          options={[{ value: 'all', label: 'All severities' }, ...['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((v) => ({ value: v, label: v }))]} />
        <Select value={status ?? 'all'} onValueChange={(v) => patch('status', v === 'all' ? null : v)} ariaLabel="Filter by status"
          options={[{ value: 'all', label: 'All statuses' }, ...ISSUE_STATUSES.map((v) => ({ value: v, label: issueStatusLabel(v) }))]} />
      </div>

      <div className="flex gap-4">
        <div className="min-w-0 flex-1 rounded-xl border border-border bg-card">
          {loading && !page ? (
            <div className="flex h-40 items-center justify-center"><Spinner /></div>
          ) : error ? (
            <div className="space-y-3 p-5"><ErrorState message={error} /><Button variant="secondary" onClick={() => setRefresh((c) => c + 1)}>Retry</Button></div>
          ) : !page || page.items.length === 0 ? (
            <EmptyState icon={Wrench} title="No issues match these filters" hint="Adjust the filters, or run an analysis to populate issues." />
          ) : (
            <div className="divide-y divide-border">
              {page.items.map((it) => {
                const Icon = typeIcon(it.type)
                return (
                  <button key={it.id} type="button" onClick={() => patch('id', it.id)}
                    aria-pressed={selectedId === it.id}
                    className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-elevated/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/60 aria-pressed:bg-brand/5">
                    <SevBadge sev={it.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium text-foreground">{it.title || it.ruleKey}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-mutedfg">
                        <span className="inline-flex items-center gap-1"><Icon className="size-3.5" aria-hidden="true" />{it.type}</span>
                        {it.language && <span className="font-mono">{it.language}</span>}
                        {issueCodeLink(projectKey, it) ? <Link to={issueCodeLink(projectKey, it)!} onClick={(event) => event.stopPropagation()} className="font-mono text-branddim hover:underline">{it.location}</Link> : it.location && <span className="font-mono">{it.location}</span>}
                        <span className="capitalize">{issueStatusLabel(it.status)}</span>
                        {it.isNew && <Pill>New</Pill>}
                      </div>
                    </div>
                  </button>
                )
              })}
              {page.next && (
                <div className="p-3">
                  <Button variant="secondary" loading={loading} disabled={loading} onClick={() => {
                    if (loading) return
                    setLoading(true)
                    api.listProjectIssues(projectKey, { ...filter, before_last_seen_at: page.next!.beforeLastSeenAt, before_id: page.next!.beforeId })
                      .then((res) => setPage((prev) => (prev ? { ...res, items: [...prev.items, ...res.items] } : res)))
                      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load more'))
                      .finally(() => setLoading(false))
                  }}>Load more issues</Button>
                </div>
              )}
            </div>
          )}
        </div>

        {selected && (
          <IssueDetail
            projectKey={projectKey}
            issue={selected}
            onClose={() => patch('id', null)}
            onTransitioned={() => setRefresh((c) => c + 1)}
          />
        )}
      </div>
    </div>
  )
}

function issueCodeLink(projectKey: string, issue: ProjectIssue): string | null {
  const line = /:(\d+)$/.exec(issue.location)?.[1]
  if (!issue.file || !line || !issue.lastSeenAnalysisId) return null
  return projectCodePath(projectKey, { analysisId: issue.lastSeenAnalysisId, path: issue.file, view: 'source', line: Number(line), findingId: null })
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-sm font-medium text-mutedfg">{label}</div>
      <div className="font-mono text-2xl font-semibold tabular-nums text-foreground">{value.toLocaleString()}</div>
    </div>
  )
}

function IssueDetail({ projectKey, issue, onClose, onTransitioned }: {
  projectKey: string
  issue: ProjectIssue
  onClose: () => void
  onTransitioned: () => void
}) {
  const [to, setTo] = useState<IssueStatus>(() => ISSUE_STATUSES.find((s) => canTransitionIssue(issue.status, s)) ?? issue.status)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Move focus into the panel when it opens for a new issue so keyboard and
  // screen-reader users are not left parked on the triggering list row.
  useEffect(() => { panelRef.current?.focus() }, [issue.id])

  const targets = ISSUE_STATUSES.filter((s) => canTransitionIssue(issue.status, s))

  function submit() {
    if (rationale.trim().length < 3) { setErr('A rationale of at least 3 characters is required.'); return }
    setBusy(true)
    setErr(null)
    api.transitionProjectIssue(projectKey, issue.id, to, rationale.trim(), issue.version)
      .then(() => { setRationale(''); onTransitioned() })
      .catch((e) => setErr(e instanceof ApiError ? e.message : 'Transition failed'))
      .finally(() => setBusy(false))
  }

  return (
    <aside ref={panelRef} tabIndex={-1} role="region" aria-labelledby="issue-detail-title"
      className="w-[24rem] shrink-0 overflow-y-auto rounded-xl border border-border bg-bg p-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <SevBadge sev={issue.severity} />
          <Pill>{issue.type}</Pill>
          {issue.cwe && <Pill>{issue.cwe}</Pill>}
        </div>
        <button type="button" onClick={onClose} aria-label="Close"
          className="rounded-md p-1 text-mutedfg hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
          <X className="size-4" aria-hidden="true" />
        </button>
      </div>
      <h3 id="issue-detail-title" className="mt-4 font-semibold">{issue.title || issue.ruleKey}</h3>
      {issue.ruleName && <p className="mt-1 text-xs text-mutedfg">{issue.ruleName} · <span className="font-mono">{issue.ruleKey}</span></p>}
      <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-mutedfg">{issue.description || 'No description was supplied.'}</p>
      {issue.location && <p className="mt-3 font-mono text-xs text-subtlefg">{issue.location}</p>}

      <div className="mt-5 border-t border-border pt-4">
        <div className="text-sm font-medium text-foreground">Triage</div>
        <p className="mt-1 text-xs text-mutedfg">Current status: <span className="capitalize">{issueStatusLabel(issue.status)}</span></p>
        {targets.length === 0 ? (
          <p className="mt-2 text-xs text-mutedfg">No transitions available from this status.</p>
        ) : (
          <div className="mt-3 space-y-3">
            <Field label="Move to" htmlFor="issue-transition-to">
              <Select value={to} onValueChange={(v) => setTo(v as IssueStatus)} ariaLabel="Move to status"
                options={targets.map((s) => ({ value: s, label: issueStatusLabel(s) }))} />
            </Field>
            <Field label="Rationale" htmlFor="issue-transition-rationale">
              <textarea id="issue-transition-rationale" value={rationale} onChange={(e) => setRationale(e.target.value)}
                rows={3} disabled={busy}
                className="w-full rounded-md border border-border bg-card px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                placeholder="Why is this the right decision?" />
            </Field>
            {err && <p className="text-xs text-critical">{err}</p>}
            <Button variant="brand" onClick={submit} loading={busy} disabled={busy}>Apply transition</Button>
          </div>
        )}
      </div>
    </aside>
  )
}
