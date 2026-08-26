import { ArrowRight, Check, ChevronDown, ChevronUp, Copy01, File02, XClose } from '@untitledui/icons'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button, cn } from '../../../components/ui'
import { api, ApiError } from '../../../lib/api'
import { canTransitionIssue, ISSUE_STATUSES, issueStatusLabel, type IssueStatus, type ProjectIssue } from '../../../lib/types'
import { cleanIssueTitle, severityBadge, typeMeta } from './projectIssueHelpers'

export function IssueDetail({
  projectKey,
  issue,
  onClose,
  onTransitioned,
}: {
  projectKey: string
  issue: ProjectIssue
  onClose: () => void
  onTransitioned: () => void
}) {
  const [to, setTo] = useState<IssueStatus>(
    () => ISSUE_STATUSES.find((s) => canTransitionIssue(issue.status, s)) ?? issue.status,
  )
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  const meta = typeMeta(issue.type)
  const TypeIcon = meta.icon

  const [showFullDesc, setShowFullDesc] = useState(false)
  const isLongDesc = (issue.description || '').length > 200 || (issue.description || '').split('\n').length > 4

  useEffect(() => {
    setShowFullDesc(false)
  }, [issue.id])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    panelRef.current?.focus()
  }, [issue.id])

  function copyLocation(text: string) {
    if (!text) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  const targets = ISSUE_STATUSES.filter((s) => canTransitionIssue(issue.status, s))

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (rationale.trim().length < 3) {
      setErr('A rationale of at least 3 characters is required.')
      return
    }
    setBusy(true)
    setErr(null)
    api.transitionProjectIssue(projectKey, issue.id, to, rationale.trim(), issue.version)
      .then(() => {
        setRationale('')
        onTransitioned()
      })
      .catch((e) => setErr(e instanceof ApiError ? e.message : 'Transition failed'))
      .finally(() => setBusy(false))
  }

  return (
    <div ref={panelRef} tabIndex={-1} className="space-y-5 focus-visible:outline-none">
      {/* Header Bar */}
      <div className="flex items-start justify-between gap-3 border-b border-secondary pb-4">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold border', meta.badge)}>
              <TypeIcon className="size-3.5 shrink-0" />
              <span>{meta.label}</span>
            </span>
            <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs font-bold uppercase border', severityBadge(issue.severity))}>
              {issue.severity}
            </span>
            {issue.cwe && (
              <span className="font-mono rounded-md border border-secondary bg-secondary px-2 py-0.5 text-xs text-secondary">
                {issue.cwe}
              </span>
            )}
          </div>
          <h3 id="issue-detail-title" className="text-base font-bold text-primary leading-snug">
            {cleanIssueTitle(issue.title || issue.ruleKey)}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close inspector"
          className="rounded-lg p-1.5 text-tertiary hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 shrink-0"
        >
          <XClose className="size-4" aria-hidden="true" />
        </button>
      </div>

      {/* File & Line box */}
      <div>
        <div className="text-xs font-bold uppercase tracking-wider text-tertiary mb-1.5">
          Location
        </div>
        <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary/30 p-2.5 shadow-2xs text-xs">
          <div className="flex items-center gap-1.5 min-w-0 font-mono text-primary truncate">
            <File02 className="size-3.5 text-tertiary shrink-0" aria-hidden="true" />
            <span className="truncate">{issue.location}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => copyLocation(issue.location)}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium text-tertiary hover:bg-secondary hover:text-primary transition-colors"
              title={copied ? 'Copied location!' : 'Copy path'}
            >
              {copied ? <Check className="size-3 text-success-primary" /> : <Copy01 className="size-3" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <Link
              to={`/code-quality/projects/${encodeURIComponent(projectKey)}/code`}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold text-brand-secondary hover:underline"
            >
              <span>View Code</span>
              <ArrowRight className="size-3" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </div>

      {/* Description / Explanation (Collapsible) */}
      <div>
        <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-tertiary mb-1.5">
          <span>Finding Description</span>
          {isLongDesc && (
            <button
              type="button"
              onClick={() => setShowFullDesc((v) => !v)}
              className="font-sans font-semibold text-brand-secondary hover:underline capitalize text-[11px]"
            >
              {showFullDesc ? 'Show less' : 'Show full'}
            </button>
          )}
        </div>
        <div className="rounded-xl border border-secondary bg-primary p-3.5 shadow-2xs relative">
          <div className={cn('relative font-mono text-xs leading-relaxed text-secondary transition-all', !showFullDesc && isLongDesc && 'max-h-[110px] overflow-hidden')}>
            <p className="whitespace-pre-wrap">
              {issue.description || 'No description was supplied for this rule.'}
            </p>
            {!showFullDesc && isLongDesc && (
              <div className="absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-primary to-transparent pointer-events-none" />
            )}
          </div>
          {isLongDesc && (
            <button
              type="button"
              onClick={() => setShowFullDesc((v) => !v)}
              className="mt-2.5 inline-flex items-center gap-1 text-[11px] font-semibold text-brand-secondary hover:underline"
            >
              <span>{showFullDesc ? 'Show less' : 'Show full description'}</span>
              {showFullDesc ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
            </button>
          )}
        </div>
      </div>

      {/* Triage Decision Form */}
      <form onSubmit={submit} className="rounded-xl border border-secondary bg-primary p-4 shadow-xs space-y-3.5">
        <div className="text-xs font-bold uppercase tracking-wider text-primary">
          Review Classification
        </div>
        <p className="text-xs text-tertiary">
          Current status: <span className="font-semibold text-primary capitalize">{issueStatusLabel(issue.status)}</span>
        </p>

        {targets.length === 0 ? (
          <p className="text-xs text-tertiary">No transitions available from this status.</p>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium text-secondary mb-1.5 block">
                Target Status
              </label>
              <div className="grid grid-cols-2 gap-2">
                {targets.map((st) => (
                  <button
                    key={st}
                    type="button"
                    disabled={busy}
                    onClick={() => setTo(st)}
                    className={cn(
                      'flex items-center justify-between rounded-lg border p-2 text-xs font-semibold transition-all',
                      to === st
                        ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                        : 'border-secondary bg-secondary/40 text-secondary hover:bg-secondary hover:text-primary',
                    )}
                  >
                    <span>{issueStatusLabel(st)}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="issue-transition-rationale" className="text-xs font-medium text-secondary mb-1.5 block">
                Rationale <span className="text-error-primary">*</span>
              </label>
              <textarea
                id="issue-transition-rationale"
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                rows={3}
                disabled={busy}
                className="w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-xs text-primary shadow-2xs focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
                placeholder="Enter triage notes or rationale for this status change..."
              />
            </div>

            {err && <p className="text-xs font-medium text-error-primary">{err}</p>}

            <Button
              type="submit"
              variant="primary"
              loading={busy}
              disabled={busy}
              className="w-full !bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs font-semibold"
            >
              Apply Classification
            </Button>
          </div>
        )}
      </form>
    </div>
  )
}
