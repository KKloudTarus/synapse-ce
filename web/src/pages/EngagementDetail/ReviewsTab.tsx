import { useState, useEffect, useRef } from 'react'
import { AlertTriangle, CheckCircle, ShieldTick, Shield01 } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { ApiError, api } from '../../lib/api'
import type { CurrentUser, EvidenceLedger, Judgment } from '../../lib/types'
import { EVIDENCE_BAR, GATED_JUDGMENT_CAPABILITIES, JudgmentClaim, JudgmentStateBadge, sealedJudgmentId } from './FindingsTab'

export function JudgmentReviewTab({ engagementId }: { engagementId: string }) {
  const { data, error: fetchErr, refetch: load } = useParallelFetch<[Judgment[], EvidenceLedger, CurrentUser | null]>(
    () => Promise.all([
      api.judgments(engagementId),
      api.evidenceLedger(engagementId),
      api.me().catch(() => null),
    ]),
    { deps: [engagementId] },
  )
  const [judgments, setJudgments] = useState<Judgment[] | null>(null)
  const [ledger, setLedger] = useState<EvidenceLedger | null>(null)
  const [me, setMe] = useState<CurrentUser | null | undefined>(undefined)
  const [selected, setSelected] = useState<Judgment | null>(null)
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  const reviewHeadingRef = useRef<HTMLHeadingElement>(null)
  const pendingReviewFocus = useRef<string | null>(null)

  // Sync hook data into local state for mutations
  useEffect(() => {
    if (data) {
      setJudgments(data[0].filter((j) => j.state === 'proposed'))
      setLedger(data[1])
      setMe(data[2])
      setErr('')
    }
    if (fetchErr) setErr(fetchErr)
  }, [data, fetchErr])

  function focusReviewTrigger(id?: string) {
    pendingReviewFocus.current = id ?? ''
  }

  useEffect(() => {
    const id = pendingReviewFocus.current
    if (id === null) return
    pendingReviewFocus.current = null
    const triggers = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-review-trigger]'))
    const trigger = triggers.find((button) => button.dataset.reviewTrigger === id) ?? triggers[0]
    ;(trigger ?? reviewHeadingRef.current)?.focus({ preventScroll: true })
  }, [judgments, selected])

  async function settled(updated: Judgment) {
    setJudgments((current) => current?.filter((j) => j.id !== updated.id) ?? current)
    setSelected(null)
    setNotice('')
    focusReviewTrigger()
    const nextLedger = await api.evidenceLedger(engagementId).catch(() => null)
    if (nextLedger) setLedger(nextLedger)
  }

  async function conflict() {
    const id = selected?.id
    setSelected(null)
    setNotice('This judgment changed; the review list was reloaded.')
    await load()
    focusReviewTrigger(id)
  }

  if (judgments === null && !err) return <Spinner label="Loading judgments…" />
  if (err)
    return (
      <div className="space-y-3">
        <ErrorState message={err} />
        <Button variant="secondary" onClick={load}>Retry</Button>
      </div>
    )
  if (!judgments?.length) {
    return (
      <div className="space-y-3">
        <EmptyState icon={ShieldTick} title="No judgments awaiting review" hint="All proposed judgments have been settled." />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 ref={reviewHeadingRef} tabIndex={-1} className="text-lg font-semibold text-primary">Judgments awaiting review</h2>
        <p className="mt-1 text-sm text-tertiary">
          Verify evidence-gated claims or accept descriptive claims. The server records every decision in the evidence chain.
        </p>
      </div>
      {notice && <p role="status" className="text-sm text-accent">{notice}</p>}
      {!ledger?.intact && (
        <p role="alert" className="flex items-center gap-2 text-sm text-critical">
          <AlertTriangle className="size-4" /> Evidence chain integrity check failed.
        </p>
      )}
      <ul role="list" className="space-y-3">
        {judgments.map((judgment) => {
          const gated = GATED_JUDGMENT_CAPABILITIES.has(judgment.capability)
          const evidence = ledger?.items.find((item) => sealedJudgmentId(item) === judgment.id)
          const blockedReason =
            me === undefined
              ? 'Loading reviewer identity…'
              : me === null
                ? 'Reviewer identity is unavailable.'
                : me.id === judgment.proposedBy
                  ? 'The proposer cannot review their own judgment.'
                  : me.role !== 'admin' && me.role !== 'reviewer'
                    ? 'Reviewer permission is required.'
                    : ''
          return (
            <li
              key={judgment.id}
              onClick={(event) => {
                if (blockedReason || (event.target as HTMLElement).closest('button, input, textarea, label, select, a')) return
                setSelected(judgment)
              }}
              onKeyDown={(event) => {
                if (blockedReason || event.target !== event.currentTarget || (event.key !== 'Enter' && event.key !== ' ')) return
                event.preventDefault()
                setSelected(judgment)
              }}
              tabIndex={blockedReason ? undefined : 0}
            >
              <Card bodyClass="p-4" className={cn(!blockedReason && 'cursor-pointer hover:border-primary')}>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium capitalize text-primary">{judgment.capability.replaceAll('_', ' ')}</span>
                      <JudgmentStateBadge state={judgment.state} />
                      <Pill>{gated ? 'evidence-gated' : 'human acceptance'}</Pill>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-tertiary">
                      <span>{judgment.subjectKind || 'subject'}: <span className="break-all font-mono text-primary">{judgment.subjectId}</span></span>
                      <span>proposed by <span className="font-mono text-primary">{judgment.proposedBy}</span></span>
                    </div>
                  </div>
                  <div className="text-right">
                    <Button
                      variant="secondary"
                      data-review-trigger={judgment.id}
                      aria-expanded={selected?.id === judgment.id}
                      aria-controls={`judgment-review-${judgment.id}`}
                      disabled={Boolean(blockedReason)}
                      title={blockedReason || undefined}
                      onClick={() => setSelected(judgment)}
                      className="px-3 py-1.5"
                    >
                      {gated ? <ShieldTick className="size-4" /> : <CheckCircle className="size-4" />}
                      {gated ? 'Verify' : 'Accept'}
                    </Button>
                    {blockedReason && <p className="mt-1 max-w-64 text-xs text-quaternary">{blockedReason}</p>}
                  </div>
                </div>
                <div className="mt-4 rounded-lg border border-secondary bg-primary p-3">
                  <JudgmentClaim judgment={judgment} />
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-tertiary">
                  {evidence ? (
                    <>
                      <span className="flex items-center gap-1.5 text-accent"><ShieldTick className="size-3.5" /> Sealed proposal</span>
                      <span className="font-mono" title={evidence.hash}>sha256 {evidence.hash.slice(0, 12)}</span>
                      <span>by {evidence.createdBy}</span>
                      <span>{evidence.createdAt ? new Date(evidence.createdAt).toLocaleString() : '–'}</span>
                    </>
                  ) : (
                    <span className="flex items-center gap-1.5 text-medium"><Shield01 className="size-3.5" /> Sealed proposal evidence unavailable</span>
                  )}
                </div>
                {selected?.id === judgment.id && (
                  <JudgmentReviewForm
                    engagementId={engagementId}
                    judgment={judgment}
                    onCancel={() => {
                      setSelected(null)
                      focusReviewTrigger(judgment.id)
                    }}
                    onSettled={settled}
                    onConflict={conflict}
                  />
                )}
              </Card>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function JudgmentReviewForm({
  engagementId,
  judgment,
  onCancel,
  onSettled,
  onConflict,
}: {
  engagementId: string
  judgment: Judgment
  onCancel: () => void
  onSettled: (judgment: Judgment) => void
  onConflict: () => void
}) {
  const gated = GATED_JUDGMENT_CAPABILITIES.has(judgment.capability)
  const [score, setScore] = useState(90)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function submit() {
    setBusy(true)
    setErr('')
    try {
      const updated = gated
        ? await api.verifyJudgment(engagementId, judgment.id, score, rationale.trim(), judgment.version)
        : await api.acceptJudgment(engagementId, judgment.id, judgment.version)
      onSettled(updated)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) onConflict()
      else setErr(e instanceof ApiError ? e.message : `${gated ? 'Verify' : 'Accept'} failed`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div id={`judgment-review-${judgment.id}`} className="mt-4 border-t border-secondary pt-4">
      {gated ? (
        <div className="space-y-3">
          <p className="text-xs text-tertiary">
            Record an adversarial verdict. Scores ≥ {EVIDENCE_BAR} confirm this claim; lower scores refute it. Either outcome is sealed.
          </p>
          <Field label="Evidence score" hint="0–100">
            <Input
              type="number"
              min={0}
              max={100}
              value={score}
              onChange={(e) => setScore(Math.max(0, Math.min(100, Number(e.target.value))))}
            />
          </Field>
          <Field label="Rationale">
            <textarea
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={4}
              placeholder="How the claim was reproduced or refuted"
              className="w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand/40"
            />
          </Field>
        </div>
      ) : (
        <p className="text-sm text-tertiary">
          Accept this descriptive claim as reviewed. The acceptance is sealed into the evidence chain.
        </p>
      )}

      {err && <p role="alert" className="mt-3 text-sm text-critical">{err}</p>}
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" disabled={busy} onClick={onCancel}>Cancel</Button>
        <Button loading={busy} disabled={gated && !rationale.trim()} onClick={submit}>
          {gated ? 'Seal verdict' : 'Accept judgment'}
        </Button>
      </div>
    </div>
  )
}
