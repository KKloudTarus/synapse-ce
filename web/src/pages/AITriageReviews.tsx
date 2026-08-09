import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, ExternalLink, ShieldQuestion, X } from 'lucide-react'
import { AITriageBadges } from '../components/AITriageBadges'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, SevBadge, Spinner } from '../components/ui'
import { api, ApiError } from '../lib/api'
import type { AITriageReview, AITriageReviewFilter, AITriageReviewState, CurrentUser, Project, Severity } from '../lib/types'

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const states: AITriageReviewState[] = ['pending', 'accepted', 'rejected']

export function AITriageReviews() {
  const [params, setParams] = useSearchParams()
  const [reviews, setReviews] = useState<AITriageReview[] | null>(null)
  const [projects, setProjects] = useState<Project[]>([])
  const [me, setMe] = useState<CurrentUser | null>(null)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [selected, setSelected] = useState<AITriageReview | null>(null)

  const filter = useMemo<AITriageReviewFilter>(() => ({
    severity: (params.get('severity') as Severity) || undefined,
    cwe: params.get('cwe') || undefined,
    project: params.get('project') || undefined,
    state: (params.get('state') as AITriageReviewState) || 'pending',
  }), [params])

  useEffect(() => {
    let active = true
    setReviews(null)
    setError('')
    Promise.all([api.aiTriageReviews(filter), api.listProjects().catch(() => []), api.me().catch(() => null)])
      .then(([items, projectList, currentUser]) => {
        if (!active) return
        setReviews(items); setProjects(projectList); setMe(currentUser)
        setSelected((current) => current ? items.find((item) => item.id === current.id) ?? null : null)
      })
      .catch((e) => { if (active) setError(e instanceof ApiError ? e.message : 'Failed to load AI-triage reviews') })
    return () => { active = false }
  }, [filter, refresh])

  function patch(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value && !(key === 'state' && value === 'pending')) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const projectByID = useMemo(() => new Map(projects.map((p) => [p.id, p])), [projects])
  const canReview = me?.role === 'admin' || me?.role === 'reviewer'

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">AI triage reviews</h1>
        <p className="mt-1 text-sm text-mutedfg">Human decisions for false-positive recommendations that policy would not let AI exempt.</p>
      </div>

      <div className="grid gap-3 rounded-xl border border-border bg-card p-3 sm:grid-cols-2 lg:grid-cols-4">
        <Select value={filter.severity ?? 'all'} onValueChange={(v) => patch('severity', v === 'all' ? '' : v)} ariaLabel="Filter reviews by severity"
          options={[{ value: 'all', label: 'All severities' }, ...severities.map((v) => ({ value: v, label: v }))]} />
        <Input aria-label="Filter reviews by CWE" value={filter.cwe ?? ''} onChange={(e) => patch('cwe', e.target.value)} placeholder="CWE, e.g. CWE-89" />
        <Select value={filter.project ?? 'all'} onValueChange={(v) => patch('project', v === 'all' ? '' : v)} ariaLabel="Filter reviews by project"
          options={[{ value: 'all', label: 'All projects' }, ...projects.map((p) => ({ value: p.id, label: p.name }))]} />
        <Select value={filter.state ?? 'pending'} onValueChange={(v) => patch('state', v)} ariaLabel="Filter reviews by state"
          options={states.map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))} />
      </div>

      {error ? <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={() => setRefresh((v) => v + 1)}>Retry</Button></div>
        : reviews === null ? <Spinner label="Loading AI-triage reviews…" />
          : reviews.length === 0 ? <EmptyState icon={ShieldQuestion} title="No reviews match these filters" hint="Review-required findings appear here after an AI-triaged scan is sealed." />
            : <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_25rem]">
              <ul className="space-y-3" role="list">
                {reviews.map((review) => {
                  const project = projectByID.get(review.projectId)
                  return <li key={review.id}>
                    <button type="button" onClick={() => setSelected(review)} aria-pressed={selected?.id === review.id}
                      className="w-full rounded-xl text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60">
                      <Card bodyClass="p-4" className="transition-colors hover:border-borderstrong aria-pressed:border-brand">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2"><SevBadge sev={review.severity} /><Pill className="capitalize">{review.state}</Pill>{review.cwe && <Pill>{review.cwe}</Pill>}</div>
                            <h2 className="mt-2 font-semibold text-foreground">{review.title}</h2>
                            <div className="mt-2"><AITriageBadges triage={review} /></div>
                          </div>
                          <div className="text-right text-xs text-mutedfg">
                            <div>{project?.name ?? (review.projectId ? review.projectId : 'Engagement')}</div>
                            <div className="mt-1">Owner: <span className="text-foreground">{review.owner || 'Unassigned'}</span></div>
                          </div>
                        </div>
                      </Card>
                    </button>
                  </li>
                })}
              </ul>
              {selected && <ReviewPanel review={selected} project={projectByID.get(selected.projectId)} canReview={canReview} reviewerId={me?.id ?? ''}
                onClosed={() => setSelected(null)} onDecided={() => { setSelected(null); setRefresh((v) => v + 1) }} />}
            </div>}
    </div>
  )
}

function ReviewPanel({ review, project, canReview, reviewerId, onClosed, onDecided }: { review: AITriageReview; project?: Project; canReview: boolean; reviewerId: string; onClosed: () => void; onDecided: () => void }) {
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState<'accept' | 'reject' | 'claim' | ''>('')
  const [error, setError] = useState('')
  const pending = review.state === 'pending'

  async function claim() {
    setBusy('claim'); setError('')
    try { await api.claimAITriageReview(review.id, review.version); onDecided() }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Claim failed') }
    finally { setBusy('') }
  }

  async function decide(decision: 'accept' | 'reject') {
    if (rationale.trim().length < 3) { setError('A rationale of at least 3 characters is required.'); return }
    setBusy(decision); setError('')
    try { await api.decideAITriageReview(review.id, decision, rationale.trim(), review.version); onDecided() }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Decision failed') }
    finally { setBusy('') }
  }

  const sourceLink = project ? `/code-quality/projects/${encodeURIComponent(project.key)}/analysis` : `/engagements/${encodeURIComponent(review.engagementId)}`
  return <aside className="h-fit rounded-xl border border-border bg-bg p-5" aria-label="AI triage review details">
    <div className="flex items-start justify-between gap-2"><div><SevBadge sev={review.severity} /><h2 className="mt-3 text-lg font-semibold">{review.title}</h2></div>
      <button type="button" onClick={onClosed} aria-label="Close review details" className="rounded-md p-1 text-mutedfg hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"><X className="size-4" /></button></div>
    <AITriageBadges triage={review} />
    <dl className="mt-5 grid grid-cols-2 gap-3 text-xs">
      <Meta label="Proposer" value={`${review.proposerModel} · ${review.verdict} · ${review.confidence}%`} />
      <Meta label="Verifier" value={review.verifierModel ? `${review.verifierModel} · ${review.verifierVerdict || '—'} · ${review.verifierConfidence}%` : 'Not attached'} />
      <Meta label="Prompt" value={review.promptVersion} />
      <Meta label="Policy" value={review.policyVersion} />
      <Meta label="Policy reason" value={review.policyReason.replaceAll('_', ' ')} />
      <Meta label="Rollout mode" value={review.shadow ? (review.wouldGateExempt ? 'Shadow · would exempt' : 'Shadow · held') : 'Enforce · held'} />
      <Meta label="Evidence" value={review.evidenceRef} mono />
      <Meta label="Owner" value={review.owner || 'Unassigned'} />
    </dl>
    <Link to={sourceLink} className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-branddim hover:underline">Open finding context <ExternalLink className="size-3" /></Link>
    {pending ? <div className="mt-5 border-t border-border pt-4">
      {canReview && <div className="mb-4 flex items-center justify-between gap-3 rounded-lg border border-border bg-card p-3 text-xs"><span>{review.owner === reviewerId ? 'Owned by you' : review.owner ? `Owned by ${review.owner}` : 'This review is unassigned.'}</span>{!review.owner && <Button variant="secondary" className="px-2.5 py-1.5 text-xs" loading={busy === 'claim'} disabled={Boolean(busy)} onClick={claim}>Claim review</Button>}</div>}
      <Field label="Mandatory rationale"><textarea value={rationale} onChange={(e) => setRationale(e.target.value)} rows={4} disabled={Boolean(busy) || review.owner !== reviewerId} placeholder="Why should the AI recommendation be accepted or rejected?"
        className="w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60" /></Field>
      {!canReview && <p className="mt-2 text-xs text-medium">Reviewer or admin permission is required to decide.</p>}
      {canReview && review.owner !== reviewerId && <p className="mt-2 text-xs text-medium">Claim this unassigned review before deciding. Reviews owned by another reviewer cannot be taken over.</p>}
      {error && <p role="alert" className="mt-2 text-xs text-critical">{error}</p>}
      <div className="mt-4 flex flex-wrap gap-2"><Button loading={busy === 'accept'} disabled={!canReview || review.owner !== reviewerId || Boolean(busy) || rationale.trim().length < 3} onClick={() => decide('accept')}><Check className="size-4" />Accept FP</Button>
        <Button variant="danger" loading={busy === 'reject'} disabled={!canReview || review.owner !== reviewerId || Boolean(busy) || rationale.trim().length < 3} onClick={() => decide('reject')}><X className="size-4" />Reject & gate</Button></div>
      <p className="mt-3 text-xs text-subtlefg">Accept marks the finding false-positive. Reject reopens it so subsequent gates count it.</p>
    </div> : <div className="mt-5 rounded-lg border border-border bg-card p-3 text-sm"><div className="font-medium capitalize">{review.state} by {review.decidedBy}</div><p className="mt-1 whitespace-pre-wrap text-mutedfg">{review.decisionRationale}</p></div>}
  </aside>
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0"><dt className="text-subtlefg">{label}</dt><dd className={`${mono ? 'break-all font-mono' : ''} mt-1 text-foreground`}>{value || '—'}</dd></div>
}
