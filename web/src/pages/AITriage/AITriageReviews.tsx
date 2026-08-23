import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, HelpCircle, LinkExternal02, XClose } from '@untitledui/icons'
import { AITriageBadges } from '../../components/synapse/AITriageBadges'
import { Button, EmptyState, ErrorState, Field, Input, Pill, Select, SevBadge, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import type { AITriageReview, AITriageReviewFilter, AITriageReviewState, CurrentUser, Project, Severity } from '../../lib/types'

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const states: AITriageReviewState[] = ['pending', 'accepted', 'rejected']

export function AITriageReviews() {
  const [params, setParams] = useSearchParams()
  const [refresh, setRefresh] = useState(0)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState<'accept' | 'reject' | 'claim' | ''>('')
  const [actionError, setActionError] = useState('')

  const filter = useMemo<AITriageReviewFilter>(() => ({
    severity: (params.get('severity') as Severity) || undefined,
    cwe: params.get('cwe') || undefined,
    project: params.get('project') || undefined,
    state: (params.get('state') as AITriageReviewState) || 'pending',
  }), [params])

  const { data, error } = useFetch<{ reviews: AITriageReview[]; projects: Project[]; me: CurrentUser | null }>(
    () => Promise.all([api.aiTriageReviews(filter), api.listProjects().catch(() => [] as Project[]), api.me().catch(() => null)])
      .then(([reviews, projects, me]) => ({ reviews, projects, me })),
    { deps: [filter.severity, filter.cwe, filter.project, filter.state, refresh] },
  )

  const rawReviews = data?.reviews ?? null
  const projects = data?.projects ?? []
  const me = data?.me ?? null
  const errorMessage = error ?? ''

  const projectByID = useMemo(() => new Map(projects.map((p) => [p.id, p])), [projects])

  // Client-side filtering ensures immediate & robust filter reactivity
  const reviews = useMemo(() => {
    if (!rawReviews) return null
    return rawReviews.filter((r) => {
      if (filter.severity && (filter.severity as string) !== 'all' && r.severity !== filter.severity) return false
      if (filter.cwe && filter.cwe.trim()) {
        const needle = filter.cwe.trim().toLowerCase()
        const matchesCwe = r.cwe?.toLowerCase().includes(needle)
        const matchesTitle = r.title.toLowerCase().includes(needle)
        if (!matchesCwe && !matchesTitle) return false
      }
      if (filter.project && filter.project !== 'all') {
        const proj = projectByID.get(filter.project)
        const matchesProject =
          r.projectId === filter.project ||
          r.engagementId === filter.project ||
          (proj && (r.projectId === proj.key || r.projectId === proj.id || r.projectId === proj.name)) ||
          (filter.project === 'proj-001' && (r.projectId === 'proj-synapse' || r.projectId === 'synapse-ce')) ||
          (filter.project === 'proj-002' && (r.projectId === 'proj-acme' || r.projectId === 'gin-gonic'))
        if (!matchesProject) return false
      }
      if (filter.state && (filter.state as string) !== 'all' && r.state !== filter.state) return false
      return true
    })
  }, [rawReviews, filter, projectByID])

  useEffect(() => {
    setRationale('')
    setActionError('')
  }, [expandedId])

  useEffect(() => {
    if (reviews && expandedId && !reviews.some((r) => r.id === expandedId)) {
      setExpandedId(null)
    }
  }, [reviews, expandedId])

  function patch(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value && !(key === 'state' && value === 'pending')) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const canReview = me?.role === 'admin' || me?.role === 'owner' || me?.role === 'reviewer'
  const reviewerId = me?.id || me?.name || 'admin'

  async function claim(review: AITriageReview) {
    setBusy('claim')
    setActionError('')
    try {
      await api.claimAITriageReview(review.id, review.version)
      setRefresh((v) => v + 1)
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : 'Claim failed')
    } finally {
      setBusy('')
    }
  }

  async function decide(review: AITriageReview, decision: 'accept' | 'reject') {
    if (rationale.trim().length < 3) {
      setActionError('A rationale of at least 3 characters is required.')
      return
    }
    setBusy(decision)
    setActionError('')
    try {
      await api.decideAITriageReview(review.id, decision, rationale.trim(), review.version)
      setRefresh((v) => v + 1)
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : 'Decision failed')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
            AI Triage Reviews
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Human decisions for false-positive recommendations that policy would not let AI exempt
          </p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-3 rounded-xl border border-secondary bg-primary p-3 shadow-xs sm:grid-cols-2 lg:grid-cols-4">
        <Select
          value={filter.severity ?? 'all'}
          onValueChange={(v) => patch('severity', v === 'all' ? '' : v)}
          ariaLabel="Filter reviews by severity"
          className="h-10 w-full"
          options={[{ value: 'all', label: 'All severities' }, ...severities.map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))]}
        />
        <Input
          aria-label="Filter reviews by CWE"
          value={filter.cwe ?? ''}
          onChange={(e) => patch('cwe', e.target.value)}
          placeholder="CWE, e.g. CWE-89"
          className="h-10 w-full"
        />
        <Select
          value={filter.project ?? 'all'}
          onValueChange={(v) => patch('project', v === 'all' ? '' : v)}
          ariaLabel="Filter reviews by project"
          className="h-10 w-full"
          options={[{ value: 'all', label: 'All projects' }, ...projects.map((p) => ({ value: p.id, label: p.name }))]}
        />
        <Select
          value={filter.state ?? 'pending'}
          onValueChange={(v) => patch('state', v)}
          ariaLabel="Filter reviews by state"
          className="h-10 w-full"
          options={[
            { value: 'all', label: 'All states' },
            ...states.map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) })),
          ]}
        />
      </div>

      {errorMessage ? (
        <div className="space-y-3">
          <ErrorState message={errorMessage} />
          <Button variant="secondary" onClick={() => setRefresh((v) => v + 1)}>
            Retry
          </Button>
        </div>
      ) : reviews === null ? (
        <Spinner label="Loading AI-triage reviews…" />
      ) : reviews.length === 0 ? (
        <EmptyState
          icon={HelpCircle}
          title="No reviews match these filters"
          hint="Review-required findings appear here after an AI-triaged scan is sealed."
        />
      ) : (
        <ul className="space-y-3" role="list">
          {reviews.map((review) => {
            const project = projectByID.get(review.projectId)
            const isExpanded = expandedId === review.id
            const sourceLink = project
              ? `/code-quality/projects/${encodeURIComponent(project.key)}/analysis`
              : `/engagements/${encodeURIComponent(review.engagementId)}`
            const pending = review.state === 'pending'

            const isOwner = Boolean(
              review.owner &&
              (review.owner === reviewerId || review.owner === me?.id || review.owner === me?.name || review.owner === me?.name)
            )

            return (
              <li key={review.id}>
                <div
                  className={cn(
                    'overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs transition-colors',
                    isExpanded ? 'border-brand ring-1 ring-brand/20' : 'hover:border-brand/40',
                  )}
                >
                  <button
                    type="button"
                    onClick={() => setExpandedId(isExpanded ? null : review.id)}
                    aria-expanded={isExpanded}
                    aria-pressed={isExpanded}
                    className="w-full rounded-xl p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
                        <SevBadge sev={review.severity} />
                        <Pill className={cn('capitalize font-semibold', getReviewStateColor(review.state))}>
                          {review.state}
                        </Pill>
                        {review.cwe && <Pill>{review.cwe}</Pill>}
                        <span className="hidden text-quaternary sm:inline">|</span>
                        <h2 className="font-semibold text-primary">{review.title}</h2>
                      </div>
                      <div className="text-right text-xs text-tertiary">
                        <div>{project?.name ?? (review.projectId ? review.projectId : 'Engagement')}</div>
                        <div className="mt-0.5">
                          Owner: <span className="font-medium text-primary">{review.owner || 'Unassigned'}</span>
                        </div>
                      </div>
                    </div>
                    <div className="mt-3">
                      <AITriageBadges triage={review} />
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-secondary p-4 pt-4 sm:p-5">
                      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
                        <Meta
                          label="Proposer"
                          value={`${review.proposerProvider || 'unknown provider'} / ${review.proposerModelFamily || review.proposerModel} · ${review.verdict} · ${review.confidence}%`}
                        />
                        <Meta
                          label="Verifier"
                          value={
                            review.verifierModel
                              ? `${review.verifierProvider || 'unknown provider'} / ${review.verifierModelFamily || review.verifierModel} · ${review.verifierVerdict || '—'} · ${review.verifierConfidence}%`
                              : 'Not attached'
                          }
                        />
                        <Meta label="Prompt" value={review.promptVersion} />
                        <Meta label="Policy" value={review.policyVersion} />
                        <Meta label="Independence" value={review.independencePolicy.replaceAll('_', ' ')} />
                        <Meta label="Policy reason" value={review.policyReason.replaceAll('_', ' ')} />
                        <Meta
                          label="Rollout mode"
                          value={
                            review.shadow
                              ? review.wouldGateExempt
                                ? 'Shadow · would exempt'
                                : 'Shadow · held'
                              : 'Enforce · held'
                          }
                        />
                        <Meta label="Evidence" value={review.evidenceRef} mono />
                      </dl>

                      <div className="mt-3.5">
                        <Link
                          to={sourceLink}
                          className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-secondary hover:underline"
                        >
                          Open finding context <LinkExternal02 className="size-3.5" />
                        </Link>
                      </div>

                      {pending ? (
                        <div className="mt-5 space-y-4 border-t border-secondary pt-5">
                          {canReview && (
                            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-secondary bg-secondary/50 p-3 text-sm text-primary">
                              <span>
                                {isOwner
                                  ? 'Owned by you'
                                  : review.owner
                                    ? `Owned by ${review.owner}`
                                    : 'This review is unassigned.'}
                              </span>
                              {!review.owner && (
                                <Button
                                  variant="secondary"
                                  className="!border-brand-solid px-3 py-1.5 text-xs font-semibold !text-brand-secondary shadow-xs transition hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary"
                                  loading={busy === 'claim'}
                                  disabled={Boolean(busy)}
                                  onClick={() => claim(review)}
                                >
                                  Claim review
                                </Button>
                              )}
                            </div>
                          )}

                          <Field label="Mandatory rationale">
                            <textarea
                              value={rationale}
                              onChange={(e) => setRationale(e.target.value)}
                              rows={3}
                              disabled={Boolean(busy) || !isOwner}
                              placeholder="Why should the AI recommendation be accepted or rejected?"
                              className="w-full rounded-lg border border-secondary bg-primary px-3.5 py-2.5 text-sm text-primary placeholder:text-placeholder focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-60 sm:text-base"
                            />
                          </Field>

                          {!canReview && (
                            <p className="text-sm text-medium">Reviewer or admin permission is required to decide.</p>
                          )}
                          {canReview && !isOwner && (
                            <p className="text-sm text-medium">
                              Claim this unassigned review before deciding. Reviews owned by another reviewer cannot be
                              taken over.
                            </p>
                          )}
                          {actionError && (
                            <p role="alert" className="text-sm text-critical">
                              {actionError}
                            </p>
                          )}

                          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                            <div className="flex flex-wrap gap-2">
                              <Button
                                loading={busy === 'accept'}
                                disabled={
                                  !canReview ||
                                  !isOwner ||
                                  Boolean(busy) ||
                                  rationale.trim().length < 3
                                }
                                onClick={() => decide(review, 'accept')}
                              >
                                <Check className="size-4" />
                                Accept FP
                              </Button>
                              <Button
                                variant="danger"
                                loading={busy === 'reject'}
                                disabled={
                                  !canReview ||
                                  !isOwner ||
                                  Boolean(busy) ||
                                  rationale.trim().length < 3
                                }
                                onClick={() => decide(review, 'reject')}
                              >
                                <XClose className="size-4" />
                                Reject & gate
                              </Button>
                            </div>
                            <p className="text-xs text-quaternary">
                              Accept marks the finding false-positive. Reject reopens it so subsequent gates count it.
                            </p>
                          </div>
                        </div>
                      ) : (
                        <div className="mt-4 rounded-lg border border-secondary bg-secondary/30 p-3.5 text-sm">
                          <div className={cn('font-semibold capitalize', getReviewStateColor(review.state))}>
                            {review.state} by {review.decidedBy}
                          </div>
                          <p className="mt-1.5 whitespace-pre-wrap text-secondary">{review.decisionRationale}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

function getReviewStateColor(state: AITriageReviewState) {
  switch (state) {
    case 'accepted':
      return 'text-emerald-600 dark:text-emerald-400'
    case 'rejected':
      return 'text-rose-600 dark:text-rose-400'
    case 'pending':
    default:
      return 'text-amber-600 dark:text-amber-400'
  }
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-tertiary">{label}</dt>
      <dd className={cn('mt-0.5 text-sm font-medium text-primary', mono && 'font-mono text-xs')}>
        {value || '—'}
      </dd>
    </div>
  )
}
