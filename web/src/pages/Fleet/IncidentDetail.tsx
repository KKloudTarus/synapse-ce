import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ClockRewind, RefreshCw01 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { CurrentUser, Incident, IncidentDisposition, IncidentState } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, SevBadge, Select, Spinner, cn } from '../../components/ui'
import { useFetch, useMutation } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import {
  IncidentDispositionBadge,
  IncidentStateBadge,
  INCIDENT_DISPOSITION_OPTIONS,
  INCIDENT_STATE_OPTIONS,
  ScoreBar,
  incidentDispositionLabel,
  incidentStateLabel,
} from './incidentShared'

// Client-side control gating mirrors the backend RBAC matrix (authoritative check stays server-side;
// this only hides controls a role can't use). Triage = owner/status/comment; Review = disposition;
// Operate = risk reassess.
const TRIAGE_ROLES = ['admin', 'consultant', 'member', 'reviewer']
const REVIEW_ROLES = ['admin', 'reviewer']
const OPERATE_ROLES = ['admin', 'consultant', 'member']

export function IncidentDetail() {
  const { id = '' } = useParams()
  const { data: me } = useFetch<CurrentUser | null>(() => api.me().catch(() => null), { deps: [] })
  const { data: incident, loading, error, refetch } = useFetch<Incident>(() => api.getIncident(id), { deps: [id] })

  const role = me?.role ?? ''
  const canTriage = TRIAGE_ROLES.includes(role)
  const canReview = REVIEW_ROLES.includes(role)
  const canOperate = OPERATE_ROLES.includes(role)

  if (loading && !incident) return <div className="p-8"><Spinner label="Loading incident…" /></div>
  if (error && !incident)
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4">
        <BackLink />
        <ErrorState message={error} />
        <Button variant="secondary" onClick={refetch}>Retry</Button>
      </div>
    )
  if (!incident) return null

  return (
    <div className="mx-auto max-w-[1400px] animate-fade-in space-y-6 pb-12">
      <BackLink />

      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-primary">{incident.title || incident.id}</h1>
          <SevBadge sev={incident.severity} />
          <IncidentStateBadge state={incident.state} />
          <IncidentDispositionBadge disposition={incident.disposition} />
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-tertiary">
          <span className="font-mono">{incident.id}</span>
          <span>· Asset <span className="font-mono text-secondary">{incident.assetId || '—'}</span></span>
          <span>· Owner <span className="text-secondary">{incident.ownerId || 'unassigned'}</span></span>
          <span>· Rev {incident.revision}</span>
          <span>· Updated {formatFleetTime(incident.updatedAt)}</span>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <div className="space-y-6">
          <RiskPanel incident={incident} canOperate={canOperate} onReassessed={refetch} />
          <DetectionsCard incident={incident} />
          <ResponsesCard incident={incident} />
          <CommentsCard incident={incident} />
          <AssetTimelineCard assetId={incident.assetId} />
        </div>

        <aside className="space-y-6">
          <AnalystActions
            incident={incident}
            canTriage={canTriage}
            canReview={canReview}
            onChanged={refetch}
          />
        </aside>
      </div>
    </div>
  )
}

function BackLink() {
  return (
    <Link to="/fleet/incidents" className="inline-flex items-center gap-1.5 text-sm text-tertiary hover:text-primary">
      <ArrowLeft className="size-4" /> Incidents
    </Link>
  )
}

function RiskPanel({ incident, canOperate, onReassessed }: { incident: Incident; canOperate: boolean; onReassessed: () => void }) {
  const { mutate, loading, error } = useMutation(() => api.reassessIncidentRisk(incident.id), { onSuccess: onReassessed })
  const risk = incident.risk

  return (
    <Card
      title="Tri-score risk"
      actions={
        canOperate ? (
          <Button variant="secondary" className="px-2.5 py-1 text-xs" loading={loading} onClick={() => mutate(undefined)}>
            <RefreshCw01 className="size-4" /> Reassess
          </Button>
        ) : undefined
      }
    >
      {error && <div className="mb-3"><ErrorState message={error} /></div>}
      {!risk ? (
        <p className="text-sm text-tertiary">
          Not yet scored. {canOperate ? 'Run a reassessment to gather this incident’s factors.' : 'An operator can run a reassessment.'}
        </p>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <ScoreBar label="Risk" value={risk.risk} tone="risk" hint="Escalation — from Threat/Exposure/Behavior factors only" />
            <ScoreBar label="Confidence" value={risk.confidence} hint="Evidence strength; bounded by coverage" />
            <ScoreBar label="Coverage" value={risk.coverage} hint="Telemetry completeness — never lowers Risk" />
          </div>

          <div>
            <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-tertiary">Coverage by class</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-4">
              {([['Process', risk.coverageVector.process], ['Network', risk.coverageVector.network], ['File', risk.coverageVector.file], ['Privilege', risk.coverageVector.privilege]] as const).map(
                ([label, v]) => (
                  <div key={label} className="flex items-center justify-between rounded-md bg-secondary px-2 py-1">
                    <span className="text-xs text-tertiary">{label}</span>
                    <span className="font-mono text-xs font-semibold tabular-nums text-primary">{v}</span>
                  </div>
                ),
              )}
            </div>
          </div>

          {risk.factorContributions.length > 0 && (
            <div>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-tertiary">Factor contributions</div>
              <div className="space-y-1">
                {risk.factorContributions.map((f, i) => (
                  <div key={`${f.factor}:${i}`} className="flex items-center gap-2 text-xs">
                    <span className="w-24 shrink-0 font-medium text-secondary">{f.factor}</span>
                    <span className="font-mono tabular-nums text-primary">+{f.points}</span>
                    <span className="truncate text-tertiary" title={f.detail}>{f.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {risk.reasonCodes.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {risk.reasonCodes.map((c) => (
                <Pill key={c}>{c}</Pill>
              ))}
            </div>
          )}

          <div className="text-[11px] text-quaternary">
            scorer {risk.scorerVersion || '—'} · policy {risk.policyVersion || '—'} · rev {risk.incidentRevision} · {formatFleetTime(risk.createdAt)}
          </div>
        </div>
      )}
    </Card>
  )
}

function DetectionsCard({ incident }: { incident: Incident }) {
  return (
    <Card title={`Detections (${incident.detectionIds.length})`}>
      {incident.detectionIds.length === 0 ? (
        <p className="text-sm text-tertiary">No detections attached.</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {incident.detectionIds.map((d) => (
            <span key={d} className="rounded-md bg-secondary px-2 py-1 font-mono text-xs text-secondary" title={d}>{d}</span>
          ))}
        </div>
      )}
    </Card>
  )
}

function ResponsesCard({ incident }: { incident: Incident }) {
  if (incident.responses.length === 0) return null
  return (
    <Card title={`Governed responses (${incident.responses.length})`}>
      <div className="space-y-1.5">
        {incident.responses.map((r) => (
          <div key={r.actionId} className="flex items-center gap-2 text-sm">
            <span className="font-mono text-xs text-secondary">{r.actionId}</span>
            <span
              className={cn(
                'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset',
                r.verified ? 'bg-accent/10 text-accent ring-accent/30' : 'bg-medium/10 text-medium ring-medium/30',
              )}
            >
              {r.verified ? 'Verified' : 'Applied — unverified'}
            </span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function CommentsCard({ incident }: { incident: Incident }) {
  return (
    <Card title={`Comments (${incident.comments.length})`}>
      {incident.comments.length === 0 ? (
        <p className="text-sm text-tertiary">No comments yet.</p>
      ) : (
        <ul className="space-y-3">
          {incident.comments.map((c, i) => (
            <li key={`${c.at}:${i}`} className="text-sm">
              <div className="flex items-center gap-2 text-xs text-tertiary">
                <span className="font-medium text-secondary">{c.actor || 'unknown'}</span>
                <span>{formatFleetTime(c.at)}</span>
              </div>
              <p className="mt-0.5 whitespace-pre-wrap text-primary">{c.text}</p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function AssetTimelineCard({ assetId }: { assetId: string }) {
  const [open, setOpen] = useState(false)
  const { data, loading, error } = useFetch(() => api.assetTimeline(assetId, { limit: 100 }), {
    enabled: open && !!assetId,
    deps: [assetId, open],
  })

  return (
    <Card
      title="Asset State Timeline"
      actions={
        <Button variant="secondary" className="px-2.5 py-1 text-xs" onClick={() => setOpen((v) => !v)} disabled={!assetId}>
          <ClockRewind className="size-4" /> {open ? 'Hide' : 'Show'}
        </Button>
      }
    >
      {!assetId ? (
        <p className="text-sm text-tertiary">No asset associated.</p>
      ) : !open ? (
        <p className="text-sm text-tertiary">The event-time timeline of accepted telemetry for this asset.</p>
      ) : loading ? (
        <Spinner className="size-4" />
      ) : error ? (
        <ErrorState message={error} />
      ) : !data || data.length === 0 ? (
        <EmptyState icon={ClockRewind} title="No timeline entries" hint="No accepted telemetry projected for this asset yet." />
      ) : (
        <ol className="relative space-y-3 border-l border-secondary pl-4">
          {data.map((e) => (
            <li key={e.eventId} className="relative">
              <span className="absolute -left-[21px] top-1.5 size-2 rounded-full bg-brand-solid ring-2 ring-primary" />
              <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-tertiary">
                <span className="font-mono text-[11px] tabular-nums">{formatFleetTime(e.occurredAt)}</span>
                <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] uppercase text-secondary">{e.kind}</span>
                <span className="font-mono text-[11px]">{e.entityKind}</span>
              </div>
              <p className="mt-0.5 text-sm text-primary">{e.summary}</p>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}

function AnalystActions({
  incident,
  canTriage,
  canReview,
  onChanged,
}: {
  incident: Incident
  canTriage: boolean
  canReview: boolean
  onChanged: () => void
}) {
  const [comment, setComment] = useState('')
  const [owner, setOwner] = useState('')

  const status = useMutation((to: IncidentState) => api.changeIncidentStatus(incident.id, to), { onSuccess: onChanged })
  const disposition = useMutation((d: IncidentDisposition) => api.setIncidentDisposition(incident.id, d), { onSuccess: onChanged })
  const assignOwner = useMutation((o: string) => api.assignIncidentOwner(incident.id, o), {
    onSuccess: () => { setOwner(''); onChanged() },
  })
  const addComment = useMutation((t: string) => api.commentIncident(incident.id, t), {
    onSuccess: () => { setComment(''); onChanged() },
  })

  const actionError = status.error || disposition.error || assignOwner.error || addComment.error
  const busy = status.loading || disposition.loading || assignOwner.loading || addComment.loading

  if (!canTriage && !canReview) {
    return (
      <Card title="Analyst actions">
        <p className="text-sm text-tertiary">Triage or review permission is required to act on this incident.</p>
      </Card>
    )
  }

  return (
    <Card title="Analyst actions">
      <div className="space-y-4">
        {actionError && <ErrorState message={actionError} />}

        {canTriage && (
          <Field label="Status">
            <Select
              value={incident.state}
              onValueChange={(v) => status.mutate(v as IncidentState)}
              options={INCIDENT_STATE_OPTIONS.map((s) => ({ value: s, label: incidentStateLabel(s) }))}
              ariaLabel="Change incident status"
              disabled={busy}
            />
          </Field>
        )}

        {canReview && (
          <Field label="Disposition" hint="Analyst verdict — requires review permission.">
            <Select
              value={incident.disposition}
              onValueChange={(v) => disposition.mutate(v as IncidentDisposition)}
              options={INCIDENT_DISPOSITION_OPTIONS.map((d) => ({ value: d, label: incidentDispositionLabel(d) }))}
              ariaLabel="Set incident disposition"
              disabled={busy}
            />
          </Field>
        )}

        {canTriage && (
          <>
            <Field label="Assign owner">
              <div className="flex gap-2">
                <Input
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  placeholder={incident.ownerId || 'user id'}
                  disabled={busy}
                />
                <Button variant="secondary" disabled={!owner.trim() || busy} loading={assignOwner.loading} onClick={() => assignOwner.mutate(owner.trim())}>
                  Assign
                </Button>
              </div>
            </Field>

            <Field label="Add comment">
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                rows={3}
                placeholder="Investigation note…"
                disabled={busy}
                className="input-inset w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary placeholder:text-quaternary focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
              />
              <div className="mt-2 flex justify-end">
                <Button variant="secondary" disabled={!comment.trim() || busy} loading={addComment.loading} onClick={() => addComment.mutate(comment.trim())}>
                  Comment
                </Button>
              </div>
            </Field>
          </>
        )}
      </div>
    </Card>
  )
}

export default IncidentDetail
