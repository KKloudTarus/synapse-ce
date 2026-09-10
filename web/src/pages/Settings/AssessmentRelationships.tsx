import { useCallback, useEffect, useState } from 'react'
import { Link01 } from '@untitledui/icons'
import { ApiError, api } from '../../lib/api'
import type {
  AssessmentRelationshipCandidate,
  AssessmentRelationshipDecisionAction,
  AssessmentRelationshipStatus,
} from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner } from '../../components/ui'

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open candidates' },
  { value: 'all', label: 'All candidates' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'expired', label: 'Expired' },
]

const SIGNAL_LABELS: Record<string, string> = {
  exact_frozen_boundary: 'Exact frozen boundary',
  explicit_imported_reference: 'Imported reference',
  trusted_manifest_compatible: 'Trusted manifest match',
  deterministic_finding_overlap: 'Deterministic finding overlap',
}

function message(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) return 'Review permission is required to access relationship candidates.'
  if (error instanceof Error) return error.message
  return 'The relationship review queue could not be loaded.'
}

export function AssessmentRelationships() {
  const [status, setStatus] = useState<AssessmentRelationshipStatus | 'all'>('open')
  const [items, setItems] = useState<AssessmentRelationshipCandidate[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [predecessorCycleId, setPredecessorCycleId] = useState('')
  const [successorCycleId, setSuccessorCycleId] = useState('')
  const [importedReferenceHash, setImportedReferenceHash] = useState('')
  const [generating, setGenerating] = useState(false)
  const [selectedId, setSelectedId] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState<AssessmentRelationshipDecisionAction | ''>('')

  const load = useCallback(async (preserveError = false) => {
    setLoading(true)
    if (!preserveError) setError('')
    try {
      setItems(await api.listAssessmentRelationshipCandidates(status))
    } catch (caught) {
      setError(message(caught))
    } finally {
      setLoading(false)
    }
  }, [status])

  useEffect(() => { void load() }, [load])

  async function generate(event: React.FormEvent) {
    event.preventDefault()
    setGenerating(true)
    setError('')
    setNotice('')
    try {
      const candidate = await api.generateAssessmentRelationshipCandidate({
        predecessorCycleId: predecessorCycleId.trim(),
        successorCycleId: successorCycleId.trim(),
        importedReferenceHash: importedReferenceHash.trim() || undefined,
      })
      setNotice(`Candidate ${candidate.id} is ready for review.`)
      setPredecessorCycleId('')
      setSuccessorCycleId('')
      setImportedReferenceHash('')
      if (status === 'open' || status === 'all') {
        setItems((current) => [candidate, ...current.filter((item) => item.id !== candidate.id)])
      }
    } catch (caught) {
      setError(message(caught))
    } finally {
      setGenerating(false)
    }
  }

  async function decide(candidate: AssessmentRelationshipCandidate, action: AssessmentRelationshipDecisionAction) {
    if (reason.trim().length < 3) {
      setError('An audit reason of at least 3 characters is required.')
      return
    }
    setBusy(action)
    setError('')
    setNotice('')
    try {
      const updated = await api.decideAssessmentRelationshipCandidate(candidate, action, reason.trim())
      setItems((current) => current.map((item) => item.id === updated.id ? updated : item).filter((item) => status === 'all' || item.status === status))
      setSelectedId('')
      setReason('')
      setNotice(`Candidate ${candidate.id} was ${updated.status}.`)
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 409) {
        setError('This candidate changed or expired. The queue has been refreshed; review the latest state before retrying.')
        await load(true)
      } else {
        setError(message(caught))
      }
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-primary">Historical relationship review</h2>
          <p className="mt-1 max-w-3xl text-sm text-tertiary">
            Review deterministic candidates between singleton Assessment Cycles. Confirmation seals a blocked repair plan and never changes the Cycle graph.
          </p>
        </div>
        <Select
          ariaLabel="Filter relationship candidates by status"
          value={status}
          onValueChange={(value) => setStatus(value as AssessmentRelationshipStatus | 'all')}
          options={STATUS_OPTIONS}
          className="w-48"
        />
      </div>

      <Card title="Generate candidate">
        <form className="grid gap-4 lg:grid-cols-[1fr_1fr_1.4fr_auto] lg:items-end" onSubmit={generate}>
          <label className="space-y-1.5 text-sm font-medium text-secondary">
            Predecessor Cycle ID
            <Input required value={predecessorCycleId} onChange={(event) => setPredecessorCycleId(event.target.value)} autoComplete="off" />
          </label>
          <label className="space-y-1.5 text-sm font-medium text-secondary">
            Successor Cycle ID
            <Input required value={successorCycleId} onChange={(event) => setSuccessorCycleId(event.target.value)} autoComplete="off" />
          </label>
          <label className="space-y-1.5 text-sm font-medium text-secondary">
            Imported reference SHA-256 (optional)
            <Input
              value={importedReferenceHash}
              onChange={(event) => setImportedReferenceHash(event.target.value)}
              pattern="[0-9a-f]{64}"
              minLength={64}
              maxLength={64}
              autoComplete="off"
              aria-describedby="relationship-reference-hint"
            />
            <span id="relationship-reference-hint" className="block text-xs font-normal text-quaternary">Raw imported metadata is never submitted or stored.</span>
          </label>
          <Button type="submit" loading={generating}>Generate</Button>
        </form>
      </Card>

      <div aria-live="polite" className="space-y-3">
        {notice ? <p className="rounded-lg border border-success/30 bg-success/10 px-4 py-3 text-sm text-success">{notice}</p> : null}
        {error && (loading || items.length > 0) ? <p role="alert" className="rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">{error}</p> : null}
      </div>

      {loading ? <Spinner label="Loading relationship candidates…" /> : null}
      {!loading && error && items.length === 0 ? <div className="space-y-3"><ErrorState message={error} /><Button variant="secondary" onClick={() => void load()}>Retry</Button></div> : null}
      {!loading && !error && items.length === 0 ? (
        <EmptyState icon={Link01} title="No relationship candidates" hint="Generate a candidate only when exact boundary plus deterministic evidence is available." />
      ) : null}

      {!loading && items.length > 0 ? (
        <div className="space-y-4">
          {items.map((candidate) => {
            const selected = selectedId === candidate.id
            return (
              <Card
                key={candidate.id}
                title={<span className="font-mono text-xs">{candidate.id}</span>}
                actions={<div className="flex gap-2"><Pill>{candidate.confidence}</Pill><Pill>{candidate.status}</Pill></div>}
                bodyClass="space-y-4"
              >
                <dl className="grid gap-3 text-sm md:grid-cols-2">
                  <div><dt className="text-xs font-semibold uppercase tracking-wide text-quaternary">Proposed predecessor</dt><dd className="mt-1 font-mono text-xs text-secondary">{candidate.predecessorCycleId}<br />{candidate.predecessorAssessmentId}</dd></div>
                  <div><dt className="text-xs font-semibold uppercase tracking-wide text-quaternary">Proposed successor</dt><dd className="mt-1 font-mono text-xs text-secondary">{candidate.successorCycleId}<br />{candidate.successorAssessmentId}</dd></div>
                </dl>
                <div className="flex flex-wrap gap-2" aria-label="Candidate evidence signals">
                  {candidate.signals.map((signal) => <Pill key={signal.kind}>{SIGNAL_LABELS[signal.kind] ?? signal.kind}{signal.matchCount ? ` · ${signal.matchCount}` : ''}</Pill>)}
                </div>
                <p className="text-xs text-quaternary">Expires {new Date(candidate.expiresAt).toLocaleString()} · input <span className="font-mono">{candidate.inputHash}</span></p>

                {candidate.repairPlan ? (
                  <details className="rounded-lg border border-secondary bg-secondary/30 p-3">
                    <summary className="cursor-pointer text-sm font-semibold text-primary">Blocked repair plan</summary>
                    <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all text-xs text-secondary">{JSON.stringify(candidate.repairPlan.body, null, 2)}</pre>
                  </details>
                ) : null}

                {candidate.status === 'open' ? (
                  selected ? (
                    <div className="space-y-3 rounded-lg border border-secondary bg-secondary/30 p-4">
                      <label className="block space-y-1.5 text-sm font-medium text-secondary">
                        Audit reason
                        <textarea
                          className="min-h-24 w-full rounded-lg border border-primary bg-primary px-3 py-2 text-sm text-primary outline-none focus:ring-2 focus:ring-brand/50"
                          value={reason}
                          onChange={(event) => setReason(event.target.value)}
                          maxLength={2000}
                          required
                        />
                      </label>
                      <div className="flex flex-wrap gap-2">
                        <Button loading={busy === 'confirm'} onClick={() => void decide(candidate, 'confirm')}>Confirm and seal plan</Button>
                        <Button variant="danger" loading={busy === 'reject'} onClick={() => void decide(candidate, 'reject')}>Reject</Button>
                        <Button variant="secondary" loading={busy === 'dismiss'} onClick={() => void decide(candidate, 'dismiss')}>Dismiss</Button>
                        <Button variant="ghost" onClick={() => { setSelectedId(''); setReason(''); setError('') }}>Cancel</Button>
                      </div>
                    </div>
                  ) : <Button variant="secondary" onClick={() => { setSelectedId(candidate.id); setReason(''); setError('') }}>Review candidate</Button>
                ) : candidate.decision ? (
                  <p className="rounded-lg bg-secondary px-3 py-2 text-sm text-secondary"><strong>{candidate.decision.action}</strong> by {candidate.decision.actor}: {candidate.decision.reason}</p>
                ) : null}
              </Card>
            )
          })}
        </div>
      ) : null}
    </div>
  )
}

export default AssessmentRelationships
