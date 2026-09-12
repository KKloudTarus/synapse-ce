import { useState } from 'react'
import { useOptionalAuth } from '../../auth/AuthContext'
import { Button, Card, ErrorState, Field, Input, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { OwnershipAction, OwnershipCapability, OwnershipDecision, OwnershipTeam } from '../../lib/api/ownership'
import type { CurrentUser } from '../../lib/types'
import { canTriage, Choice, ownershipError, ResolutionEvidence, TeamChoice, useOwnershipRequestKey, useOwnershipTeams } from './shared'

export function OwnershipPanel({ engagement, finding, capability, user, teams, readOnly = false, onChanged }: { engagement: string; finding: string; capability: OwnershipCapability; user: CurrentUser; teams: OwnershipTeam[]; readOnly?: boolean; onChanged?: () => void }) {
  const current = useFetch((signal) => api.findingOwnership(engagement, finding, signal), { deps: [engagement, finding] })
  const [action, setAction] = useState<OwnershipAction>('claim')
  const [team, setTeam] = useState('')
  const [assignee, setAssignee] = useState('')
  const [clearAssignee, setClearAssignee] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [showHistory, setShowHistory] = useState(false)
  const [historyRevision, setHistoryRevision] = useState(0)
  const requestKey = useOwnershipRequestKey()
  const writable = canTriage(user) && !readOnly
  async function apply() {
    if (!current.data) return
    const input = {
      action,
      ...(action === 'assign' || action === 'transfer' ? { team_id: team, assignee_id: assignee, ...(action === 'transfer' ? { clear_assignee: clearAssignee } : {}) } : {}),
      finding_version: current.data.finding_version,
      ownership_revision: current.data.assignment.revision,
      manual_generation: current.data.assignment.manual_generation,
    }
    setBusy(true); setError(''); setSuccess('')
    try {
      await api.assignOwnership(engagement, finding, input, requestKey({ engagement, finding, input }))
      setSuccess(action === 'release' ? 'Automatic routing queued.' : 'Ownership updated.')
      setHistoryRevision((value) => value + 1); current.refetch(); onChanged?.()
    } catch (error) { setError(ownershipError(error)) }
    finally { setBusy(false) }
  }
  const name = (id?: string) => teams.find((team) => team.id === id)?.name ?? id ?? 'Unassigned'
  return <Card title="Finding ownership" actions={<Button variant="ghost" onClick={current.refetch} disabled={busy || current.loading}>Reload</Button>}>
    <div className="space-y-4">
      {current.loading && <Spinner label="Loading owner…" />}
      {current.error && <ErrorState message={current.error} />}
      {current.data && <>
        <div className="flex flex-wrap items-center gap-2"><strong>{name(current.data.assignment.team_id)}</strong><Pill>{current.data.assignment.mode}</Pill><Pill>{current.data.resolution}</Pill></div>
        <p className="text-sm text-secondary">{current.data.reason.replaceAll('_', ' ')}{current.data.finding_assignee ? ` · Assignee: ${current.data.finding_assignee}` : ''}</p>
        {current.data.assignment.mode === 'manual' && <p className="text-sm text-secondary">Automatic scans preserve this assignment. Clear keeps manual protection; release allows routing again.</p>}
        {writable ? <div className="space-y-3 border-t border-secondary pt-4">
          <Field label="Ownership action"><Choice value={action} aria-label="Ownership action" onChange={(event) => { setAction(event.target.value as OwnershipAction); setError(''); setSuccess('') }} disabled={busy}>
            <option value="claim">Claim for myself</option><option value="assign">Assign team / person</option><option value="transfer">Transfer team</option><option value="clear">Clear assignment and protect</option><option value="release">Release to automatic routing</option>
          </Choice></Field>
          {(action === 'assign' || action === 'transfer') && <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Destination team"><TeamChoice teams={teams} value={team} onChange={setTeam} disabled={busy} label="Destination team" /></Field>
            <Field label="Assignee user ID" hint={action === 'transfer' ? 'Leave empty to preserve an eligible assignee, or explicitly clear below.' : 'Optional. The person must be an active member of the selected team.'}><Input value={assignee} disabled={busy || clearAssignee && action === 'transfer'} onChange={(event) => setAssignee(event.target.value)} /></Field>
          </div>}
          {action === 'transfer' && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={clearAssignee} disabled={busy} onChange={(event) => { setClearAssignee(event.target.checked); if (event.target.checked) setAssignee('') }} />Clear the current assignee during transfer</label>}
          {action === 'claim' && <p className="text-xs text-secondary">You must be an active member of the owning team.</p>}
          {action === 'release' && (!capability.routing_available || capability.mode !== 'enforce') && <p className="text-sm text-warning-primary">Release requires an available worker in enforce mode.</p>}
          <Button onClick={() => void apply()} loading={busy} disabled={current.loading || action === 'transfer' && !team || action === 'claim' && !current.data.assignment.team_id || action === 'release' && (!capability.routing_available || capability.mode !== 'enforce')}>Apply ownership action</Button>
        </div> : <p className="text-sm text-secondary">Ownership is read-only for this view.</p>}
      </>}
      {error && <ErrorState message={error} />}{success && <p role="status" className="text-sm text-success-primary">{success}</p>}
      <Button variant="secondary" onClick={() => setShowHistory((value) => !value)}>{showHistory ? 'Hide history' : 'Show ownership history'}</Button>
      {showHistory && <OwnershipHistory key={`${engagement}:${finding}:${historyRevision}`} engagement={engagement} finding={finding} teams={teams} />}
    </div>
  </Card>
}

function OwnershipHistory({ engagement, finding, teams }: { engagement: string; finding: string; teams: OwnershipTeam[] }) {
  const [cursor, setCursor] = useState<string>()
  const history = useFetch(() => api.findingOwnershipHistory(engagement, finding, cursor), { deps: [engagement, finding, cursor] })
  return <div className="space-y-3">
    {history.loading && <Spinner label="Loading history…" />}{history.error && <ErrorState message={history.error} />}
    {history.data?.items.length === 0 && <p className="text-sm text-secondary">No ownership decisions yet.</p>}
    {history.data?.items.map((decision: OwnershipDecision) => <article key={decision.id} className="space-y-2 rounded-lg border border-secondary p-3"><p className="text-xs text-tertiary">{new Date(decision.created_at).toLocaleString()} · {decision.actor}</p><ResolutionEvidence result={decision.result} teams={teams} /><p className="text-xs text-secondary">{decision.before.mode} → {decision.after.mode}</p></article>)}
    <div className="flex gap-2">{cursor && <Button variant="secondary" onClick={() => setCursor(undefined)}>Latest decisions</Button>}{history.data?.next && <Button variant="secondary" onClick={() => setCursor(history.data?.next)} disabled={history.loading}>Older decisions</Button>}</div>
  </div>
}

// Existing finding pages stay usable on deployments without this optional
// feature. Fetch ownership only after an authenticated human is available.
export function FindingOwnership({ engagement, finding, version, readOnly, onChanged }: { engagement: string; finding: string; version: number; readOnly?: boolean; onChanged: () => void }) {
  const auth = useOptionalAuth()
  const capability = useFetch((signal) => api.ownershipCapability(signal), { enabled: !!auth?.currentUser })
  if (!auth?.currentUser || !capability.data?.enabled) return null
  return <EmbeddedOwnership key={`${finding}:${version}`} engagement={engagement} finding={finding} capability={capability.data} user={auth.currentUser} readOnly={readOnly} onChanged={onChanged} />
}
function EmbeddedOwnership(props: Omit<Parameters<typeof OwnershipPanel>[0], 'teams'>) {
  const state = useOwnershipTeams()
  return <div className="space-y-2">{state.error && <ErrorState message={state.error} />}<OwnershipPanel {...props} teams={state.teams} />{state.next && <Button variant="secondary" onClick={() => void state.more()} disabled={state.loading}>Load more teams</Button>}</div>
}
