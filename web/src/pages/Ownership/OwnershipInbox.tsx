import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Button, Card, ErrorState, Field, Input, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { OwnershipAction, OwnershipBulkResult, OwnershipCapability, OwnershipFilter, OwnershipFinding } from '../../lib/api/ownership'
import type { CurrentUser } from '../../lib/types'
import { OwnershipPanel } from './OwnershipPanel'
import { canTriage, Choice, findingHref, OwnershipBoundary, ownershipError, TeamChoice, useOwnershipRequestKey, useOwnershipTeams } from './shared'

export function OwnershipInbox() {
  return <OwnershipBoundary>{(capability, user) => <Inbox capability={capability} user={user} />}</OwnershipBoundary>
}

function findingKey(item: Pick<OwnershipFinding, 'engagement_id' | 'id'>) {
  return `${item.engagement_id}:${item.id}`
}

function resultKey(item: Pick<OwnershipBulkResult, 'engagement_id' | 'finding_id'>) {
  return `${item.engagement_id}:${item.finding_id}`
}

function Inbox({ capability, user }: { capability: OwnershipCapability; user: CurrentUser }) {
  const [params, setParams] = useSearchParams()
  const [cursor, setCursor] = useState<string>()
  const [previous, setPrevious] = useState<Array<string | undefined>>([])
  const [selected, setSelected] = useState<string[]>([])
  const [opened, setOpened] = useState<OwnershipFinding>()
  const [action, setAction] = useState<OwnershipAction>('claim')
  const [team, setTeam] = useState('')
  const [assignee, setAssignee] = useState('')
  const [clear, setClear] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [outcomes, setOutcomes] = useState<OwnershipBulkResult[]>([])
  const teams = useOwnershipTeams()
  const engagements = useFetch(() => api.listEngagements())
  const filter: OwnershipFilter = {
    engagement_id: params.get('engagement_id') || undefined, team_id: params.get('team_id') || undefined,
    severity: params.get('severity') || undefined, kind: params.get('kind') || undefined,
    status: params.get('status') || undefined, sla_status: params.get('sla_status') || undefined,
    due_before: params.get('due_before') || undefined,
    ...(params.get('scope') === 'my_teams' ? { my_teams: true } : {}),
    ...(params.get('scope') === 'mine' ? { mine: true } : {}),
    ...(params.get('scope') === 'unresolved' ? { unresolved: true } : {}),
  }
  const serialized = JSON.stringify(filter)
  const page = useFetch((signal) => api.ownershipInbox(filter, cursor, signal), { deps: [serialized, cursor] })
  const requestKey = useOwnershipRequestKey()
  function change(name: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value); else next.delete(name)
    setParams(next); setCursor(undefined); setPrevious([]); setSelected([]); setOpened(undefined); setOutcomes([])
  }
  const items = page.data?.items ?? []
  const chosen = items.filter((item) => selected.includes(findingKey(item)))
  async function applyBulk() {
    const input = chosen.map((item) => ({
      engagement_id: item.engagement_id, finding_id: item.id, action,
      ...(action === 'assign' || action === 'transfer' ? { team_id: team, assignee_id: assignee, ...(action === 'transfer' ? { clear_assignee: clear } : {}) } : {}),
      finding_version: item.version, ownership_revision: item.assignment.revision, manual_generation: item.assignment.manual_generation,
    }))
    setBusy(true); setError(''); setOutcomes([])
    try {
      const result = await api.bulkOwnership(input, requestKey(input))
      setOutcomes(result); setSelected(result.filter((item) => item.status !== 200).map(resultKey)); page.refetch()
    } catch (error) { setError(ownershipError(error)) }
    finally { setBusy(false) }
  }
  return <div className="mx-auto max-w-[1600px] space-y-5 pb-12">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-bold text-primary">Team inbox</h1><p className="mt-1 text-sm text-secondary">Review routed findings, take ownership and track your team's work.</p></div><Link to="/settings/ownership" className="text-sm font-semibold text-brand-secondary">Manage ownership</Link></header>
    {capability.mode === 'observe' && <p className="rounded-lg bg-secondary p-3 text-sm text-secondary">Observe mode evaluates routing without changing assignments. Manual triage remains available.</p>}
    {!capability.routing_available && <p role="status" className="text-sm text-warning-primary">The routing worker is unavailable. Existing assignments and manual triage remain accessible.</p>}
    <Card title="Filter findings"><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Field label="Work queue"><Choice aria-label="Work queue" value={params.get('scope') ?? ''} onChange={(event) => change('scope', event.target.value)}><option value="">All findings</option><option value="my_teams">My teams</option><option value="mine">Assigned to me</option><option value="unresolved">Unresolved</option></Choice></Field>
      <Field label="Owning team"><TeamChoice teams={teams.teams} value={params.get('team_id') ?? ''} onChange={(value) => change('team_id', value)} label="Owning team" /></Field>
      <Field label="Engagement"><Choice value={params.get('engagement_id') ?? ''} onChange={(event) => change('engagement_id', event.target.value)}><option value="">All engagements</option>{engagements.data?.map((eng) => <option key={eng.id} value={eng.id}>{eng.name}</option>)}</Choice></Field>
      <Field label="Severity"><Choice value={params.get('severity') ?? ''} onChange={(event) => change('severity', event.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map((value) => <option key={value}>{value}</option>)}</Choice></Field>
      <Field label="Finding kind"><Choice value={params.get('kind') ?? ''} onChange={(event) => change('kind', event.target.value)}><option value="">All kinds</option>{['sast', 'sca', 'secret', 'misconfig', 'dast', 'cloud_posture', 'manual', 'exploitation', 'threat', 'recon', 'hypothesis', 'quality', 'reliability'].map((value) => <option key={value}>{value}</option>)}</Choice></Field>
      <Field label="Finding status"><Choice value={params.get('status') ?? ''} onChange={(event) => change('status', event.target.value)}><option value="">All statuses</option>{['open', 'triage', 'confirmed', 'false_positive', 'remediated'].map((value) => <option key={value}>{value}</option>)}</Choice></Field>
      <Field label="SLA status"><Choice value={params.get('sla_status') ?? ''} onChange={(event) => change('sla_status', event.target.value)}><option value="">Any SLA state</option>{['open', 'mitigating', 'remediated', 'accepted_risk'].map((value) => <option key={value}>{value}</option>)}</Choice></Field>
      <Field label="Remediation due before"><Input type="date" value={(params.get('due_before') ?? '').slice(0, 10)} onChange={(event) => change('due_before', event.target.value ? `${event.target.value}T23:59:59Z` : '')} /></Field>
    </div>{teams.next && <Button className="mt-3" variant="secondary" disabled={teams.loading} onClick={() => void teams.more()}>Load more teams</Button>}{(teams.error || engagements.error) && <ErrorState message={teams.error || engagements.error || ''} />}</Card>
    {page.error && <ErrorState message={page.error} />}
    <Card title={`${page.data?.total ?? 0} findings`} actions={<Button variant="secondary" onClick={page.refetch} disabled={page.loading || busy}>Refresh inbox</Button>} bodyClass="p-0">
      {page.loading ? <Spinner label="Loading findings…" /> : <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-secondary bg-secondary text-tertiary"><tr>
        {canTriage(user) && <th className="p-3"><input type="checkbox" aria-label="Select this page" checked={items.length > 0 && chosen.length === items.length} disabled={!items.length || busy} onChange={(event) => setSelected(event.target.checked ? items.map(findingKey) : [])} /></th>}
        <th className="p-3">Finding</th><th className="p-3">Owner</th><th className="p-3">Status / SLA</th><th className="p-3">Routing</th><th className="p-3">Details</th>
      </tr></thead><tbody className="divide-y divide-secondary">{items.map((item) => <tr key={`${item.engagement_id}:${item.id}`}>
        {canTriage(user) && <td className="p-3"><input type="checkbox" aria-label={`Select ${item.title}`} checked={selected.includes(findingKey(item))} disabled={busy} onChange={(event) => setSelected((old) => event.target.checked ? [...old, findingKey(item)] : old.filter((id) => id !== findingKey(item)))} /></td>}
        <td className="max-w-md p-3"><Link to={findingHref(item.engagement_id, item.id)} className="font-semibold text-brand-secondary">{item.title}</Link><p className="mt-1 text-xs text-tertiary">{item.severity} · {item.kind}</p></td>
        <td className="p-3"><p>{teams.teams.find((team) => team.id === item.assignment.team_id)?.name ?? item.assignment.team_id ?? 'Unassigned'}</p><p className="text-xs text-tertiary">{item.assignment.legacy_assignee || 'No individual assignee'}</p></td>
        <td className="p-3"><Pill>{item.status}</Pill>{item.remediate_by && <p className="mt-1 text-xs">Due {new Date(item.remediate_by).toLocaleString()}</p>}{item.sla_status && <p className="text-xs text-secondary">{item.sla_status.replaceAll('_', ' ')}</p>}</td>
        <td className="p-3"><Pill>{item.assignment.mode}</Pill><p className="mt-1 text-xs text-secondary">{item.reason.replaceAll('_', ' ')}</p></td>
        <td className="p-3"><Button variant="secondary" onClick={() => setOpened(item)}>View ownership</Button></td>
      </tr>)}</tbody></table>{items.length === 0 && <p className="p-8 text-center text-secondary">No findings match these filters.</p>}</div>}
      <div className="flex items-center justify-between border-t border-secondary p-3"><span className="text-xs text-tertiary">{items.length} shown · ordered by finding ID</span><div className="flex gap-2"><Button variant="secondary" disabled={!previous.length || page.loading || busy} onClick={() => { setCursor(previous[previous.length - 1]); setPrevious((old) => old.slice(0, -1)); setSelected([]) }}>Previous</Button><Button variant="secondary" disabled={!page.data?.next || page.loading || busy} onClick={() => { setPrevious((old) => [...old, cursor]); setCursor(page.data?.next); setSelected([]) }}>Next</Button></div></div>
    </Card>
    {canTriage(user) && chosen.length > 0 && <Card title={`Update ${chosen.length} selected findings`}><div className="space-y-3">
      <Field label="Bulk action"><Choice value={action} onChange={(event) => { setAction(event.target.value as OwnershipAction); setOutcomes([]) }} disabled={busy}><option value="claim">Claim for myself</option><option value="assign">Assign team / person</option><option value="transfer">Transfer team</option><option value="clear">Clear and keep manual protection</option><option value="release">Release to automatic routing</option></Choice></Field>
      {(action === 'assign' || action === 'transfer') && <div className="grid gap-3 sm:grid-cols-2"><Field label="Destination team"><TeamChoice teams={teams.teams} value={team} onChange={setTeam} label="Bulk destination team" disabled={busy} /></Field><Field label="Assignee user ID"><Input value={assignee} onChange={(event) => setAssignee(event.target.value)} disabled={busy || clear && action === 'transfer'} /></Field></div>}
      {action === 'transfer' && <label className="flex gap-2 text-sm"><input type="checkbox" checked={clear} onChange={(event) => { setClear(event.target.checked); if (event.target.checked) setAssignee('') }} disabled={busy} />Clear the current assignee during transfer</label>}
      <p className="text-xs text-secondary">Each finding is updated independently. Conflicts stay selected for review; successful updates are kept.</p>
      <Button loading={busy} onClick={() => void applyBulk()} disabled={page.loading || action === 'transfer' && !team || action === 'release' && (capability.mode !== 'enforce' || !capability.routing_available)}>Apply to selected findings</Button>
    </div></Card>}
    {error && <ErrorState message={error} />}
    {!!outcomes.length && <div role="status" className="rounded-lg border border-secondary p-4 text-sm"><p>{outcomes.filter((item) => item.status === 200).length} updated; {outcomes.filter((item) => item.status !== 200).length} need review.</p>{outcomes.filter((item) => item.status !== 200).map((item) => <p key={resultKey(item)}>{item.engagement_id}/{item.finding_id}: {item.status === 409 ? 'Changed since you loaded it. Review before retrying.' : item.error}</p>)}</div>}
    {opened && <div className="space-y-2"><div className="flex items-center justify-between"><h2 className="font-semibold">{opened.title}</h2><Button variant="ghost" onClick={() => setOpened(undefined)}>Close details</Button></div><OwnershipPanel key={`${opened.id}:${opened.version}`} engagement={opened.engagement_id} finding={opened.id} capability={capability} user={user} teams={teams.teams} onChanged={page.refetch} /></div>}
  </div>
}
