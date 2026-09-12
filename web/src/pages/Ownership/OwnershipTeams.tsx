import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Button, Card, ErrorState, Field, Input, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { OwnershipTeam } from '../../lib/api/ownership'
import { Choice, ownershipError, useOwnershipTeams } from './shared'

export function OwnershipTeams() {
  const state = useOwnershipTeams()
  const [selected, setSelected] = useState('')
  const [editing, setEditing] = useState<OwnershipTeam>()
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const selectedTeam = state.teams.find((team) => team.id === selected)
  async function save(archive?: OwnershipTeam) {
    setBusy(true); setError(''); setNotice('')
    try {
      const current = archive ?? state.teams.find((team) => team.id === editing?.id)
      const team = await api.saveOwnershipTeam({ name: archive?.name ?? name, slug: archive?.slug ?? slug, archived: archive ? !archive.archived : current?.archived ?? false, revision: current?.revision ?? 0 }, current?.id)
      setNotice(`${team.name} saved.`); setEditing(undefined); setName(''); setSlug(''); setSelected(team.id); await state.reload()
    } catch (error) { setError(ownershipError(error)) }
    finally { setBusy(false) }
  }
  return <div className="space-y-4">
    <p className="text-sm text-secondary">Teams group findings within your tenant. Membership does not expand access to engagements. <Link className="text-brand-secondary underline" to="/settings/team">Manage users and API keys</Link>.</p>
    {(state.error || error) && <ErrorState message={error || state.error} />}{notice && <p role="status" className="text-sm text-success-primary">{notice}</p>}
    <Card title={editing ? `Edit ${editing.name}` : 'Create ownership team'}>
      <form className="grid items-end gap-3 sm:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void save() }}>
        <Field label="Team name"><Input aria-label="Team name" value={name} onChange={(event) => setName(event.target.value)} maxLength={200} required disabled={busy} /></Field>
        <Field label="Team slug" hint="Lowercase letters, numbers and hyphens."><Input aria-label="Team slug" value={slug} onChange={(event) => setSlug(event.target.value)} maxLength={80} pattern="[a-z0-9]+(-[a-z0-9]+)*" required disabled={busy} /></Field>
        <div className="flex gap-2"><Button type="submit" loading={busy} disabled={state.loading}>{editing ? 'Save team' : 'Create team'}</Button>{editing && <Button type="button" variant="secondary" onClick={() => { setEditing(undefined); setName(''); setSlug('') }}>Cancel edit</Button>}</div>
      </form>
    </Card>
    <Card title="Ownership teams" actions={<Button variant="secondary" disabled={busy || state.loading} onClick={() => void state.reload()}>Reload teams</Button>}>
      {state.loading && <Spinner label="Loading teams…" />}
      {!state.loading && state.teams.length === 0 && <p className="text-sm text-secondary">Create a team to start routing findings.</p>}
      <div className="divide-y divide-secondary">{state.teams.map((team) => <div key={team.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><strong>{team.name}</strong><span className="ml-2 text-sm text-tertiary">{team.slug}</span>{team.archived && <Pill>archived</Pill>}</div><div className="flex gap-2"><Button variant="secondary" onClick={() => setSelected(team.id)}>Members</Button><Button variant="ghost" disabled={busy} onClick={() => { setEditing(team); setName(team.name); setSlug(team.slug) }}>Edit</Button><Button variant="ghost" disabled={busy || state.loading} onClick={() => void save(team)}>{team.archived ? 'Restore' : 'Archive'}</Button></div></div>)}</div>
      {state.next && <Button variant="secondary" disabled={state.loading} onClick={() => void state.more()}>Load more teams</Button>}
    </Card>
    {selectedTeam && <TeamMembers team={selectedTeam} onChanged={state.reload} />}
  </div>
}

function TeamMembers({ team, onChanged }: { team: OwnershipTeam; onChanged: () => Promise<void> }) {
  const [cursor, setCursor] = useState<string>()
  const [user, setUser] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const members = useFetch(() => api.ownershipMembers(team.id, cursor), { deps: [team.id, team.revision, cursor] })
  const users = useFetch(() => api.listUsers())
  async function change(id: string, remove: boolean) {
    setBusy(true); setError('')
    try { await api.setOwnershipMember(team.id, id, team.revision, remove); setUser(''); await onChanged(); members.refetch() }
    catch (error) { setError(ownershipError(error)) }
    finally { setBusy(false) }
  }
  return <Card title={`${team.name} members`}><div className="space-y-4">
    {(error || members.error || users.error) && <ErrorState message={error || members.error || users.error || ''} />}
    <div className="flex flex-wrap items-end gap-3"><Field label="Add member"><Choice value={user} onChange={(event) => setUser(event.target.value)} disabled={busy || team.archived} aria-label="Add team member"><option value="">Choose a user</option>{users.data?.filter((user) => !user.disabled).map((user) => <option key={user.id} value={user.id}>{user.name} · {user.role}</option>)}</Choice></Field><Button disabled={!user || busy || team.archived || members.loading} onClick={() => void change(user, false)}>Add member</Button></div>
    {members.loading && <Spinner label="Loading members…" />}
    {members.data?.items.length === 0 && <p className="text-sm text-secondary">This team has no members.</p>}
    <ul className="divide-y divide-secondary">{members.data?.items.map((member) => { const identity = users.data?.find((user) => user.id === member.user_id); return <li key={member.user_id} className="flex items-center justify-between gap-3 py-2"><span>{identity?.name ?? member.user_id}{identity?.disabled && <Pill>disabled</Pill>}</span><Button variant="ghost" disabled={busy || members.loading} onClick={() => void change(member.user_id, true)}>Remove member</Button></li> })}</ul>
    <div className="flex gap-2">{cursor && <Button variant="secondary" onClick={() => setCursor(undefined)}>First members</Button>}{members.data?.next && <Button variant="secondary" onClick={() => setCursor(members.data?.next)} disabled={members.loading}>More members</Button>}</div>
  </div></Card>
}
