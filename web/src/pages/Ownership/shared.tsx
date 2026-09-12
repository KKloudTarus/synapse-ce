import { useEffect, useRef, useState, type ReactNode, type SelectHTMLAttributes } from 'react'
import { Link } from 'react-router-dom'
import { Button, Card, ErrorState, Pill, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { newIdempotencyKey } from '../../lib/api/client'
import type { OwnershipCapability, OwnershipResult, OwnershipTeam } from '../../lib/api/ownership'
import type { CurrentUser } from '../../lib/types'

export const controlClass = 'w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 disabled:opacity-50'
export function Choice({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${controlClass} ${props.className ?? ''}`}>{children}</select>
}
export function ownershipError(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) return 'This item changed. Reload the latest state, review it and try again.'
  if (error instanceof ApiError && error.status === 403) return 'Your account does not have permission for this action.'
  if (error instanceof ApiError && error.status === 503) return 'Routing is unavailable. Check the ownership worker and try again.'
  return error instanceof Error ? error.message : 'The request failed. Try again.'
}
export const canTriage = (user: CurrentUser | null) => !!user && ['admin', 'consultant', 'member', 'reviewer'].includes(user.role)
export function OwnershipBoundary({ children, admin = false }: { children: (cap: OwnershipCapability, user: CurrentUser) => ReactNode; admin?: boolean }) {
  const state = useFetch(async (signal) => {
    const [cap, user] = await Promise.all([api.ownershipCapability(signal), api.me()])
    return { cap, user }
  })
  if (state.loading) return <Spinner label="Loading ownership…" />
  if (state.error) return <div className="space-y-3"><ErrorState message={state.error} /><Button onClick={state.refetch}>Try again</Button></div>
  if (!state.data?.cap.enabled) return <Card title="Finding ownership is not enabled"><p className="text-sm text-secondary">Ask your administrator to enable finding ownership for this deployment.</p></Card>
  if (admin && state.data.user.role !== 'admin') return <Card title="Administrator access required"><p className="text-sm text-secondary">Administrators manage teams and routing policies. You can review findings in the <Link className="text-brand-secondary underline" to="/ownership">team inbox</Link>.</p></Card>
  return <>{children(state.data.cap, state.data.user)}</>
}

export function useOwnershipTeams() {
  const [teams, setTeams] = useState<OwnershipTeam[]>([])
  const [next, setNext] = useState<string>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const generation = useRef(0)
  async function load(cursor?: string) {
    const revision = ++generation.current
    setLoading(true); setError('')
    try {
      const page = await api.ownershipTeams(cursor)
      if (revision !== generation.current) return
      setTeams((old) => cursor ? [...old, ...page.items.filter((team) => !old.some((item) => item.id === team.id))] : page.items)
      setNext(page.next)
    } catch (error) { if (revision === generation.current) setError(ownershipError(error)) }
    finally { if (revision === generation.current) setLoading(false) }
  }
  useEffect(() => { void load() }, [])
  return { teams, next, loading, error, reload: () => load(), more: () => load(next) }
}

export function TeamChoice({ teams, value, onChange, disabled, label = 'Team', allowEmpty = true }: { teams: OwnershipTeam[]; value: string; onChange: (id: string) => void; disabled?: boolean; label?: string; allowEmpty?: boolean }) {
  return <Choice aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled}>
    <option value="">{allowEmpty ? 'No team selected' : 'Choose a team'}</option>
    {value && !teams.some((team) => team.id === value) && <option value={value}>{value}</option>}
    {teams.map((team) => <option key={team.id} value={team.id} disabled={team.archived}>{team.name}{team.archived ? ' (archived)' : ''}</option>)}
  </Choice>
}

export function ResolutionEvidence({ result, teams }: { result: OwnershipResult; teams: OwnershipTeam[] }) {
  const name = (id: string) => teams.find((team) => team.id === id)?.name ?? id
  return <div className="space-y-2 text-sm">
    <div className="flex flex-wrap gap-2"><Pill>{result.resolution}</Pill><span>{result.reason.replaceAll('_', ' ')}</span>{result.team_id && <strong>{name(result.team_id)}</strong>}</div>
    {result.candidates?.length > 1 && <p className="text-secondary">Candidates: {result.candidates.map(name).join(', ')}</p>}
    {!!result.evidence?.length && <details><summary className="cursor-pointer text-brand-secondary">Path evidence ({result.evidence.length})</summary><ul className="mt-2 space-y-2">
      {result.evidence.map((evidence, i) => <li key={`${evidence.path}-${i}`} className="break-words rounded border border-secondary p-2"><code>{evidence.path}</code><p className="text-secondary">{evidence.reason.replaceAll('_', ' ')}{evidence.line ? ` · line ${evidence.line}: ${evidence.pattern}` : ''}</p>{evidence.owners?.length ? <p>{evidence.owners.join(', ')}</p> : null}</li>)}
    </ul></details>}
  </div>
}

// Keep the same key for a network retry with the same body. Changed input is a
// new operation; never recycle a bulk reservation for a different selection.
export function useOwnershipRequestKey() {
  const ref = useRef({ body: '', key: '' })
  return (body: unknown) => {
    const encoded = JSON.stringify(body)
    if (encoded !== ref.current.body) ref.current = { body: encoded, key: newIdempotencyKey() }
    return ref.current.key
  }
}

export const findingHref = (engagement: string, finding: string) => `/engagements/${encodeURIComponent(engagement)}/findings#finding-${encodeURIComponent(finding)}`
