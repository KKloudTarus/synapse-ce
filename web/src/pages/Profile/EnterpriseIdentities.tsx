import { useEffect, useRef, useState } from 'react'
import { InvitationAcceptance } from '../../auth/InvitationAcceptance'
import { useOptionalAuth } from '../../auth/AuthContext'
import { snapshotAuth } from '../../lib/api/client'
import { ApiError, errorFromResponse } from '../../lib/api/errors'

type Identity = { connectionId: string; name: string; state: string }
type Connection = { id: string; name: string }

function record(value: unknown): Record<string, unknown> { return value !== null && typeof value === 'object' ? value as Record<string, unknown> : {} }
function text(value: unknown): string { return typeof value === 'string' ? value : '' }
function identities(value: unknown): Identity[] {
  const items = record(value).identities
  return Array.isArray(items) ? items.map((item) => {
    const candidate = record(item)
    return { connectionId: text(candidate.connection_id), name: text(candidate.name), state: text(candidate.state) }
  }).filter((item) => item.connectionId && item.name) : []
}
function connections(value: unknown): Connection[] {
  const items = record(value).connections
  return Array.isArray(items) ? items.map((item) => {
    const candidate = record(item)
    return { id: text(candidate.id), name: text(candidate.name) }
  }).filter((item) => item.id && item.name) : []
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const auth = snapshotAuth()
  let response: Response
  try { response = await fetch(path, auth.requestInit(init)) } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!response.ok) {
    const error = await errorFromResponse(response)
    auth.notifyUnauthorized(error)
    throw error
  }
  return response.json()
}

/** Lists identities for the signed-in person and starts a server-approved link or step-up flow. */
export function EnterpriseIdentities() {
  const auth = useOptionalAuth()
  const [linked, setLinked] = useState<Identity[]>([])
  const [available, setAvailable] = useState<Connection[]>([])
  const [connectionId, setConnectionId] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const generation = useRef(0)

  useEffect(() => {
    const attempt = ++generation.current
    const controller = new AbortController()
    let cancelled = false
    void Promise.all([
      request('/api/v1/identity/authenticators', { signal: controller.signal }),
      request('/api/v1/identity/link-connections', { signal: controller.signal }),
    ]).then(([authenticators, providerConnections]) => {
      if (cancelled || attempt !== generation.current) return
      const next = connections(providerConnections)
      setLinked(identities(authenticators)); setAvailable(next); setConnectionId(next.length === 1 ? next[0].id : '')
    }).catch((cause: unknown) => {
      if (!cancelled && attempt === generation.current && !(cause instanceof DOMException && cause.name === 'AbortError')) setError(cause instanceof Error ? cause.message : 'Could not load enterprise identities.')
    }).finally(() => { if (!cancelled && attempt === generation.current) setLoading(false) })
    return () => { cancelled = true; controller.abort() }
  }, [])

  async function begin() {
    if (!connectionId) return
    const attempt = ++generation.current
    setSubmitting(true); setError(null)
    try {
      const value = record(await request('/api/auth/enterprise/begin', {
        method: 'POST', body: JSON.stringify({ purpose: auth?.currentUser?.recentAuth === false ? 'step_up' : 'link', connection_id: connectionId }),
      }))
      if (attempt !== generation.current) return
      const authorizationURL = text(value.authorization_url)
      if (!authorizationURL) throw new Error('The identity provider did not return an authorization destination.')
      window.location.assign(authorizationURL)
    } catch (cause) {
      if (attempt === generation.current && !(cause instanceof DOMException && cause.name === 'AbortError')) setError(cause instanceof Error ? cause.message : 'Could not start identity linking.')
    } finally { if (attempt === generation.current) setSubmitting(false) }
  }

  const requiresStepUp = auth?.currentUser?.recentAuth === false
  return <section aria-labelledby="enterprise-identities-heading" className="space-y-4 border-t border-secondary pt-6">
    <header className="space-y-1"><h2 id="enterprise-identities-heading" className="text-xl font-semibold text-primary">Enterprise identities</h2><p className="text-sm text-tertiary">Link an approved work identity or accept an organization invitation.</p></header>
    {loading ? <p role="status" className="text-sm text-tertiary">Loading enterprise identities…</p> : <>
      {linked.length ? <ul className="overflow-hidden rounded-xl border border-secondary bg-primary divide-y divide-secondary">{linked.map((identity) => <li key={identity.connectionId} className="px-4 py-3 text-sm text-primary">{identity.name} · {identity.state}</li>)}</ul> : <p className="rounded-xl border border-secondary bg-secondary/30 p-4 text-sm text-tertiary">No linked enterprise identities.</p>}
      {available.length ? <div className="space-y-3 rounded-xl border border-secondary bg-primary p-4 sm:p-5">
        <label htmlFor="identity-provider" className="block text-sm font-medium text-primary">Approved identity provider</label>
        <select id="identity-provider" value={connectionId} disabled={submitting} onChange={(event) => setConnectionId(event.target.value)} className="w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-sm text-primary shadow-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20 disabled:opacity-50">
          <option value="">Choose a provider</option>{available.map((connection) => <option key={connection.id} value={connection.id}>{connection.name}</option>)}
        </select>
        {requiresStepUp ? <p className="text-sm text-tertiary">Reauthenticate with an approved provider before linking an identity.</p> : null}
        <button type="button" disabled={!connectionId || submitting} onClick={() => { void begin() }} className="w-full sm:w-auto rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-brand-solid_hover disabled:cursor-not-allowed disabled:opacity-50">{submitting ? 'Opening provider…' : requiresStepUp ? 'Reauthenticate to link' : 'Link identity'}</button>
      </div> : <p className="rounded-xl border border-secondary bg-secondary/30 p-4 text-sm text-tertiary">No additional identity providers are approved for this organization.</p>}
    </>}
    {error ? <p role="alert" className="rounded-lg border border-error-subtle bg-error-primary/10 p-3 text-sm text-error-primary">{error}</p> : null}
    <InvitationAcceptance />
  </section>
}
