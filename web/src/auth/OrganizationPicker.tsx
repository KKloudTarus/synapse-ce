import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from './AuthContext'
import { newIdempotencyKey, snapshotAuth } from '../lib/api/client'
import { ApiError, errorFromResponse } from '../lib/api/errors'

interface Membership {
  tenantId: string
  membershipId: string
  name: string
  role: string
  active: boolean
}

interface ConnectionChoice {
  id: string
  name: string
}

interface SwitchInput {
  tenantId: string
  membershipId: string
  connectionId?: string
  retryKey: string
}

type RecordValue = Record<string, unknown>

function asRecord(value: unknown): RecordValue {
  return value !== null && typeof value === 'object' ? value as RecordValue : {}
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function membershipFromWire(value: unknown): Membership {
  const membership = asRecord(value)
  return {
    tenantId: stringValue(membership.tenant_id),
    membershipId: stringValue(membership.membership_id),
    name: stringValue(membership.name),
    role: stringValue(membership.role),
    active: membership.active === true,
  }
}

function connectionsFromWire(value: unknown): ConnectionChoice[] {
  return Array.isArray(value)
    ? value.map((item) => {
      const connection = asRecord(item)
      return { id: stringValue(connection.id), name: stringValue(connection.name) }
    }).filter((connection) => connection.id !== '')
    : []
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const auth = snapshotAuth()
  let response: Response
  try {
    response = await fetch(path, auth.requestInit(init))
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!response.ok) {
    const error = await errorFromResponse(response)
    auth.notifyUnauthorized(error)
    throw error
  }
  return response.status === 204 ? null : response.json()
}

function isRetryableSwitchFailure(cause: unknown): boolean {
  return cause instanceof ApiError && (cause.status === 0 || cause.status >= 500)
}

/**
 * A tenant selector for an already authenticated person. The authoritative membership list comes
 * from the server; no organization choice, retry key, CSRF token, or authorization URL is stored.
 */
export function OrganizationPicker() {
  const { currentUser, completeOrganizationSwitch } = useAuth()
  const [memberships, setMemberships] = useState<Membership[]>([])
  const [selectedMembershipId, setSelectedMembershipId] = useState('')
  const [connections, setConnections] = useState<ConnectionChoice[]>([])
  const [selectedConnectionId, setSelectedConnectionId] = useState('')
  const [loading, setLoading] = useState(true)
  const [switching, setSwitching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [canRetry, setCanRetry] = useState(false)
  const generation = useRef(0)
  const pendingSwitch = useRef<SwitchInput | null>(null)
  const membershipsController = useRef<AbortController | null>(null)
  const switchController = useRef<AbortController | null>(null)

  const loadMemberships = useCallback(async () => {
    if (!currentUser?.membershipId) { setMemberships([]); setLoading(false); return }
    membershipsController.current?.abort()
    const requestGeneration = ++generation.current
    const controller = new AbortController()
    membershipsController.current = controller
    setLoading(true)
    setError(null)
    try {
      const response = asRecord(await request('/api/v1/identity/memberships', { signal: controller.signal }))
      if (generation.current !== requestGeneration) return
      const next = Array.isArray(response.memberships) ? response.memberships.map(membershipFromWire).filter((membership) => membership.active) : []
      setMemberships(next)
      const current = next.find((membership) => membership.membershipId === currentUser?.membershipId)
      setSelectedMembershipId(current?.membershipId ?? next[0]?.membershipId ?? '')
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      if (generation.current === requestGeneration) {
        setError(cause instanceof Error ? cause.message : 'Could not load organizations.')
        setCanRetry(isRetryableSwitchFailure(cause))
      }
    } finally {
      if (generation.current === requestGeneration) setLoading(false)
    }
  }, [currentUser?.membershipId])

  useEffect(() => {
    void loadMemberships()
    return () => {
      generation.current += 1
      membershipsController.current?.abort()
      switchController.current?.abort()
    }
  }, [loadMemberships])

  const switchTo = useCallback(async (input: SwitchInput) => {
    switchController.current?.abort()
    const controller = new AbortController()
    switchController.current = controller
    const requestGeneration = ++generation.current
    pendingSwitch.current = input
    setSwitching(true)
    setError(null)
    setCanRetry(false)
    try {
      const response = asRecord(await request('/api/auth/enterprise/switch', {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          tenant_id: input.tenantId,
          membership_id: input.membershipId,
          ...(input.connectionId ? { connection_id: input.connectionId } : {}),
          retry_key: input.retryKey,
        }),
      }))
      if (generation.current !== requestGeneration) return
      const csrfToken = stringValue(response.csrf_token)
      if (csrfToken) {
        pendingSwitch.current = null
        await completeOrganizationSwitch(csrfToken)
        return
      }
      if (response.reauthentication_required === true) {
        setConnections(connectionsFromWire(response.connections))
        setSelectedConnectionId('')
        return
      }
      const authorizationURL = stringValue(response.authorization_url)
      if (authorizationURL) {
        window.location.assign(authorizationURL)
        return
      }
      throw new Error('The organization switch response was incomplete.')
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      if (generation.current !== requestGeneration) return
      setError(cause instanceof Error ? cause.message : 'Could not switch organizations.')
      setCanRetry(isRetryableSwitchFailure(cause))
    } finally {
      if (generation.current === requestGeneration) setSwitching(false)
    }
  }, [completeOrganizationSwitch])

  const selected = memberships.find((membership) => membership.membershipId === selectedMembershipId) ?? null
  const canSwitch = selected !== null && selected.membershipId !== currentUser?.membershipId

  if (loading) return currentUser?.membershipId ? <p role="status" className="text-xs text-tertiary">Loading organizations…</p> : null
  if (memberships.length < 2) return error ? <section aria-label="Organization switcher" className="space-y-2"><p role="alert" className="text-xs text-critical">{error}</p>{canRetry ? <button type="button" className="text-xs underline" onClick={() => { void loadMemberships() }}>Retry organizations</button> : null}</section> : null

  function beginSwitch() {
    if (!selected || !canSwitch) return
    setConnections([])
    setSelectedConnectionId('')
    void switchTo({ tenantId: selected.tenantId, membershipId: selected.membershipId, retryKey: newIdempotencyKey() })
  }

  function chooseProvider() {
    const pending = pendingSwitch.current
    if (!pending || !selectedConnectionId) return
    void switchTo({ ...pending, connectionId: selectedConnectionId })
  }

  function retrySwitch() {
    const pending = pendingSwitch.current
    if (pending) void switchTo(pending)
  }

  return (
    <section aria-label="Organization switcher" className="space-y-2">
      <label className="block text-xs font-semibold text-tertiary" htmlFor="organization-picker">Organization</label>
      <select
        id="organization-picker"
        value={selectedMembershipId}
        disabled={switching}
        onChange={(event) => {
          setSelectedMembershipId(event.target.value)
          setConnections([])
          setSelectedConnectionId('')
          setError(null)
          setCanRetry(false)
        }}
        className="w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:opacity-50"
      >
        {memberships.map((membership) => <option key={membership.membershipId} value={membership.membershipId}>{membership.name} ({membership.role})</option>)}
      </select>
      <button type="button" disabled={!canSwitch || switching} onClick={beginSwitch} className="w-full rounded-lg border border-secondary px-3 py-2 text-sm font-semibold text-primary disabled:opacity-50">
        {switching ? 'Switching organization…' : 'Switch organization'}
      </button>

      {connections.length > 0 ? (
        <div className="space-y-2 rounded-lg border border-secondary p-3">
          <label className="block text-xs font-semibold text-tertiary" htmlFor="organization-switch-provider">Verify with an identity provider</label>
          <select
            id="organization-switch-provider"
            required
            value={selectedConnectionId}
            disabled={switching}
            onChange={(event) => setSelectedConnectionId(event.target.value)}
            className="w-full rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:opacity-50"
          >
            <option value="">Choose a provider</option>
            {connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.name}</option>)}
          </select>
          <button type="button" disabled={!selectedConnectionId || switching} onClick={chooseProvider} className="w-full rounded-lg bg-brand-solid px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">Continue to provider</button>
        </div>
      ) : null}

      {error ? <p role="alert" className="text-xs text-critical">{error} {canRetry ? <button type="button" onClick={retrySwitch} className="underline">Retry</button> : null}</p> : null}
    </section>
  )
}
