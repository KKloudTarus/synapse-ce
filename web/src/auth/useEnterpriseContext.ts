import { useCallback, useEffect, useRef, useState } from 'react'
import { setCSRFToken } from '../lib/api'
import { errorFromResponse } from '../lib/api/errors'

export type EnterpriseConnection = Readonly<{ id: string; name: string }>
export type EnterpriseContext = Readonly<{
  tenantId: string
  requirement: 'optional' | 'required'
  connections: EnterpriseConnection[]
  bootstrapEligible: boolean
}>

type ContextState =
  | Readonly<{ status: 'loading'; context: null; message: null }>
  | Readonly<{ status: 'legacy'; context: null; message: null }>
  | Readonly<{ status: 'ready'; context: EnterpriseContext; message: null }>
  | Readonly<{ status: 'error'; context: null; message: string }>

type EnterpriseContextResponse = {
  enabled?: unknown
  tenant_id?: unknown
  requirement?: unknown
  connections?: unknown
  bootstrap_eligible?: unknown
}

function contextFailure(status: number): string {
  if (status === 503) return 'Enterprise sign-in is temporarily unavailable. Try again.'
  if (status === 0) return 'Enterprise sign-in could not be reached. Check your connection and try again.'
  return 'Could not load enterprise sign-in. Try again.'
}

function actionFailure(status: number, action: 'begin' | 'recovery'): string {
  if (status === 503 || status === 0) {
    return action === 'begin'
      ? 'Enterprise sign-in is temporarily unavailable. Try again.'
      : 'Emergency activation is temporarily unavailable. Try again.'
  }
  return action === 'begin' ? 'Could not start enterprise sign-in. Try again.' : 'Emergency activation could not be completed.'
}

function parseContext(value: unknown): EnterpriseContext | null {
  if (!value || typeof value !== 'object') throw new Error('invalid enterprise context')
  const body = value as EnterpriseContextResponse
  if (body.enabled === false) return null
  if (body.enabled !== true || typeof body.tenant_id !== 'string' || (body.requirement !== 'optional' && body.requirement !== 'required') || !Array.isArray(body.connections)) {
    throw new Error('invalid enterprise context')
  }
  const connections = body.connections.map((connection): EnterpriseConnection => {
    if (!connection || typeof connection !== 'object') throw new Error('invalid enterprise connection')
    const candidate = connection as { id?: unknown; name?: unknown }
    if (typeof candidate.id !== 'string' || candidate.id === '' || typeof candidate.name !== 'string' || candidate.name === '') {
      throw new Error('invalid enterprise connection')
    }
    return { id: candidate.id, name: candidate.name }
  })
  return { tenantId: body.tenant_id, requirement: body.requirement, connections, bootstrapEligible: body.bootstrap_eligible === true }
}

async function responseJSON(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    throw new Error('invalid response')
  }
}

async function postJSON(path: string, body: Record<string, string>, signal: AbortSignal): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw Object.assign(new Error('network'), { status: 0 })
  }
  if (!response.ok) {
    const error = await errorFromResponse(response)
    throw Object.assign(error, { status: response.status })
  }
  return responseJSON(response)
}

function actionStatus(error: unknown): number {
  return typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number' ? error.status : 500
}

/** Loads only the server-approved enterprise sign-in choices. It never infers an identity provider. */
export function useEnterpriseContext() {
  const [state, setState] = useState<ContextState>({ status: 'loading', context: null, message: null })
  const [beginning, setBeginning] = useState(false)
  const [recovering, setRecovering] = useState(false)
  const contextRef = useRef<EnterpriseContext | null>(null)
  const generation = useRef(0)
  const contextAbort = useRef<AbortController | null>(null)
  const actionAbort = useRef<AbortController | null>(null)

  const load = useCallback(async () => {
    const requestGeneration = ++generation.current
    contextAbort.current?.abort()
    const controller = new AbortController()
    contextAbort.current = controller
    contextRef.current = null
    setState({ status: 'loading', context: null, message: null })
    try {
      const response = await fetch('/api/auth/enterprise/context', { credentials: 'same-origin', signal: controller.signal })
      if (requestGeneration !== generation.current) return
      if (response.status === 404) {
        setState({ status: 'legacy', context: null, message: null })
        return
      }
      if (!response.ok) {
        setState({ status: 'error', context: null, message: contextFailure(response.status) })
        return
      }
      const context = parseContext(await responseJSON(response))
      if (requestGeneration !== generation.current) return
      if (context === null) {
        setState({ status: 'legacy', context: null, message: null })
        return
      }
      contextRef.current = context
      setState({ status: 'ready', context, message: null })
    } catch (error) {
      if (controller.signal.aborted || requestGeneration !== generation.current) return
      setState({ status: 'error', context: null, message: contextFailure(0) })
    }
  }, [])

  useEffect(() => {
    const currentGeneration = generation
    void load()
    return () => {
      currentGeneration.current++
      contextAbort.current?.abort()
      actionAbort.current?.abort()
    }
  }, [load])

  const begin = useCallback(async (connectionID: string): Promise<string> => {
    if (!contextRef.current?.connections.some((connection) => connection.id === connectionID)) {
      throw new Error('The selected sign-in connection is no longer available. Refresh and try again.')
    }
    actionAbort.current?.abort()
    const controller = new AbortController()
    actionAbort.current = controller
    const requestGeneration = ++generation.current
    setBeginning(true)
    try {
      const result = await postJSON('/api/auth/enterprise/begin', { connection_id: connectionID, purpose: 'login' }, controller.signal)
      if (requestGeneration !== generation.current || controller.signal.aborted) throw new DOMException('stale request', 'AbortError')
      if (!result || typeof result !== 'object' || typeof (result as { authorization_url?: unknown }).authorization_url !== 'string') {
        throw new Error('invalid authorization URL')
      }
      const authorizationURL = (result as { authorization_url: string }).authorization_url
      const parsed = new URL(authorizationURL)
      if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:') || authorizationURL === '') throw new Error('invalid authorization URL')
      return authorizationURL
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error
      throw new Error(actionFailure(actionStatus(error), 'begin'))
    } finally {
      if (requestGeneration === generation.current) setBeginning(false)
    }
  }, [])

  const recover = useCallback(async (secret: string): Promise<void> => {
    const controller = new AbortController()
    actionAbort.current?.abort()
    actionAbort.current = controller
    const requestGeneration = ++generation.current
    setRecovering(true)
    try {
      const result = await postJSON('/api/auth/enterprise/recovery', { secret }, controller.signal)
      if (requestGeneration !== generation.current || controller.signal.aborted) throw new DOMException('stale request', 'AbortError')
      if (!result || typeof result !== 'object' || typeof (result as { csrf_token?: unknown }).csrf_token !== 'string') {
        throw new Error('invalid recovery response')
      }
      // The cookie is HttpOnly. Retain its paired CSRF token only in memory while AuthProvider
      // refreshes the authenticated state from the new session.
      setCSRFToken((result as { csrf_token: string }).csrf_token)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error
      throw new Error(actionFailure(actionStatus(error), 'recovery'))
    } finally {
      if (requestGeneration === generation.current) setRecovering(false)
    }
  }, [])

  return { ...state, beginning, recovering, reload: load, begin, recover }
}
