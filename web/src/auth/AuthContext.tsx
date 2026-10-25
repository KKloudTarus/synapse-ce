import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api, discoverSession, logoutSession, setCSRFToken, setToken as setApiToken, setUnauthorizedHandler } from '../lib/api'
import { ApiError, isCredentialInvalid, isUnauthenticated } from '../lib/api/errors'
import type { AupStatus, CurrentUser } from '../lib/types'

// The development/automation bearer token is kept in sessionStorage so it dies with the
// browser tab instead of persisting across restarts for later XSS to read.
const TOKEN_KEY = 'synapse.token'
type Phase = 'connecting' | 'mailbox' | 'unauthenticated' | 'need-aup' | 'ready'
type AuthMethod = 'session' | 'token'

const INVALID_TOKEN = 'Invalid API token.'
const SESSION_EXPIRED = 'Your sign-in session expired. Sign in again.'
const ACCESS_DENIED = 'This sign-in is not approved for Synapse. Ask an administrator to link your identity.'
const SIGN_IN_FAILED = 'Organization sign-in could not be completed. Try again, or use an API token.'

interface AuthState {
  phase: Phase
  aup: AupStatus | null
  currentUser: CurrentUser | null
  error: string | null
  // Server request ID for the current error, shown so an operator can quote it to support.
  errorRequestId: string | null
  // True when restoration failed for a transient reason and the credential was kept, so
  // re-running restoration may succeed without the user signing in again.
  canRetry: boolean
  retrying: boolean
  connecting: boolean
  oidcAvailable: boolean
  connect: (token: string, requiredCredential?: 'bootstrap') => Promise<void>
  acceptAup: () => Promise<void>
  logout: () => Promise<void>
  retry: () => Promise<void>
  /**
   * Applies the server-issued CSRF token after an organization switch, clears the old tenant's
   * visible identity, and restores the authenticated state for the destination tenant.
   */
  completeOrganizationSwitch: (csrfToken: string) => Promise<void>
  completeMailboxContinuation: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth must be used within AuthProvider')
  return v
}

// Non-throwing accessor for layout chrome (e.g. the sidebar) that renders inside AuthProvider in the
// app but may be mounted in isolation by unit tests. Returns null when there is no provider.
export function useOptionalAuth(): AuthState | null {
  return useContext(Ctx)
}

type Failure = { message: string; requestId: string | null; canRetry: boolean }

function failureMessage(e: unknown, context: string): string {
  if (e instanceof ApiError && e.code === 'authentication_unavailable') {
    return 'Sign-in is temporarily unavailable. Your existing sign-in has been kept. Try again.'
  }
  if (e instanceof ApiError && e.status === 0) return `${e.message} Your existing sign-in has been kept.`
  return e instanceof Error ? `${context}: ${e.message}` : `${context}.`
}

// A failure that did not reject the credential. The credential stays, and Retry is offered only
// when the server (or the transport) says repeating the request may succeed.
function keptFailure(e: unknown, context: string): Failure {
  const retryable = e instanceof ApiError ? e.retryable : true
  return {
    message: failureMessage(e, context),
    requestId: e instanceof ApiError ? e.requestId ?? null : null,
    canRetry: retryable,
  }
}

// The OIDC callback reports a refused sign-in by redirecting here with ?auth_error=<reason>.
function readAuthErrorParam(): string | null {
  if (typeof window === 'undefined') return null
  return new URLSearchParams(window.location.search).get('auth_error')
}

function preserveOrganizationLogin(user: CurrentUser | null) {
  if (user?.credentialKind !== 'browser_session' || !user.tenantId) return
  // This is a public routing hint. The server still validates the selected tenant and provider.
  const query = new URLSearchParams({ tenant_id: user.tenantId })
  window.history.replaceState(window.history.state, '', `/?${query}`)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>('connecting')
  const [aup, setAup] = useState<AupStatus | null>(null)
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null)
  const [failure, setFailure] = useState<Failure | null>(() => {
    const reason = readAuthErrorParam()
    if (!reason || reason === 'mailbox_verification_required') return null
    return { message: reason === 'access_denied' ? ACCESS_DENIED : SIGN_IN_FAILED, requestId: null, canRetry: false }
  })
  const callbackFailure = useRef(failure)
  const mailboxContinuation = useRef(readAuthErrorParam() === 'mailbox_verification_required')
  const [connecting, setConnecting] = useState(false)
  const [retrying, setRetrying] = useState(false)
  const [oidcAvailable, setOidcAvailable] = useState(true)
  const [authMethod, setAuthMethod] = useState<AuthMethod | null>(null)

  // Every restore, connect and logout takes a new generation. An async step applies its result only
  // while its generation is still current, so a late response from an attempt the user has since
  // replaced (by retrying, signing in or signing out) cannot overwrite the newer state.
  const generation = useRef(0)
  const retryInFlight = useRef(false)
  const phaseRef = useRef<Phase>(phase)
  const authMethodRef = useRef<AuthMethod | null>(authMethod)
  useEffect(() => {
    phaseRef.current = phase
    authMethodRef.current = authMethod
  }, [phase, authMethod])

  const setError = useCallback((message: string | null) => {
    callbackFailure.current = null
    setFailure(message ? { message, requestId: null, canRetry: false } : null)
  }, [])

  // Forgets the in-memory credential and user without touching the stored bearer token.
  const resetLocalAuthentication = useCallback(() => {
    setApiToken('')
    setCSRFToken('')
    setAuthMethod(null)
    setAup(null)
    setCurrentUser(null)
  }, [])

  // Also discards the stored bearer token. Reserved for a credential the server rejected.
  const clearAuthentication = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY)
    resetLocalAuthentication()
  }, [resetLocalAuthentication])

  // Loads the authenticated state. It never sets phase itself, so callers decide whether the result
  // still applies. Once the AUP is accepted, /me is part of authentication restoration: any failure
  // remains a failure instead of presenting a ready state with an unknown user.
  const loadAuthenticated = useCallback(async () => {
    let status: AupStatus
    try {
      status = await api.aup()
    } catch (cause) {
      // Break-glass sessions intentionally cannot accept the ordinary AUP. The identity returned
      // by the same authenticated client is the only authority for entering its isolated console.
      if (!(cause instanceof ApiError) || cause.status !== 403 || cause.code !== 'permission_denied') throw cause
      let me: CurrentUser
      try {
        me = await api.me()
      } catch (identityError) {
        // A failed identity read never grants recovery access. Preserve failures that restoration
        // already knows how to recover from or explain; only mask definitive non-recovery denials.
        if (isUnauthenticated(identityError) || !(identityError instanceof ApiError) || identityError.retryable) throw identityError
        throw cause
      }
      if (me.credentialKind !== 'break_glass') throw cause
      return { status: null, me }
    }
    const me = status.accepted && typeof api.me === 'function' ? await api.me() : null
    return { status, me }
  }, [])

  const applyAuthenticated = useCallback((result: { status: AupStatus | null; me: CurrentUser | null }) => {
    if (result.status === null && result.me?.credentialKind !== 'break_glass') {
      throw new Error('Recovery authentication requires a verified break-glass credential.')
    }
    setAup(result.status)
    setCurrentUser(result.me)
    const nextPhase = result.status === null || result.status.accepted ? 'ready' : 'need-aup'
    phaseRef.current = nextPhase
    setPhase(nextPhase)
  }, [])

  const completeRestoration = useCallback((result: { status: AupStatus | null; me: CurrentUser | null }) => {
    const refused = callbackFailure.current
    callbackFailure.current = null
    setFailure(refused ? {
      ...refused,
      message: refused.message === ACCESS_DENIED
        ? 'The identity you selected is not approved for this action. Your existing sign-in is still active.'
        : 'The additional sign-in attempt could not be completed. Your existing sign-in is still active.',
    } : null)
    applyAuthenticated(result)
  }, [applyAuthenticated])

  // Restoration: try the BFF cookie session, then a saved bearer token. Only a rejected credential
  // is discarded; a dependency failure keeps it and offers Retry.
  const restore = useCallback(async () => {
    const gen = ++generation.current
    // Discovery rotates the cookie that an invitation proof binds exactly. Hold
    // restoration until mailbox completion or cancellation, including generic retries.
    if (mailboxContinuation.current) { setPhase('mailbox'); return }
    const current = () => gen === generation.current
    setApiToken('')
    setCSRFToken('')
    setAuthMethod(null)
    setAup(null)

    const restoreSavedToken = async (discoveryFailure: Failure | null) => {
      const saved = sessionStorage.getItem(TOKEN_KEY)
      if (!saved) {
        setPhase('unauthenticated')
        if (discoveryFailure) setFailure(discoveryFailure)
        return
      }
      setApiToken(saved)
      setAuthMethod('token')
      try {
        const result = await loadAuthenticated()
        if (!current()) return
        completeRestoration(result)
      } catch (e) {
        if (!current()) return
        setPhase('unauthenticated')
        if (isCredentialInvalid(e)) {
          clearAuthentication()
          setError(INVALID_TOKEN)
        } else if (isUnauthenticated(e)) {
          // The server saw no credential, so nothing was proven invalid. Leave the stored token.
          resetLocalAuthentication()
          setFailure(null)
        } else {
          setFailure(keptFailure(e, 'Could not restore your sign-in session'))
        }
      }
    }

    let session
    try {
      session = await discoverSession()
    } catch (e) {
      if (!current()) return
      const bffMissing = e instanceof ApiError && e.status === 404
      if (bffMissing) setOidcAvailable(false)
      // Session discovery failing (offline, or the session store is unavailable) says nothing about
      // the cookie or the saved bearer token, so keep both. A 404 is a server without the BFF.
      await restoreSavedToken(bffMissing ? null : keptFailure(e, 'Could not check your sign-in session'))
      return
    }
    if (!current()) return

    if (!session.authenticated) {
      await restoreSavedToken(null)
      return
    }

    setCSRFToken(session.csrfToken)
    setAuthMethod('session')
    try {
      const result = await loadAuthenticated()
      if (!current()) return
      completeRestoration(result)
    } catch (e) {
      if (!current()) return
      setPhase('unauthenticated')
      if (isUnauthenticated(e)) {
        // The HttpOnly cookie is owned by the server; locally there is only in-memory state to drop.
        resetLocalAuthentication()
        setError(SESSION_EXPIRED)
      } else {
        setFailure(keptFailure(e, 'Could not restore your sign-in session'))
      }
    }
  }, [completeRestoration, clearAuthentication, loadAuthenticated, resetLocalAuthentication, setError])

  const retry = useCallback(async () => {
    if (retryInFlight.current) return
    retryInFlight.current = true
    setRetrying(true)
    try {
      await restore()
    } finally {
      retryInFlight.current = false
      setRetrying(false)
    }
  }, [restore])

  const completeMailboxContinuation = useCallback(async () => {
    mailboxContinuation.current = false
    const url = new URL(window.location.href)
    if (url.searchParams.get('auth_error') === 'mailbox_verification_required') {
      url.searchParams.delete('auth_error')
      window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
    }
    setPhase('connecting')
    await retry()
  }, [retry])

  const completeOrganizationSwitch = useCallback(async (csrfToken: string) => {
    callbackFailure.current = null
    // A switch replaces the browser session. Clear tenant-derived UI before restoring so an
    // in-flight request or cached component cannot present the previous organization's data as
    // belonging to the destination.
    generation.current++
    setCurrentUser(null)
    setAup(null)
    setFailure(null)
    setPhase('connecting')
    setCSRFToken(csrfToken)
    await retry()
  }, [retry])

  // A bearer session is purely local, so it clears without a server call. A cookie session
  // stays signed in when revocation fails: the HttpOnly cookie is still valid server-side and
  // showing the signed-out screen would misrepresent that.
  const logout = useCallback(async () => {
    const gen = ++generation.current
    if (authMethod !== 'session') {
      clearAuthentication()
      setError(null)
      setPhase('unauthenticated')
      return
    }
    try {
      await logoutSession()
    } catch (e) {
      if (gen !== generation.current) return
      // A session the server already rejects is signed out: there is nothing left to revoke, and
      // retrying would fail the same way forever.
      if (!isUnauthenticated(e)) {
        setError(e instanceof Error ? `Could not end the server session: ${e.message} Try signing out again.` : 'Could not end the server session. Try signing out again.')
        return
      }
    }
    if (gen !== generation.current) return
    preserveOrganizationLogin(currentUser)
    clearAuthentication()
    setError(null)
    setPhase('unauthenticated')
  }, [authMethod, clearAuthentication, currentUser, setError])

  // Requests made after sign-in report authentication outcomes here. Restoration and connect handle
  // their own responses, so the handler acts only on an established session.
  useEffect(() => {
    setUnauthorizedHandler((e?: ApiError) => {
      if (phaseRef.current !== 'ready' && phaseRef.current !== 'need-aup') return
      // A bare 401 from a caller that did not parse the body is treated like an old server's 401.
      const invalid = e === undefined || isCredentialInvalid(e)
      if (!invalid && !isUnauthenticated(e)) return
      generation.current++
      const message = authMethodRef.current === 'token' ? INVALID_TOKEN : SESSION_EXPIRED
      if (authMethodRef.current === 'session') preserveOrganizationLogin(currentUser)
      if (invalid) clearAuthentication()
      else resetLocalAuthentication()
      setPhase('unauthenticated')
      setError(message)
    })
  }, [clearAuthentication, currentUser, resetLocalAuthentication, setError])

  const connect = useCallback(async (raw: string, requiredCredential?: 'bootstrap') => {
    const t = raw.trim()
    if (!t) return
    const gen = ++generation.current
    setConnecting(true)
    setError(null)
    setApiToken(t)
    setCSRFToken('')
    setAuthMethod('token')
    try {
      if (requiredCredential === 'bootstrap') {
        // /me is available before AUP acceptance. Reject an ordinary API credential before
        // it can be stored or enter either authenticated phase through the operator entrance.
        const operator = await api.me()
        if (gen !== generation.current) return
        if (operator.credentialKind !== 'bootstrap' || operator.role !== 'admin') {
          throw new Error('Use the deployment operator credential for this sign-in. Organization members must use organization sign-in.')
        }
      }
      const result = await loadAuthenticated()
      if (gen !== generation.current) return
      sessionStorage.setItem(TOKEN_KEY, t)
      applyAuthenticated(result)
    } catch (e) {
      if (gen !== generation.current) return
      setPhase('unauthenticated')
      if (isCredentialInvalid(e)) {
        clearAuthentication()
        setError(INVALID_TOKEN)
      } else {
        // The new token was never stored, and nothing proved a previously stored one invalid.
        resetLocalAuthentication()
        setFailure({
          message: e instanceof Error ? e.message : 'Connection failed.',
          requestId: e instanceof ApiError ? e.requestId ?? null : null,
          canRetry: false,
        })
      }
    } finally {
      setConnecting(false)
    }
  }, [applyAuthenticated, clearAuthentication, loadAuthenticated, resetLocalAuthentication, setError])

  const acceptAup = useCallback(async () => {
    if (!aup) return
    const gen = generation.current
    try {
      setError(null)
      await api.acceptAup(aup.version)
      const result = await loadAuthenticated()
      if (gen !== generation.current) return
      applyAuthenticated(result)
    } catch (e) {
      if (gen !== generation.current) return
      if (isCredentialInvalid(e)) {
        clearAuthentication()
        setPhase('unauthenticated')
        setError(authMethodRef.current === 'token' ? INVALID_TOKEN : SESSION_EXPIRED)
        return
      }
      setError(e instanceof Error ? e.message : 'Could not accept the acceptable use policy.')
    }
  }, [aup, applyAuthenticated, clearAuthentication, loadAuthenticated, setError])

  useEffect(() => {
    // The refusal notice was captured on first render; drop the parameter so a reload does not
    // show it again and the notice never triggers another sign-in attempt.
    const reason = readAuthErrorParam()
    // The invitation flow mounts after session restoration and owns this continuation marker.
    if (reason !== null && reason !== 'mailbox_verification_required') {
      const url = new URL(window.location.href)
      url.searchParams.delete('auth_error')
      window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
    }
  }, [])

  useEffect(() => {
    const attempts = generation
    void restore()
    // Invalidate the in-flight attempt on unmount (and on the StrictMode remount).
    return () => { attempts.current++ }
  }, [restore])

  const error = failure?.message ?? null
  const errorRequestId = failure?.requestId ?? null
  const canRetry = failure?.canRetry ?? false

  const value = useMemo(
    () => ({ phase, aup, currentUser, error, errorRequestId, canRetry, retrying, connecting, oidcAvailable, connect, acceptAup, logout, retry, completeOrganizationSwitch, completeMailboxContinuation }),
    [phase, aup, currentUser, error, errorRequestId, canRetry, retrying, connecting, oidcAvailable, connect, acceptAup, logout, retry, completeOrganizationSwitch, completeMailboxContinuation],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}
