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
type Phase = 'connecting' | 'unauthenticated' | 'need-aup' | 'ready'
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
  connect: (token: string) => Promise<void>
  acceptAup: () => Promise<void>
  logout: () => Promise<void>
  retry: () => Promise<void>
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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>('connecting')
  const [aup, setAup] = useState<AupStatus | null>(null)
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null)
  const [failure, setFailure] = useState<Failure | null>(() => {
    const reason = readAuthErrorParam()
    if (!reason) return null
    return { message: reason === 'access_denied' ? ACCESS_DENIED : SIGN_IN_FAILED, requestId: null, canRetry: false }
  })
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
    const status = await api.aup()
    const me = status.accepted && typeof api.me === 'function' ? await api.me() : null
    return { status, me }
  }, [])

  const applyAuthenticated = useCallback((result: { status: AupStatus; me: CurrentUser | null }) => {
    setAup(result.status)
    setCurrentUser(result.me)
    setPhase(result.status.accepted ? 'ready' : 'need-aup')
  }, [])

  // Restoration: try the BFF cookie session, then a saved bearer token. Only a rejected credential
  // is discarded; a dependency failure keeps it and offers Retry.
  const restore = useCallback(async () => {
    const gen = ++generation.current
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
        setFailure(null)
        applyAuthenticated(result)
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
      setFailure(null)
      applyAuthenticated(result)
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
  }, [applyAuthenticated, clearAuthentication, loadAuthenticated, resetLocalAuthentication, setError])

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
    clearAuthentication()
    setError(null)
    setPhase('unauthenticated')
  }, [authMethod, clearAuthentication, setError])

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
      if (invalid) clearAuthentication()
      else resetLocalAuthentication()
      setPhase('unauthenticated')
      setError(message)
    })
  }, [clearAuthentication, resetLocalAuthentication, setError])

  const connect = useCallback(async (raw: string) => {
    const t = raw.trim()
    if (!t) return
    const gen = ++generation.current
    setConnecting(true)
    setError(null)
    setApiToken(t)
    setCSRFToken('')
    setAuthMethod('token')
    try {
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
    if (readAuthErrorParam() !== null) {
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
    () => ({ phase, aup, currentUser, error, errorRequestId, canRetry, retrying, connecting, oidcAvailable, connect, acceptAup, logout, retry }),
    [phase, aup, currentUser, error, errorRequestId, canRetry, retrying, connecting, oidcAvailable, connect, acceptAup, logout, retry],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}
