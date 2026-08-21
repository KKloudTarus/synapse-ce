import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api, ApiError, discoverSession, logoutSession, setCSRFToken, setToken as setApiToken, setUnauthorizedHandler } from '../lib/api'
import type { AupStatus } from '../lib/types'

// The development/automation bearer token is kept in sessionStorage so it dies with the
// browser tab instead of persisting across restarts for later XSS to read.
const TOKEN_KEY = 'synapse.token'
type Phase = 'connecting' | 'unauthenticated' | 'need-aup' | 'ready'

interface AuthState {
  phase: Phase
  aup: AupStatus | null
  error: string | null
  connecting: boolean
  connect: (token: string) => Promise<void>
  acceptAup: () => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth must be used within AuthProvider')
  return v
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>('connecting')
  const [aup, setAup] = useState<AupStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [connecting, setConnecting] = useState(false)
  const [authMethod, setAuthMethod] = useState<'session' | 'token' | null>(null)

  const clearAuthentication = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY)
    setApiToken('')
    setCSRFToken('')
    setAuthMethod(null)
    setAup(null)
  }, [])

  const refreshAup = useCallback(async () => {
    const status = await api.aup()
    setAup(status)
    setPhase(status.accepted ? 'ready' : 'need-aup')
  }, [])

  // A bearer session is purely local, so it clears without a server call. A cookie session
  // stays signed in when revocation fails: the HttpOnly cookie is still valid server-side and
  // showing the signed-out screen would misrepresent that.
  const logout = useCallback(async () => {
    if (authMethod !== 'session') {
      clearAuthentication()
      setError(null)
      setPhase('unauthenticated')
      return
    }
    try {
      await logoutSession()
    } catch (e) {
      setError(e instanceof Error ? `Could not end the server session: ${e.message} Try signing out again.` : 'Could not end the server session. Try signing out again.')
      return
    }
    clearAuthentication()
    setError(null)
    setPhase('unauthenticated')
  }, [authMethod, clearAuthentication])

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearAuthentication()
      setPhase('unauthenticated')
      setError(authMethod === 'token' ? 'Invalid API token.' : 'Your sign-in session expired. Sign in again.')
    })
  }, [authMethod, clearAuthentication])

  const connect = useCallback(async (raw: string) => {
    const t = raw.trim()
    if (!t) return
    setConnecting(true)
    setError(null)
    setApiToken(t)
    setCSRFToken('')
    setAuthMethod('token')
    try {
      await refreshAup()
      sessionStorage.setItem(TOKEN_KEY, t)
    } catch (e) {
      clearAuthentication()
      setPhase('unauthenticated')
      setError(e instanceof ApiError && e.status === 401 ? 'Invalid API token.' : e instanceof Error ? e.message : 'Connection failed.')
    } finally {
      setConnecting(false)
    }
  }, [clearAuthentication, refreshAup])

  const acceptAup = useCallback(async () => {
    if (!aup) return
    try {
      setError(null)
      await api.acceptAup(aup.version)
      await refreshAup()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not accept the acceptable use policy.')
    }
  }, [aup, refreshAup])

  useEffect(() => {
    let ignore = false
    const restore = async () => {
      setApiToken('')
      setCSRFToken('')
      setAuthMethod(null)
      setAup(null)
      try {
        const session = await discoverSession()
        if (ignore) return
        if (session.authenticated) {
          setCSRFToken(session.csrfToken)
          setAuthMethod('session')
          try {
            await refreshAup()
          } catch (e) {
            if (!ignore) {
              clearAuthentication()
              setPhase('unauthenticated')
              setError(e instanceof Error ? `Could not restore your sign-in session: ${e.message}` : 'Could not restore your sign-in session.')
            }
          }
          return
        }

        await restoreSavedToken()
      } catch (e) {
        if (ignore) return
        // Session discovery failing (offline, or a server without the BFF) says nothing about
        // the saved bearer token, so try it before discarding the credential.
        const discoveryError = e instanceof Error ? `Could not check your sign-in session: ${e.message}` : 'Could not check your sign-in session.'
        try {
          if (!(await restoreSavedToken())) setError(discoveryError)
        } catch {
          if (!ignore) setError(discoveryError)
        }
      }
    }
    // restoreSavedToken reports whether a saved bearer token authenticated. It only clears the
    // stored token when the token itself was rejected.
    const restoreSavedToken = async (): Promise<boolean> => {
      const saved = sessionStorage.getItem(TOKEN_KEY)
      if (!saved) {
        if (!ignore) setPhase('unauthenticated')
        return false
      }
      setApiToken(saved)
      setAuthMethod('token')
      try {
        await refreshAup()
        return true
      } catch (e) {
        if (!ignore) {
          // Only a rejected credential justifies discarding it. A transient failure (offline,
          // 5xx, DNS) says nothing about the token's validity, so keep it and surface the error;
          // otherwise one flaky request silently signs the operator out.
          const rejected = e instanceof ApiError && (e.status === 401 || e.status === 403)
          if (rejected) clearAuthentication()
          setPhase('unauthenticated')
          setError(rejected ? (e.status === 401 ? 'Invalid API token.' : 'This API token is not permitted.') : e instanceof Error ? e.message : 'Connection failed.')
        }
        return false
      }
    }
    void restore()
    return () => { ignore = true }
  }, [clearAuthentication, refreshAup])

  const value = useMemo(
    () => ({ phase, aup, error, connecting, connect, acceptAup, logout }),
    [phase, aup, error, connecting, connect, acceptAup, logout],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}
