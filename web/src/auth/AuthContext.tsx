import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api, ApiError, setToken as setApiToken, setUnauthorizedHandler } from '../lib/api'
import type { AupStatus } from '../lib/types'

const TOKEN_KEY = 'synapse.token'

type Phase = 'connecting' | 'need-token' | 'need-aup' | 'ready'

interface AuthState {
  phase: Phase
  aup: AupStatus | null
  error: string | null
  connecting: boolean
  connect: (token: string) => Promise<void>
  acceptAup: () => Promise<void>
  logout: () => void
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

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setApiToken('')
    setAup(null)
    setError(null)
    setPhase('need-token')
  }, [])

  // Any 401 from the API drops back to the token screen.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      localStorage.removeItem(TOKEN_KEY)
      setApiToken('')
      setPhase('need-token')
      setError('Session rejected – check your API token.')
    })
  }, [])

  const refreshAup = useCallback(async () => {
    const status = await api.aup()
    setAup(status)
    setPhase(status.accepted ? 'ready' : 'need-aup')
  }, [])

  const connect = useCallback(
    async (raw: string) => {
      const t = raw.trim()
      if (!t) return
      setConnecting(true)
      setError(null)
      setApiToken(t)
      try {
        await refreshAup()
        localStorage.setItem(TOKEN_KEY, t)
      } catch (e) {
        setApiToken('')
        setPhase('need-token')
        setError(
          e instanceof ApiError && e.status === 401
            ? 'Invalid API token.'
            : e instanceof Error
              ? e.message
              : 'Connection failed.',
        )
      } finally {
        setConnecting(false)
      }
    },
    [refreshAup],
  )

  const acceptAup = useCallback(async () => {
    if (!aup) return
    await api.acceptAup(aup.version)
    await refreshAup()
  }, [aup, refreshAup])

  // Restore a saved session on first load.
  useEffect(() => {
    const saved = localStorage.getItem(TOKEN_KEY)
    if (!saved) {
      setPhase('need-token')
      return
    }
    setApiToken(saved)
    refreshAup().catch(() => {
      setApiToken('')
      localStorage.removeItem(TOKEN_KEY)
      setPhase('need-token')
    })
  }, [refreshAup])

  const value = useMemo(
    () => ({ phase, aup, error, connecting, connect, acceptAup, logout }),
    [phase, aup, error, connecting, connect, acceptAup, logout],
  )

  return (
    <Ctx.Provider value={value}>
      {children}
    </Ctx.Provider>
  )
}
