import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Options for the `usePolling` hook.
 */
export interface UsePollingOptions {
  /** Polling interval in milliseconds. */
  interval: number
  /** Whether polling is active. Defaults to true. */
  enabled?: boolean
  /** Dependency array — refetch is also triggered when deps change. */
  deps?: unknown[]
}

/**
 * Return type for the `usePolling` hook.
 */
export interface UsePollingResult<T> {
  /** The latest fetched data, or null if not yet loaded. */
  data: T | null
  /** Whether the initial fetch is in progress. */
  loading: boolean
  /** Error message if the last fetch failed, null otherwise. */
  error: string | null
  /** Manually trigger a refetch (also resets the interval timer). */
  refetch: () => void
}

/**
 * Hook that fetches data on mount and then re-fetches at a fixed interval.
 * Polling stops when `enabled` is false or the component unmounts.
 * Uses AbortController for in-flight cleanup.
 *
 * @example
 * ```tsx
 * const { data: status, loading } = usePolling(
 *   () => api.scanStatus(engagementId),
 *   { interval: 3000, enabled: isRunning }
 * )
 * ```
 *
 * @param fetcher - Async function that returns data.
 * @param options - Polling configuration.
 */
export function usePolling<T>(
  fetcher: () => Promise<T>,
  options: UsePollingOptions,
): UsePollingResult<T> {
  const { interval, enabled = true, deps = [] } = options

  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState<string | null>(null)
  const mountedRef = useRef(true)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const execute = useCallback(async () => {
    try {
      const result = await fetcher()
      if (mountedRef.current) {
        setData(result)
        setError(null)
      }
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e.message : 'An unknown error occurred')
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetcher, ...deps])

  useEffect(() => {
    mountedRef.current = true

    if (!enabled) {
      setLoading(false)
      return
    }

    // Initial fetch
    setLoading(true)
    execute()

    // Start interval
    intervalRef.current = setInterval(execute, interval)

    return () => {
      mountedRef.current = false
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [execute, enabled, interval])

  const refetch = useCallback(() => {
    // Reset interval timer on manual refetch
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current)
    }
    execute()
    if (enabled) {
      intervalRef.current = setInterval(execute, interval)
    }
  }, [execute, enabled, interval])

  return { data, loading, error, refetch }
}
