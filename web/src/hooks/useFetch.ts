import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Options for the `useFetch` hook.
 */
export interface UseFetchOptions {
  /** Skip fetching when false. Defaults to true. */
  enabled?: boolean
  /** Dependency array for refetching. When any value changes, refetch is triggered. */
  deps?: unknown[]
}

/**
 * Return type for the `useFetch` hook.
 */
export interface UseFetchResult<T> {
  /** The fetched data, or null if not yet loaded. */
  data: T | null
  /** Whether the fetch is in progress. */
  loading: boolean
  /** Error message if the fetch failed, null otherwise. */
  error: string | null
  /** Manually trigger a refetch. */
  refetch: () => void
}

/**
 * Base data-fetching hook that wraps an async API function with loading/error state,
 * abort controller cleanup on unmount/re-render, and a manual refetch trigger.
 *
 * @example
 * ```tsx
 * const { data: users, loading, error, refetch } = useFetch(
 *   () => api.listUsers(),
 *   { deps: [] }
 * )
 * ```
 *
 * @param fetcher - Async function that returns data. Receives an AbortSignal for cancellation.
 * @param options - Configuration options.
 */
export function useFetch<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  options: UseFetchOptions = {},
): UseFetchResult<T> {
  const { enabled = true, deps = [] } = options

  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState<string | null>(null)
  const revisionRef = useRef(0)

  const execute = useCallback(() => {
    if (!enabled) return

    const revision = ++revisionRef.current
    const controller = new AbortController()

    setLoading(true)
    setError(null)

    fetcher(controller.signal)
      .then((result) => {
        if (revision === revisionRef.current) {
          setData(result)
        }
      })
      .catch((e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        if (revision === revisionRef.current) {
          setError(e instanceof Error ? e.message : 'An unknown error occurred')
        }
      })
      .finally(() => {
        if (revision === revisionRef.current) {
          setLoading(false)
        }
      })

    return () => {
      controller.abort()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps])

  useEffect(() => {
    const cleanup = execute()
    return cleanup
  }, [execute])

  const refetch = useCallback(() => {
    execute()
  }, [execute])

  return { data, loading, error, refetch }
}

/**
 * Variant of useFetch for parallel fetches via Promise.all.
 * Accepts a fetcher that returns a tuple and preserves the tuple type.
 *
 * @example
 * ```tsx
 * const { data, loading, error, refetch } = useParallelFetch(
 *   (signal) => Promise.all([api.listA(), api.listB()]),
 *   { deps: [] }
 * )
 * // data is [A[], B[]] | null
 * ```
 */
export function useParallelFetch<T extends readonly unknown[]>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  options: UseFetchOptions = {},
): UseFetchResult<T> {
  return useFetch<T>(fetcher, options)
}
