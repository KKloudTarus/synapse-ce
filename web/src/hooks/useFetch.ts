import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Options for the `useFetch` hook.
 */
export interface UseFetchOptions {
  /** Skip fetching when false. Defaults to true. */
  enabled?: boolean
  /** Dependency array for refetching. When any value changes, refetch is triggered. */
  deps?: unknown[]
  /**
   * Keep the previous result on screen while a dependency change refetches. Off by default:
   * when a dependency carries which record is being shown, the result in hand answers the
   * previous question, and rendering it under the new heading puts one record's data behind
   * another record's label.
   *
   * Turn it on where the dependency is a refresh counter or a polled value, so the fetch asks
   * the same question again and clearing would only flash.
   */
  keepPreviousData?: boolean
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
  const { enabled = true, deps = [], keepPreviousData = false } = options

  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState<string | null>(null)
  const revisionRef = useRef(0)
  // Distinguishes the first run from a later dependency change. A manual refetch() calls
  // execute() directly and never passes through the effect, so it keeps what is on screen.
  const startedRef = useRef(false)
  const keepPreviousRef = useRef(keepPreviousData)
  keepPreviousRef.current = keepPreviousData
  // Tracks the controller of the most recent in-flight request so a manual
  // refetch can still be aborted on unmount.
  const controllerRef = useRef<AbortController | null>(null)

  const execute = useCallback(() => {
    if (!enabled) return

    const revision = ++revisionRef.current
    const controller = new AbortController()
    controllerRef.current = controller

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
    if (startedRef.current && !keepPreviousRef.current) {
      setData(null)
      setError(null)
    }
    startedRef.current = true
    execute()
    return () => {
      controllerRef.current?.abort()
      controllerRef.current = null
    }
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
