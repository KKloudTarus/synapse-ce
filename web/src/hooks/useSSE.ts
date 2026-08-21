import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Connection status for the SSE stream.
 */
export type SSEStatus = 'connecting' | 'open' | 'closed' | 'error'

/**
 * Options for the `useSSE` hook.
 */
export interface UseSSEOptions {
  /** Whether the connection should be active. Defaults to true. */
  enabled?: boolean
  /** Whether to reconnect on error. Defaults to true. */
  reconnect?: boolean
  /** Reconnect delay in milliseconds. Defaults to 3000. */
  reconnectDelay?: number
  /** Maximum reconnection attempts. Defaults to 5. */
  maxRetries?: number
}

/**
 * Return type for the `useSSE` hook.
 */
export interface UseSSEResult<T> {
  /** The latest parsed event data, or null if no event received yet. */
  data: T | null
  /** Current connection status. */
  status: SSEStatus
  /** Error message if the connection failed, null otherwise. */
  error: string | null
  /** Manually close the connection. */
  close: () => void
}

/**
 * Hook for subscribing to Server-Sent Events via a streaming fetch
 * (not EventSource, since we need custom auth headers).
 *
 * The `subscriber` is responsible for the actual streaming logic — this hook
 * manages its lifecycle (start/stop/reconnect based on `enabled`).
 *
 * @example
 * ```tsx
 * const { data: event, status } = useSSE<ReconLogEvent>(
 *   (onEvent, signal) => streamReconLogs(engId, runId, { signal, onEvent }),
 *   { enabled: isStreaming }
 * )
 * ```
 *
 * @param subscriber - Function that starts the stream. Receives an `onEvent` callback
 *   and an AbortSignal. Should resolve when the stream ends.
 * @param options - Configuration options.
 */
export function useSSE<T>(
  subscriber: (onEvent: (event: T) => void, signal: AbortSignal) => Promise<void>,
  options: UseSSEOptions = {},
): UseSSEResult<T> {
  const { enabled = true, reconnect = true, reconnectDelay = 3000, maxRetries = 5 } = options

  const [data, setData] = useState<T | null>(null)
  const [status, setStatus] = useState<SSEStatus>('closed')
  const [error, setError] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)
  const retriesRef = useRef(0)
  const mountedRef = useRef(true)

  const start = useCallback(() => {
    if (!enabled) return

    const controller = new AbortController()
    controllerRef.current = controller
    setStatus('connecting')
    setError(null)

    subscriber(
      (event) => {
        if (mountedRef.current) {
          setData(event)
          setStatus('open')
          retriesRef.current = 0
        }
      },
      controller.signal,
    )
      .then(() => {
        if (mountedRef.current) {
          setStatus('closed')
        }
      })
      .catch((e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        if (!mountedRef.current) return
        setStatus('error')
        setError(e instanceof Error ? e.message : 'Stream connection failed')

        // Reconnect logic
        if (reconnect && retriesRef.current < maxRetries) {
          retriesRef.current++
          setTimeout(() => {
            if (mountedRef.current && enabled) {
              start()
            }
          }, reconnectDelay)
        }
      })
  }, [enabled, subscriber, reconnect, reconnectDelay, maxRetries])

  useEffect(() => {
    mountedRef.current = true

    if (enabled) {
      start()
    }

    return () => {
      mountedRef.current = false
      controllerRef.current?.abort()
      controllerRef.current = null
    }
  }, [start, enabled])

  const close = useCallback(() => {
    controllerRef.current?.abort()
    controllerRef.current = null
    setStatus('closed')
  }, [])

  return { data, status, error, close }
}
