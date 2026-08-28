import { useCallback, useRef, useState } from 'react'

/**
 * Options for the `useMutation` hook.
 */
export interface UseMutationOptions<TInput, TResponse> {
  /** Called after a successful mutation. */
  onSuccess?: (data: TResponse, input: TInput) => void
  /** Called when the mutation fails. */
  onError?: (error: Error, input: TInput) => void
}

/**
 * Return type for the `useMutation` hook.
 */
export interface UseMutationResult<TInput, TResponse> {
  /** Trigger the mutation with the given input. */
  mutate: (input: TInput) => Promise<TResponse | undefined>
  /** The response data from the last successful mutation. */
  data: TResponse | null
  /** Whether the mutation is in progress. */
  loading: boolean
  /** Error message if the mutation failed, null otherwise. */
  error: string | null
  /** Reset mutation state (data, error) back to initial. */
  reset: () => void
}

/**
 * Hook for write operations (POST, PUT, PATCH, DELETE).
 * Unlike `useFetch`, this does NOT fire on mount — the caller triggers it via `mutate()`.
 *
 * @example
 * ```tsx
 * const { mutate, loading, error } = useMutation(
 *   (values: CreateInput) => api.createEngagement(values),
 *   { onSuccess: () => refresh() }
 * )
 *
 * const handleSubmit = () => mutate(formValues)
 * ```
 *
 * @param mutator - Async function that performs the write operation.
 * @param options - Optional callbacks.
 */
export function useMutation<TInput, TResponse = unknown>(
  mutator: (input: TInput) => Promise<TResponse>,
  options: UseMutationOptions<TInput, TResponse> = {},
): UseMutationResult<TInput, TResponse> {
  const [data, setData] = useState<TResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const optionsRef = useRef(options)
  optionsRef.current = options

  const mutate = useCallback(
    async (input: TInput): Promise<TResponse | undefined> => {
      setLoading(true)
      setError(null)
      try {
        const result = await mutator(input)
        setData(result)
        optionsRef.current.onSuccess?.(result, input)
        return result
      } catch (e) {
        const err = e instanceof Error ? e : new Error('An unknown error occurred')
        setError(err.message)
        optionsRef.current.onError?.(err, input)
        return undefined
      } finally {
        setLoading(false)
      }
    },
    [mutator],
  )

  const reset = useCallback(() => {
    setData(null)
    setError(null)
  }, [])

  return { mutate, data, loading, error, reset }
}
