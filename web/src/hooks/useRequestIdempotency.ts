import { useRef } from 'react'
import { newIdempotencyKey } from '../lib/api/client'

// Retries of one logical command reuse its key. An edited payload or a newly
// selected File is a different command, not a retry of the retained request.
export function useRequestIdempotency() {
  const attempt = useRef<{ payload: string; file?: File; key: string } | null>(null)
  return (input: unknown, file?: File) => {
    const payload = JSON.stringify(input)
    if (!attempt.current || attempt.current.payload !== payload || attempt.current.file !== file) {
      attempt.current = { payload, file, key: newIdempotencyKey() }
    }
    return attempt.current.key
  }
}
