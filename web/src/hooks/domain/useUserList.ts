import { api, ApiError } from '../../lib/api'
import type { User } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

export interface UseUserListResult extends UseFetchResult<User[]> {
  /** True when the server returned 403 (admin-only endpoint). */
  forbidden: boolean
}

/**
 * Fetches the list of team members. Handles 403 as a special `forbidden` state
 * rather than a generic error, since this endpoint is admin-only.
 *
 * @example
 * ```tsx
 * const { data: users, loading, error, forbidden, refetch } = useUserList()
 * ```
 */
export function useUserList(): UseUserListResult {
  const result = useFetch<User[]>(
    async () => {
      try {
        return await api.listUsers()
      } catch (e) {
        if (e instanceof ApiError && e.status === 403) {
          // Rethrow with special marker — the hook consumer checks `forbidden`
          throw Object.assign(new Error('forbidden'), { status: 403 })
        }
        throw e
      }
    },
    { deps: [] },
  )

  const forbidden = result.error === 'forbidden'

  return {
    ...result,
    error: forbidden ? null : result.error,
    forbidden,
  }
}
