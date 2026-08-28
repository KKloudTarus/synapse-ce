import { api } from '../../lib/api'
import type { Engagement } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches the list of all engagements.
 *
 * @example
 * ```tsx
 * const { data: engagements, loading, error, refetch } = useEngagementList()
 * ```
 */
export function useEngagementList(): UseFetchResult<Engagement[]> {
  return useFetch(() => api.listEngagements(), { deps: [] })
}
