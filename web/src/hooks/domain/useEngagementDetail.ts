import { api } from '../../lib/api'
import type { Engagement } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches a single engagement by ID.
 *
 * @example
 * ```tsx
 * const { data: engagement, loading, error, refetch } = useEngagementDetail(id)
 * ```
 */
export function useEngagementDetail(id: string): UseFetchResult<Engagement> {
  return useFetch(() => api.getEngagement(id), { deps: [id], enabled: !!id })
}
