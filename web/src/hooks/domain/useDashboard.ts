import { api } from '../../lib/api'
import type { DashboardSecurityOperations } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches the dashboard security operations analytics.
 *
 * @example
 * ```tsx
 * const { data: analytics, loading, error, refetch } = useDashboardAnalytics(30)
 * ```
 */
export function useDashboardAnalytics(rangeDays = 30): UseFetchResult<DashboardSecurityOperations> {
  return useFetch(() => api.dashboardSecurityOperations(rangeDays), { deps: [rangeDays] })
}
