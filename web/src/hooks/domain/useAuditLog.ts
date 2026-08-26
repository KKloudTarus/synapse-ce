import { api } from '../../lib/api'
import type { AuditEntry } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches the recent audit log entries.
 *
 * @example
 * ```tsx
 * const { data: entries, loading, error, refetch } = useAuditLog(200)
 * ```
 */
export function useAuditLog(limit = 200): UseFetchResult<AuditEntry[]> {
  return useFetch(() => api.recentAudit(limit), { deps: [limit] })
}
