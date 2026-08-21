import { api } from '../../lib/api'
import type { RuleListFilters, RuleSummary } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches the list of rules with optional filters.
 *
 * @example
 * ```tsx
 * const { data: rules, loading, error, refetch } = useRuleList(filters)
 * ```
 */
export function useRuleList(filters: Partial<RuleListFilters> = {}): UseFetchResult<RuleSummary[]> {
  return useFetch(
    () => api.listRules(filters),
    { deps: [JSON.stringify(filters)] },
  )
}
