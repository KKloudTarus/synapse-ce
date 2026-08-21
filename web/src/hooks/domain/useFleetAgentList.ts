import { api } from '../../lib/api'
import type { FleetAgentHealth, FleetAgentRow } from '../../lib/types'
import { useFetch, type UseFetchResult } from '../useFetch'

/**
 * Fetches the list of fleet agents, optionally filtered by health state.
 *
 * @example
 * ```tsx
 * const { data: agents, loading, error, refetch } = useFleetAgentList('unhealthy')
 * ```
 */
export function useFleetAgentList(state?: FleetAgentHealth): UseFetchResult<FleetAgentRow[]> {
  return useFetch(() => api.listFleetAgents(state), { deps: [state] })
}
