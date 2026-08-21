import type {
  FleetAgentDetail,
  FleetAgentHealth,
  FleetAgentRow,
  FleetCoverageRow,
  FleetCoverageSummary,
} from '../types'
import { blobDownload, req } from './client'

function mapFleetAgent(raw: any): FleetAgentRow {
  return {
    id: raw?.id ?? '',
    name: raw?.name ?? '',
    platform: raw?.platform ?? '',
    agentVersion: raw?.agent_version ?? '',
    state: (raw?.state ?? 'healthy') as FleetAgentHealth,
    lastSeen: raw?.last_seen ?? '',
    capabilities: Array.isArray(raw?.capabilities) ? raw.capabilities : [],
    currentWork: raw?.current_work ?? 0,
  }
}

function mapFleetCoverageRow(raw: any): FleetCoverageRow {
  return {
    assetId: raw?.asset_id ?? '',
    capability: raw?.capability ?? '',
    verdict: (raw?.verdict ?? 'never') as FleetCoverageRow['verdict'],
    detail: raw?.detail ?? '',
    lastRun: raw?.last_run ?? '',
    agentId: raw?.agent_id ?? '',
  }
}

export const fleetApi = {
  listFleetAgents: async (state?: FleetAgentHealth): Promise<FleetAgentRow[]> => {
    const q = new URLSearchParams()
    if (state) q.set('state', state)
    const qs = q.toString()
    return ((await req(`/fleet/agents${qs ? `?${qs}` : ''}`)) ?? []).map(mapFleetAgent)
  },

  getFleetAgent: async (id: string): Promise<FleetAgentDetail> => {
    const res = await req(`/fleet/agents/${encodeURIComponent(id)}`)
    return {
      agent: mapFleetAgent(res?.agent ?? {}),
      recentWork: (res?.recent_work ?? []).map((r: any) => ({
        id: r?.id ?? '',
        capability: r?.capability ?? '',
        assetId: r?.asset_id ?? '',
        state: r?.state ?? '',
        updatedAt: r?.updated_at ?? '',
      })),
    }
  },

  listFleetCoverage: async (): Promise<FleetCoverageRow[]> =>
    ((await req('/fleet/coverage')) ?? []).map(mapFleetCoverageRow),

  fleetCoverageSummary: async (): Promise<FleetCoverageSummary> => {
    const res = await req('/fleet/coverage/summary')
    return {
      agentsByState: res?.agents_by_state ?? {},
      rowsByVerdict: res?.rows_by_verdict ?? {},
      oldestPerCapability: res?.oldest_per_capability ?? {},
      assetsWithoutAgent: res?.assets_without_agent ?? 0,
    }
  },

  exportFleetCoverage: async (): Promise<void> => {
    await blobDownload('/api/v1/fleet/coverage/export', 'fleet-coverage.csv')
  },
}
