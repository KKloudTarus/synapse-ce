import type {
  FleetAgentDetail,
  FleetAgentHealth,
  FleetAgentRow,
  FleetCoverageRow,
  FleetCoverageSummary,
  FleetDesiredGap,
  HostFinding,
  HostRow,
  HostScan,
  HostVulnerabilities,
  HostVulnerabilitySummary,
} from '../types'
import { mapTechnicalAsset } from './assets'
import { blobDownload, req } from './client'
import { mapFinding } from './findings'

function mapHostScan(raw: any): HostScan | null {
  if (!raw) return null
  return {
    jobId: raw.job_id ?? '',
    status: (raw.status ?? 'running') as HostScan['status'],
    stage: raw.stage ?? '',
    error: raw.error ?? '',
    startedAt: raw.started_at ?? null,
    finishedAt: raw.finished_at ?? null,
  }
}

function mapHostSummary(raw: any): HostVulnerabilitySummary {
  return {
    total: raw?.total ?? 0,
    critical: raw?.critical ?? 0,
    high: raw?.high ?? 0,
    medium: raw?.medium ?? 0,
    low: raw?.low ?? 0,
    info: raw?.info ?? 0,
    fixable: raw?.fixable ?? 0,
    kev: raw?.kev ?? 0,
  }
}

function mapHostRow(raw: any): HostRow {
  return {
    asset: mapTechnicalAsset(raw?.asset ?? {}),
    engagementId: raw?.engagement_id ?? '',
    packages: raw?.packages ?? 0,
    recordedAt: raw?.recorded_at ?? null,
    lastScan: mapHostScan(raw?.last_scan),
    summary: mapHostSummary(raw?.summary),
  }
}

// Findings keep the PascalCase domain keys of the engagement findings list; cvss_score is the one
// snake_case addition the host route computes from the vector.
export function mapHostFinding(raw: any): HostFinding {
  return {
    ...mapFinding(raw),
    cvssScore: raw.cvss_score ?? 0,
    fixedVersion: raw.FixedVersion ?? '',
    advisoryId: raw.AdvisoryID ?? '',
    sources: Array.isArray(raw.Sources) ? raw.Sources : [],
    confidence: raw.Confidence ?? '',
    detectionState: raw.DetectionState ?? '',
  }
}

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
  listHosts: async (): Promise<HostRow[]> => ((await req('/assets/hosts')) ?? []).map(mapHostRow),

  hostVulnerabilities: async (assetId: string): Promise<HostVulnerabilities> => {
    const raw = await req(`/assets/${encodeURIComponent(assetId)}/vulnerabilities`)
    return { ...mapHostRow(raw), findings: (raw?.findings ?? []).map(mapHostFinding) }
  },

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

  // Desired-vs-observed capability reconciliation (#633). Rows are snake_case-tagged (ReconciliationRow).
  // The route only exists when the desired-capabilities service is wired, so callers degrade gracefully.
  fleetDesiredGaps: async (): Promise<FleetDesiredGap[]> => {
    const res = await req('/fleet/desired-capabilities/gaps')
    return (Array.isArray(res?.gaps) ? res.gaps : []).map(
      (raw: any): FleetDesiredGap => ({
        assetId: raw?.asset_id ?? '',
        capability: raw?.capability ?? '',
        covered: Boolean(raw?.covered),
        agentId: raw?.agent_id ?? '',
        agentHealth: raw?.agent_health ?? '',
        gapReason: raw?.gap_reason ?? '',
        detail: raw?.detail ?? '',
        lastSeen: raw?.last_seen ?? '',
      }),
    )
  },
}
