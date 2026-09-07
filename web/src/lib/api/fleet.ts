import type {
  FleetAgentDetail,
  FleetAgentHealth,
  FleetAgentRow,
  FleetCoverageRow,
  FleetCoverageSummary,
  FleetDesiredGap,
  HostFinding,
  HostPackages,
  HostRow,
  HostScan,
  HostVulnerabilities,
  HostVulnerabilitySummary,
} from '../types'

export interface WorkloadImage {
  ref: string
  digest: string
}

/** One Kubernetes workload and the images it runs, from the cluster-inventory graph. */
export interface Workload {
  cluster: string
  namespace: string
  kind: string
  name: string
  serviceAccount: string
  images: WorkloadImage[]
}

function mapWorkload(r: any): Workload {
  return {
    cluster: r?.cluster ?? '',
    namespace: r?.namespace ?? '',
    kind: r?.kind ?? '',
    name: r?.name ?? '',
    serviceAccount: r?.service_account ?? '',
    images: Array.isArray(r?.images) ? r.images.map((i: any) => ({ ref: i?.ref ?? '', digest: i?.digest ?? '' })) : [],
  }
}
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
  listHosts: async (): Promise<HostRow[]> => {
    // The endpoint answers a bare JSON array; guard against any non-array shape (an error body,
    // an object envelope) so a malformed response degrades to "no hosts" instead of crashing on .map.
    const res = await req('/assets/hosts')
    const rows = Array.isArray(res) ? res : Array.isArray(res?.hosts) ? res.hosts : []
    return rows.map(mapHostRow)
  },

  hostVulnerabilities: async (assetId: string): Promise<HostVulnerabilities> => {
    const raw = await req(`/assets/${encodeURIComponent(assetId)}/vulnerabilities`)
    return { ...mapHostRow(raw), findings: (raw?.findings ?? []).map(mapHostFinding) }
  },

  hostPackages: async (assetId: string): Promise<HostPackages> => {
    const raw = await req(`/assets/${encodeURIComponent(assetId)}/packages`)
    return {
      assetId: raw?.asset_id ?? '',
      engagementId: raw?.engagement_id ?? '',
      recordedAt: raw?.recorded_at ?? null,
      packages: (raw?.packages ?? []).map((p: any) => ({ name: p?.name ?? '', version: p?.version ?? '', purl: p?.purl ?? '' })),
    }
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
  // Immutable telemetry coverage-window revisions (#611): one sealed record per asset/agent/host window,
  // carrying the per-class sensor state and the sample/drop/gap counts the revision was computed from.
  // Filters are optional; the tenant comes from the authenticated session.
  listCoverageWindows: async (filters: CoverageWindowFilters = {}): Promise<CoverageWindow[]> => {
    const qs = new URLSearchParams()
    if (filters.agentId) qs.set('agent_id', filters.agentId)
    if (filters.assetId) qs.set('asset_id', filters.assetId)
    if (filters.hostId) qs.set('host_id', filters.hostId)
    if (filters.since) qs.set('since', filters.since)
    if (filters.until) qs.set('until', filters.until)
    if (filters.limit) qs.set('limit', String(filters.limit))
    const q = qs.toString()
    const res = await req(`/fleet/coverage-windows${q ? `?${q}` : ''}`)
    return (Array.isArray(res?.coverage_windows) ? res.coverage_windows : []).map(mapCoverageWindow)
  },

  // Re-hunt the endpoint state timeline in [around-before, around+after] on a host asset (#594 B7).
  retroHunt: async (assetId: string, input: RetroHuntRequest): Promise<RetroHuntResult> =>
    mapRetroHuntResult(
      await req(`/fleet/assets/${encodeURIComponent(assetId)}/retro-hunt`, {
        method: 'POST',
        body: JSON.stringify({
          around: input.around,
          before_seconds: input.beforeSeconds,
          after_seconds: input.afterSeconds,
          entity_id: input.entityId ?? '',
          limit: input.limit ?? 0,
        }),
      }),
    ),

  /**
   * Kubernetes workloads with the images they run, from the cluster-inventory graph. This is the
   * "which deployment/statefulset does this image come from" lookup: a container CVE found on an image
   * digest can be traced to every workload that runs it. Empty until a cluster agent ingests a snapshot.
   */
  fleetWorkloads: async (): Promise<Workload[]> => {
    const r = await req('/fleet/workloads')
    return Array.isArray(r?.workloads) ? r.workloads.map(mapWorkload) : []
  },

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

// --- Coverage windows (#611 immutable telemetry coverage revisions) ---

export interface CoverageWindowFilters {
  agentId?: string
  assetId?: string
  hostId?: string
  since?: string
  until?: string
  limit?: number
}

export type CoverageClass = 'process' | 'network' | 'file' | 'privilege'

export interface CoverageClassState {
  class: string
  hostId: string
  agentId: string
  state: string
  reason: string
  since: string
}

export interface CoverageVector {
  process: number
  network: number
  file: number
  privilege: number
  reasons: string[]
}

export interface CoverageWindow {
  assetId: string
  agentId: string
  hostId: string
  since: string
  until: string
  inputDigest: string
  revision: string
  createdAt: string
  states: CoverageClassState[]
  sampledCount: number
  truncatedCount: number
  droppedCount: number
  gapCount: number
  batchCount: number
  coverage: CoverageVector
}

function mapCoverageWindow(r: any): CoverageWindow {
  return {
    assetId: r?.asset_id ?? '',
    agentId: r?.agent_id ?? '',
    hostId: r?.host_id ?? '',
    since: r?.since ?? '',
    until: r?.until ?? '',
    inputDigest: r?.input_digest ?? '',
    revision: r?.revision ?? '',
    createdAt: r?.created_at ?? '',
    states: Array.isArray(r?.states)
      ? r.states.map((s: any): CoverageClassState => ({
          class: s?.class ?? '',
          hostId: s?.host_id ?? '',
          agentId: s?.agent_id ?? '',
          state: s?.state ?? '',
          reason: s?.reason ?? '',
          since: s?.since ?? '',
        }))
      : [],
    sampledCount: r?.sampled_count ?? 0,
    truncatedCount: r?.truncated_count ?? 0,
    droppedCount: r?.dropped_count ?? 0,
    gapCount: r?.gap_count ?? 0,
    batchCount: r?.batch_count ?? 0,
    coverage: {
      process: r?.coverage?.process ?? 0,
      network: r?.coverage?.network ?? 0,
      file: r?.coverage?.file ?? 0,
      privilege: r?.coverage?.privilege ?? 0,
      reasons: Array.isArray(r?.coverage?.reasons) ? r.coverage.reasons : [],
    },
  }
}

// --- Retro-hunt (#594 B7): re-hunt the endpoint state timeline in a window around a pivot ---

export interface RetroHuntRequest {
  around: string // RFC3339 pivot time
  beforeSeconds: number
  afterSeconds: number
  entityId?: string
  limit?: number
}

export interface TimelineEntry {
  occurredAt: string
  entityKind: string
  entityId: string
  kind: string
  eventId: string
  summary: string
}

export interface RetroHuntResult {
  assetId: string
  from: string
  to: string
  entries: TimelineEntry[]
  truncated: boolean
}

function mapTimelineEntry(r: any): TimelineEntry {
  return {
    occurredAt: r?.OccurredAt ?? r?.occurred_at ?? '',
    entityKind: r?.EntityKind ?? r?.entity_kind ?? '',
    entityId: r?.EntityID ?? r?.entity_id ?? '',
    kind: r?.Kind ?? r?.kind ?? '',
    eventId: r?.EventID ?? r?.event_id ?? '',
    summary: r?.Summary ?? r?.summary ?? '',
  }
}

export function mapRetroHuntResult(r: any): RetroHuntResult {
  return {
    assetId: r?.AssetID ?? r?.asset_id ?? '',
    from: r?.From ?? r?.from ?? '',
    to: r?.To ?? r?.to ?? '',
    entries: Array.isArray(r?.Entries) ? r.Entries.map(mapTimelineEntry) : Array.isArray(r?.entries) ? r.entries.map(mapTimelineEntry) : [],
    truncated: r?.Truncated ?? r?.truncated ?? false,
  }
}
