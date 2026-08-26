import type {
  AssetCoverage,
  AssetFinding,
  AssetHistoryItem,
  AssetMembership,
  AssetPosture,
  BusinessAsset,
  BusinessAssetInput,
  BusinessAssetPage,
  TechnicalAsset,
} from '../types'
import { req } from './client'
import { mapEngagement } from './engagements'
import { mapFinding } from './findings'
import type { Engagement } from '../types'

function mapBusinessAsset(r: any): BusinessAsset {
  if (!r) return null as any
  return {
    id: r.ID ?? r.id ?? '',
    key: r.Key ?? r.key ?? '',
    name: r.Name ?? r.name ?? '',
    description: r.Description ?? r.description ?? '',
    type: r.Type ?? r.type ?? 'application',
    criticality: r.Criticality ?? r.criticality ?? 'medium',
    lifecycle: r.Lifecycle ?? r.lifecycle ?? 'draft',
    owner: r.Owner ?? r.owner ?? '',
    metadata: r.Metadata ?? r.metadata ?? {},
    version: r.Version ?? r.version ?? 1,
    createdAt: r.Audit?.CreatedAt ?? r.Audit?.created_at ?? r.created_at ?? null,
    updatedAt: r.Audit?.UpdatedAt ?? r.Audit?.updated_at ?? r.updated_at ?? null,
    posture: r.posture,
    postureExplanation: r.posture_explanation,
  }
}

function mapAssetMembership(r: any): AssetMembership {
  return {
    componentId: r.ComponentID ?? r.component_id ?? r.componentId ?? r.id ?? '',
    role: r.Role ?? r.role ?? 'supporting',
    provenance: r.Provenance ?? r.provenance ?? '',
  }
}

function mapTechnicalAsset(r: any): TechnicalAsset {
  return {
    id: r.ID ?? r.id ?? '',
    kind: r.Kind ?? r.kind ?? '',
    key: r.Key ?? r.key ?? '',
    name: r.Name ?? r.name ?? '',
    attributes: r.Attributes ?? r.attributes ?? {},
  }
}

export const assetsApi = {
  listTechnicalAssets: async (): Promise<TechnicalAsset[]> =>
    ((await req('/assets')) ?? []).map(mapTechnicalAsset),

  listBusinessAssets: async (query = '', signal?: AbortSignal): Promise<BusinessAssetPage> => {
    const raw = await req(`/appsec/assets${query ? `?${query}` : ''}`, signal ? { signal } : undefined)
    return { items: (raw.items ?? []).map(mapBusinessAsset), total: raw.total ?? 0, limit: raw.limit ?? 50, offset: raw.offset ?? 0 }
  },

  getBusinessAsset: async (id: string): Promise<BusinessAsset> =>
    mapBusinessAsset(await req(`/appsec/assets/${encodeURIComponent(id)}`)),

  createBusinessAsset: async (input: BusinessAssetInput): Promise<BusinessAsset> =>
    mapBusinessAsset(await req('/appsec/assets', { method: 'POST', body: JSON.stringify(input) })),

  updateBusinessAsset: async (id: string, input: BusinessAssetInput): Promise<BusinessAsset> =>
    mapBusinessAsset(await req(`/appsec/assets/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(input) })),

  businessAssetProjects: async (id: string): Promise<AssetMembership[]> =>
    ((await req(`/appsec/assets/${encodeURIComponent(id)}/projects`)) ?? []).map(mapAssetMembership),

  replaceBusinessAssetProjects: async (id: string, items: AssetMembership[]): Promise<void> =>
    req(`/appsec/assets/${encodeURIComponent(id)}/projects`, { method: 'PUT', body: JSON.stringify({ items: items.map(x => ({ id: x.componentId, role: x.role, provenance: x.provenance })) }) }),

  businessAssetTechnicalAssets: async (id: string): Promise<AssetMembership[]> =>
    ((await req(`/appsec/assets/${encodeURIComponent(id)}/technical-assets`)) ?? []).map(mapAssetMembership),

  replaceBusinessAssetTechnicalAssets: async (id: string, items: AssetMembership[]): Promise<void> =>
    req(`/appsec/assets/${encodeURIComponent(id)}/technical-assets`, { method: 'PUT', body: JSON.stringify({ items: items.map(x => ({ id: x.componentId, role: x.role, provenance: x.provenance })) }) }),

  businessAssetEngagements: async (id: string): Promise<Engagement[]> =>
    ((await req(`/appsec/assets/${encodeURIComponent(id)}/engagements`)) ?? []).map(mapEngagement),

  businessAssetFindings: async (id: string): Promise<AssetFinding[]> =>
    ((await req(`/appsec/assets/${encodeURIComponent(id)}/findings`)) ?? []).map((r: any) => ({
      finding: mapFinding(r.finding),
      external: r.external ?? false,
      canSelfPromote: r.can_self_promote,
      suppressedByTool: r.suppressed_by_tool ?? false,
      provenance: r.provenance ? { toolName: r.provenance.ToolName ?? '', toolVersion: r.provenance.ToolVersion ?? '', ruleId: r.provenance.RuleID ?? '', sourceDigest: r.provenance.SourceDigest ?? '', ingestedBy: r.provenance.IngestedBy ?? '', ingestedAt: r.provenance.IngestedAt ?? null } : undefined,
      reachability: { state: r.reachability?.state ?? 'unknown', tier: r.reachability?.tier ?? 'tier-0', confidence: r.reachability?.confidence ?? 0, path: r.reachability?.path ?? [], status: r.reachability?.status ?? '', source: r.reachability?.source ?? 'none', history: (r.reachability?.history ?? []).map((h: any) => ({ judgmentId: h.judgment_id ?? '', state: h.state ?? 'unknown', tier: h.tier ?? 'tier-0', confidence: h.confidence ?? 0, path: h.path ?? [], status: h.status ?? '', observedAt: h.observed_at ?? null })) },
      engagementId: r.engagement_id ?? '',
      engagementName: r.engagement_name ?? '',
    })),

  businessAssetCoverage: async (id: string): Promise<AssetCoverage> => {
    const r = await req(`/appsec/assets/${encodeURIComponent(id)}/coverage`)
    return { rows: (r.rows ?? []).map((x: any) => ({ kind: x.kind ?? '', componentId: x.component_id ?? '', name: x.name ?? '', verdict: x.verdict ?? 'unknown', engagementId: x.engagement_id ?? '', lastAssessed: x.last_assessed ?? null, freshnessTargetDays: x.freshness_target_days ?? 0 })), counts: r.counts ?? {}, freshnessTargetDays: r.freshness_target_days ?? 0 }
  },

  businessAssetPosture: async (id: string): Promise<AssetPosture> => {
    const r = await req(`/appsec/assets/${encodeURIComponent(id)}/posture`)
    return { rating: r.rating ?? 'unknown', explanation: r.explanation ?? '', findingCounts: r.finding_counts ?? {}, coverageCounts: r.coverage_counts ?? {} }
  },

  businessAssetHistory: async (id: string): Promise<AssetHistoryItem[]> =>
    ((await req(`/appsec/assets/${encodeURIComponent(id)}/history`)) ?? []).map((r: any) => ({ engagementId: r.engagement_id ?? '', name: r.name ?? '', status: r.status ?? '', authorizedFrom: r.authorized_from ?? null, authorizedTo: r.authorized_to ?? null, scopeCount: r.scope_count ?? 0, findingCount: r.finding_count ?? 0, retestCount: r.retest_count ?? 0, updatedAt: r.updated_at ?? '' })),
}
