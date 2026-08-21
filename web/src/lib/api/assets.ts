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
  return { id: r.ID ?? '', key: r.Key ?? '', name: r.Name ?? '', description: r.Description ?? '', type: r.Type ?? 'application', criticality: r.Criticality ?? 'medium', lifecycle: r.Lifecycle ?? 'draft', owner: r.Owner ?? '', metadata: r.Metadata ?? {}, version: r.Version ?? 1, createdAt: r.Audit?.CreatedAt ?? null, updatedAt: r.Audit?.UpdatedAt ?? null, posture: r.posture, postureExplanation: r.posture_explanation }
}

function mapAssetMembership(r: any): AssetMembership {
  return { componentId: r.ComponentID ?? '', role: r.Role ?? 'supporting', provenance: r.Provenance ?? '' }
}

function mapTechnicalAsset(r: any): TechnicalAsset {
  return { id: r.ID ?? '', kind: r.Kind ?? '', key: r.Key ?? '', name: r.Name ?? '', attributes: r.Attributes ?? {} }
}

export const assetsApi = {
  listTechnicalAssets: async (): Promise<TechnicalAsset[]> =>
    ((await req('/assets')) ?? []).map(mapTechnicalAsset),

  listBusinessAssets: async (query = ''): Promise<BusinessAssetPage> => {
    const raw = await req(`/appsec/assets${query ? `?${query}` : ''}`)
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
