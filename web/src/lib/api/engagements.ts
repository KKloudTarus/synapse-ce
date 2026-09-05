import type {
  CreateEngagementInput,
  Engagement,
  ScopeTarget,
  UploadedSourcePackage,
} from '../types'
import { req } from './client'
import type { EngagementWire, ScopeTargetWire } from './wire'

function createRequest(input: CreateEngagementInput) {
  return {
    name: input.name,
    client: input.client,
    in_scope: input.inScope.map((target) => ({ kind: target.kind, value: target.value })),
    out_of_scope: input.outOfScope.map((target) => ({ kind: target.kind, value: target.value })),
    authorized_from: input.authorizedFrom ?? '',
    authorized_to: input.authorizedTo ?? '',
    timezone: input.timezone ?? '',
    asset_id: input.assetId ?? '',
  }
}

// The wire shape is `engagementView` in internal/adapter/httpapi/resource_view.go: snake_case,
// with the audit timestamps flattened onto the resource. See ./wire.ts.
function mapEngagement(r: EngagementWire): Engagement {
  const targets = (xs: ScopeTargetWire[] | undefined): ScopeTarget[] =>
    (xs ?? []).map((t) => ({ kind: t?.kind ?? '', value: t?.value ?? '' }))
  return {
    id: r.id ?? '',
    name: r.name ?? '',
    client: r.client ?? '',
    status: r.status ?? '',
    inScope: targets(r.scope?.in_scope),
    outOfScope: targets(r.scope?.out_of_scope),
    authorizedFrom: r.authorized_from ?? null,
    authorizedTo: r.authorized_to ?? null,
    roe: {
      allowedToolClasses: r.roe?.allowed_tool_classes ?? [],
      blackouts: (r.roe?.blackouts ?? []).map((b) => ({ from: b?.from ?? '', to: b?.to ?? '' })),
    },
    liveReconEnabled: r.live_recon_enabled ?? false,
    createdAt: r.created_at ?? null,
    businessAssetId: r.business_asset_id ?? '',
    // Optional list-view enrichment; stays undefined when the API omits it.
    findingsCount: r.findings_count
      ? {
          total: r.findings_count.total ?? 0,
          critical: r.findings_count.critical ?? 0,
          high: r.findings_count.high ?? 0,
          medium: r.findings_count.medium ?? 0,
          low: r.findings_count.low ?? 0,
        }
      : undefined,
    lastScanDate: r.last_scan_date ?? undefined,
  }
}

export { mapEngagement }

export const engagementsApi = {
  listEngagements: async (): Promise<Engagement[]> =>
    ((await req('/engagements')) ?? []).map(mapEngagement),

  createEngagement: async (input: CreateEngagementInput): Promise<Engagement> =>
    mapEngagement(
      await req('/engagements', {
        method: 'POST',
        body: JSON.stringify(createRequest(input)),
      }),
    ),

  createEngagementFromSource: async (input: CreateEngagementInput, source: File): Promise<Engagement> => {
    const form = new FormData()
    form.append('metadata', JSON.stringify(createRequest(input)))
    form.append('source', source)
    return mapEngagement(await req('/engagements', {
      method: 'POST',
      body: form,
    }))
  },

  getEngagement: async (id: string): Promise<Engagement> =>
    mapEngagement(await req(`/engagements/${encodeURIComponent(id)}`)),

  uploadedSource: async (id: string): Promise<UploadedSourcePackage> => {
    const source = await req(`/engagements/${encodeURIComponent(id)}/source`)
    return {
      filename: source.filename ?? '',
      size: source.size ?? 0,
      sha256: source.sha256 ?? '',
      target: source.target ?? '',
      uploadedBy: source.uploaded_by ?? '',
      uploadedAt: source.uploaded_at ?? null,
    }
  },

  updateScope: async (id: string, inScope: ScopeTarget[], outOfScope: ScopeTarget[]): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(id)}/scope`, {
        method: 'PUT',
        body: JSON.stringify({
          in_scope: inScope.map((t) => ({ kind: t.kind, value: t.value })),
          out_of_scope: outOfScope.map((t) => ({ kind: t.kind, value: t.value })),
        }),
      }),
    ),

  setAuthorizationWindow: async (
    id: string,
    authorizedFrom: string,
    authorizedTo: string,
    timezone: string,
  ): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(id)}/authorization-window`, {
        method: 'PUT',
        body: JSON.stringify({ authorized_from: authorizedFrom, authorized_to: authorizedTo, timezone }),
      }),
    ),

  transitionEngagement: async (id: string, status: string): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    ),

  setRoE: async (
    id: string,
    allowedToolClasses: string[],
    blackouts: { from: string; to: string }[],
  ): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(id)}/roe`, {
        method: 'PUT',
        body: JSON.stringify({ allowed_tool_classes: allowedToolClasses, blackouts }),
      }),
    ),

  importBundle: async (bundleJSON: string): Promise<Engagement> =>
    mapEngagement(await req('/engagements/import', { method: 'POST', body: bundleJSON })),

  assignEngagementAsset: async (engagementId: string, assetId: string): Promise<void> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/asset`, { method: 'PUT', body: JSON.stringify({ asset_id: assetId }) }),
}
