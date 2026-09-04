import type {
  CreateEngagementInput,
  Engagement,
  ScopeTarget,
  UploadedSourcePackage,
} from '../types'
import { newIdempotencyKey, req } from './client'

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

function mapEngagement(r: any): Engagement {
  const targets = (xs: any[]): { kind: string; value: string }[] =>
    (xs ?? []).map((t) => ({ kind: t.Kind ?? '', value: t.Value ?? '' }))
  return {
    id: r.ID,
    name: r.Name ?? '',
    client: r.Client ?? '',
    status: r.Status ?? '',
    inScope: targets(r.Scope?.InScope),
    outOfScope: targets(r.Scope?.OutOfScope),
    authorizedFrom: r.AuthorizedFrom ?? null,
    authorizedTo: r.AuthorizedTo ?? null,
    roe: {
      allowedToolClasses: r.RoE?.allowed_tool_classes ?? [],
      blackouts: (r.RoE?.blackouts ?? []).map((b: any) => ({ from: b.from ?? '', to: b.to ?? '' })),
    },
    liveReconEnabled: r.LiveReconEnabled ?? false,
    requiresExplicitExecutionAuthorization: r.RequiresExplicitExecutionAuthorization ?? false,
    createdAt: r.Audit?.CreatedAt ?? null,
    businessAssetId: r.BusinessAssetID ?? '',
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
        headers: { 'Idempotency-Key': newIdempotencyKey() },
        body: JSON.stringify(createRequest(input)),
      }),
    ),

  createEngagementFromSource: async (input: CreateEngagementInput, source: File): Promise<Engagement> => {
    const form = new FormData()
    form.append('metadata', JSON.stringify(createRequest(input)))
    form.append('source', source)
    return mapEngagement(await req('/engagements', {
      method: 'POST',
      headers: { 'Idempotency-Key': newIdempotencyKey() },
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
