import type {
  CreateEngagementInput,
  Engagement,
  ScopeTarget,
} from '../types'
import { req } from './client'

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
    createdAt: r.Audit?.CreatedAt ?? null,
    businessAssetId: r.BusinessAssetID ?? '',
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
        body: JSON.stringify({
          name: input.name,
          client: input.client,
          in_scope: input.inScope.map((t) => ({ kind: t.kind, value: t.value })),
          out_of_scope: input.outOfScope.map((t) => ({ kind: t.kind, value: t.value })),
          authorized_from: input.authorizedFrom ?? '',
          authorized_to: input.authorizedTo ?? '',
          timezone: input.timezone ?? '',
          asset_id: input.assetId ?? '',
        }),
      }),
    ),

  getEngagement: async (id: string): Promise<Engagement> =>
    mapEngagement(await req(`/engagements/${encodeURIComponent(id)}`)),

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
