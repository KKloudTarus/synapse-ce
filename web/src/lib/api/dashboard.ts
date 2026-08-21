import type { DashboardSecurityOperations, Judgment, ThreatModel } from '../types'
import { ApiError, req } from './client'

function mapThreatModel(r: any): ThreatModel {
  return {
    components: (r.components ?? []).map((c: any) => ({
      id: c.id ?? '',
      name: c.name ?? '',
      kind: c.kind ?? '',
      boundary: c.boundary ?? '',
      assets: c.assets ?? [],
    })),
    flows: (r.flows ?? []).map((f: any) => ({
      id: f.id ?? '',
      from: f.from ?? '',
      to: f.to ?? '',
      data: f.data ?? '',
      dataAsset: f.data_asset ?? '',
    })),
    boundaries: (r.boundaries ?? []).map((b: any) => ({ id: b.id ?? '', name: b.name ?? '' })),
    assets: (r.assets ?? []).map((a: any) => ({
      id: a.id ?? '',
      name: a.name ?? '',
      classification: a.classification ?? '',
    })),
  }
}

function mapJudgment(r: any): Judgment {
  return {
    id: r.ID ?? '',
    engagementId: r.EngagementID ?? '',
    capability: r.Capability ?? '',
    subjectKind: r.SubjectKind ?? '',
    subjectId: r.SubjectID ?? '',
    state: (r.State ?? 'proposed') as Judgment['state'],
    evidenceScore: r.EvidenceScore ?? 0,
    proposedBy: r.ProposedBy ?? '',
    version: r.Version ?? 0,
    claim: r.Claim ?? {},
  }
}

export const dashboardApi = {
  dashboardSecurityOperations: async (rangeDays = 30): Promise<DashboardSecurityOperations> => {
    const res = await req(`/dashboard/security-operations?range=${rangeDays}d`)
    return {
      rangeDays: res?.range_days ?? rangeDays,
      generatedAt: res?.generated_at ?? '',
      assetPosture: res?.asset_posture ?? {},
      assetsByCriticality: res?.assets_by_criticality ?? {},
      activeFindingsBySeverity: res?.active_findings_by_severity ?? {},
      findingsOverTime: (res?.findings_over_time ?? []).map((point: any) => ({ date: point?.date ?? '', counts: point?.counts ?? {} })),
      findingsWithoutTimestamp: res?.findings_without_timestamp ?? 0,
      externalFindingsIncluded: res?.external_findings_included ?? false,
    }
  },

  threatModel: async (engagementId: string): Promise<ThreatModel | null> => {
    try {
      return mapThreatModel(await req(`/engagements/${encodeURIComponent(engagementId)}/threat-model`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  judgments: async (engagementId: string): Promise<Judgment[]> => {
    try {
      const r = await req(`/engagements/${encodeURIComponent(engagementId)}/judgments`)
      return (r?.judgments ?? []).map(mapJudgment)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return []
      throw e
    }
  },

  verifyJudgment: async (
    engagementId: string,
    judgmentId: string,
    score: number,
    rationale: string,
    version: number,
  ): Promise<Judgment> =>
    mapJudgment(
      await req(
        `/engagements/${encodeURIComponent(engagementId)}/judgments/${encodeURIComponent(judgmentId)}/verify`,
        { method: 'POST', body: JSON.stringify({ score, rationale, version }) },
      ),
    ),

  acceptJudgment: async (engagementId: string, judgmentId: string, version: number): Promise<Judgment> =>
    mapJudgment(
      await req(
        `/engagements/${encodeURIComponent(engagementId)}/judgments/${encodeURIComponent(judgmentId)}/accept`,
        { method: 'POST', body: JSON.stringify({ version }) },
      ),
    ),
}
