import { req } from './client'

/**
 * Unified per-asset risk story (#427): one narrative per asset that correlates the asset's identity,
 * exposure, findings (with corroboration from reachability, attack paths, and detections), attack paths,
 * and runtime detections into a single ranked score. The read route reports an empty set when the
 * correlation view is not enabled, so the client treats [] as "not enabled".
 */
export interface RiskAssetFacts {
  kind: string
  key: string
  name: string
}

export interface RiskExposure {
  description: string
  confidence: string
  qualifiers: string[]
}

export interface RiskFinding {
  findingId: string
  title: string
  severity: string
  priority: number // 1..5 (1 = act now); 0 = unset
  riskScore: number
  kev: boolean
  reachability: string
  reachable: boolean
  onAttackPath: boolean
  seenUnderAttack: boolean
  corroboration: string[]
  rankReason: string
  lastObserved: string
  stale: boolean
}

export interface RiskPath {
  summary: string
  confidence: string
  qualifiers: string[]
}

export interface RiskDetection {
  ruleId: string
  severity: string
  observed: string
  stale: boolean
  qualifiers: string[]
}

export interface RiskStory {
  assetId: string
  identity: RiskAssetFacts
  exposure: RiskExposure[]
  findings: RiskFinding[]
  paths: RiskPath[]
  detections: RiskDetection[]
  score: number
  qualifiers: string[]
  generatedAt: string
}

function arr<T>(v: any, map: (x: any) => T): T[] {
  return Array.isArray(v) ? v.map(map) : []
}

function mapFinding(f: any): RiskFinding {
  return {
    findingId: f?.finding_id ?? '',
    title: f?.title ?? '',
    severity: f?.severity ?? '',
    priority: f?.priority ?? 0,
    riskScore: f?.risk_score ?? 0,
    kev: f?.kev === true,
    reachability: f?.reachability ?? '',
    reachable: f?.reachable === true,
    onAttackPath: f?.on_attack_path === true,
    seenUnderAttack: f?.seen_under_attack === true,
    corroboration: Array.isArray(f?.corroboration) ? f.corroboration : [],
    rankReason: f?.rank_reason ?? '',
    lastObserved: f?.last_observed ?? '',
    stale: f?.stale === true,
  }
}

function mapStory(s: any): RiskStory {
  return {
    assetId: s?.asset_id ?? '',
    identity: { kind: s?.identity?.kind ?? '', key: s?.identity?.key ?? '', name: s?.identity?.name ?? '' },
    exposure: arr(s?.exposure, (e) => ({ description: e?.description ?? '', confidence: e?.confidence ?? '', qualifiers: Array.isArray(e?.qualifiers) ? e.qualifiers : [] })),
    findings: arr(s?.findings, mapFinding),
    paths: arr(s?.paths, (p) => ({ summary: p?.summary ?? '', confidence: p?.confidence ?? '', qualifiers: Array.isArray(p?.qualifiers) ? p.qualifiers : [] })),
    detections: arr(s?.detections, (d) => ({ ruleId: d?.rule_id ?? '', severity: d?.severity ?? '', observed: d?.observed ?? '', stale: d?.stale === true, qualifiers: Array.isArray(d?.qualifiers) ? d.qualifiers : [] })),
    score: s?.score ?? 0,
    qualifiers: Array.isArray(s?.qualifiers) ? s.qualifiers : [],
    generatedAt: s?.generated_at ?? '',
  }
}

export const riskStoryApi = {
  // One assembled risk story per asset in the engagement. Returns [] when the correlation view is off.
  riskStories: async (engagementId: string): Promise<RiskStory[]> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/risk-stories`)
    return arr(r?.stories, mapStory)
  },
}
