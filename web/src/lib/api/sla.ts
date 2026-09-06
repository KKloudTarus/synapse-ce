import { req } from './client'

// Risk-based-remediation SLA policy (#... slauc). The server stores an append-only history of policy
// versions per tenant and marks one active. A policy scores a finding 0-100 from weighted factors, maps
// the score to a tier via thresholds, and assigns a per-tier mitigate/remediate due range.
//
// The wire carries due ranges as Go time.Duration (nanoseconds). This module converts them to whole days
// at the boundary so the UI only ever deals in days.

const NS_PER_DAY = 86_400_000_000_000

export interface SlaWeights {
  severity: number
  exploitability: number
  threatIntel: number
  exposure: number
  criticality: number
  feasibilityRelief: number
}

export interface SlaThresholds {
  emergency: number
  critical: number
  high: number
  medium: number
}

// Due range in whole days (converted from the wire's nanoseconds).
export interface SlaDueRange {
  mitigateDays: number
  remediateDays: number
}

export type SlaTier = 'emergency' | 'critical' | 'high' | 'medium' | 'low' | 'exception'

export type SlaDueRanges = Record<SlaTier, SlaDueRange>

export interface SlaConfig {
  weights: SlaWeights
  thresholds: SlaThresholds
  dueRanges: SlaDueRanges
  version: string
}

export interface SlaPolicy {
  config: SlaConfig
  sha256: string
  createdBy: string
  createdAt: string | null
}

export const SLA_TIERS: SlaTier[] = ['emergency', 'critical', 'high', 'medium', 'low', 'exception']

function nsToDays(ns: unknown): number {
  const n = typeof ns === 'number' ? ns : 0
  return Math.round((n / NS_PER_DAY) * 10) / 10
}

function daysToNs(days: number): number {
  return Math.round(days * NS_PER_DAY)
}

function mapDueRange(r: any): SlaDueRange {
  return { mitigateDays: nsToDays(r?.mitigate_within), remediateDays: nsToDays(r?.remediate_within) }
}

function mapConfig(r: any): SlaConfig {
  const dr = r?.due_ranges ?? {}
  const ranges = {} as SlaDueRanges
  for (const tier of SLA_TIERS) ranges[tier] = mapDueRange(dr[tier])
  return {
    version: r?.version ?? '',
    weights: {
      severity: r?.weights?.severity ?? 0,
      exploitability: r?.weights?.exploitability ?? 0,
      threatIntel: r?.weights?.threat_intel ?? 0,
      exposure: r?.weights?.exposure ?? 0,
      criticality: r?.weights?.criticality ?? 0,
      feasibilityRelief: r?.weights?.feasibility_relief ?? 0,
    },
    thresholds: {
      emergency: r?.thresholds?.emergency ?? 0,
      critical: r?.thresholds?.critical ?? 0,
      high: r?.thresholds?.high ?? 0,
      medium: r?.thresholds?.medium ?? 0,
    },
    dueRanges: ranges,
  }
}

function mapPolicy(r: any): SlaPolicy | null {
  if (!r || !r.config) return null
  return {
    config: mapConfig(r.config),
    sha256: r?.sha256 ?? '',
    createdBy: r?.created_by ?? '',
    createdAt: r?.created_at ?? null,
  }
}

function configToWire(c: SlaConfig) {
  const dr: Record<string, { mitigate_within: number; remediate_within: number }> = {}
  for (const tier of SLA_TIERS) {
    dr[tier] = {
      mitigate_within: daysToNs(c.dueRanges[tier].mitigateDays),
      remediate_within: daysToNs(c.dueRanges[tier].remediateDays),
    }
  }
  return {
    version: c.version,
    weights: {
      severity: c.weights.severity,
      exploitability: c.weights.exploitability,
      threat_intel: c.weights.threatIntel,
      exposure: c.weights.exposure,
      criticality: c.weights.criticality,
      feasibility_relief: c.weights.feasibilityRelief,
    },
    thresholds: c.thresholds,
    due_ranges: dr,
  }
}

export const slaApi = {
  // Active policy plus the append-only version history for the tenant.
  slaPolicies: async (): Promise<{ active: SlaPolicy | null; policies: SlaPolicy[] }> => {
    const r = await req('/sla/policies')
    return {
      active: mapPolicy(r?.active),
      policies: Array.isArray(r?.policies) ? r.policies.map(mapPolicy).filter(Boolean) : [],
    }
  },
  // Append and activate a new policy version. PermAdminister. `created` is false when the config is
  // byte-identical to the already-active version (the server re-activates rather than duplicating).
  activateSLAPolicy: async (config: SlaConfig): Promise<{ policy: SlaPolicy | null; created: boolean }> => {
    const r = await req('/sla/policies', { method: 'POST', body: JSON.stringify({ config: configToWire(config) }) })
    return { policy: mapPolicy(r?.policy), created: r?.created === true }
  },
}
