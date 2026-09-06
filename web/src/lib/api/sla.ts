import { ApiError, req } from './client'

/**
 * SLA remediation policy (tenant-wide). A Policy is an immutable, tenant-owned config version; activating
 * another one only moves the active pointer, so historical assessments keep the exact version they were
 * scored under. The scoring Config is fully declarative: factor Weights (each the MAX points that factor
 * contributes; the five positive weights sum to 100), score Thresholds mapping 0..100 to a tier (strictly
 * descending, positive), and per-tier DueRanges. Durations arrive as int64 nanoseconds; the client works
 * in days at the edge. Routes register only with the SLA use case wired, so a 404 means "not enabled".
 *
 * SOURCE OF TRUTH: `internal/domain/sla/{config,assessment}.go`, handler `sla_handler.go`
 * (`listSLAPolicies`, `activateSLAPolicy`).
 */

export interface SLAWeights {
  severity: number
  exploitability: number
  threatIntel: number
  exposure: number
  criticality: number
  feasibilityRelief: number
}

export interface SLAThresholds {
  emergency: number
  critical: number
  high: number
  medium: number
}

export interface SLADueRange {
  mitigateDays: number
  remediateDays: number
}

export type SLADueTier = 'emergency' | 'critical' | 'high' | 'medium' | 'low' | 'exception'

export type SLADueRanges = Record<SLADueTier, SLADueRange>

export interface SLAConfig {
  version: string
  weights: SLAWeights
  thresholds: SLAThresholds
  dueRanges: SLADueRanges
}

export interface SLAPolicy {
  tenantId: string
  config: SLAConfig
  sha256: string
  createdBy: string
  createdAt: string
}

export interface SLAPoliciesView {
  active: SLAPolicy | null
  policies: SLAPolicy[]
}

const NS_PER_DAY = 24 * 60 * 60 * 1_000_000_000

export function nsToDays(ns: number): number {
  return Math.round((ns / NS_PER_DAY) * 100) / 100
}

export function daysToNs(days: number): number {
  return Math.round(days * NS_PER_DAY)
}

const DUE_TIERS: SLADueTier[] = ['emergency', 'critical', 'high', 'medium', 'low', 'exception']

function mapDueRange(r: any): SLADueRange {
  return { mitigateDays: nsToDays(r?.mitigate_within ?? 0), remediateDays: nsToDays(r?.remediate_within ?? 0) }
}

function mapConfig(c: any): SLAConfig {
  const w = c?.weights ?? {}
  const t = c?.thresholds ?? {}
  const d = c?.due_ranges ?? {}
  const dueRanges = {} as SLADueRanges
  for (const tier of DUE_TIERS) dueRanges[tier] = mapDueRange(d[tier])
  return {
    version: c?.version ?? '',
    weights: {
      severity: w.severity ?? 0,
      exploitability: w.exploitability ?? 0,
      threatIntel: w.threat_intel ?? 0,
      exposure: w.exposure ?? 0,
      criticality: w.criticality ?? 0,
      feasibilityRelief: w.feasibility_relief ?? 0,
    },
    thresholds: {
      emergency: t.emergency ?? 0,
      critical: t.critical ?? 0,
      high: t.high ?? 0,
      medium: t.medium ?? 0,
    },
    dueRanges,
  }
}

function mapPolicy(p: any): SLAPolicy | null {
  if (!p || typeof p !== 'object') return null
  // A real Policy always carries a config version (sla.NewPolicy requires a non-empty version). The zero
  // Policy the server sends for `active` when nothing is activated has an empty Config, hence an empty
  // version. Detect it by that: Go's zero time.Time marshals to "0001-01-01T00:00:00Z", not "", so
  // created_at cannot be used to spot an absent policy.
  if (!p.config?.version) return null
  const createdBy = p.created_by ?? ''
  const createdAt = p.created_at ?? ''
  return {
    tenantId: p.tenant_id ?? '',
    config: mapConfig(p.config),
    sha256: p.sha256 ?? '',
    createdBy,
    createdAt,
  }
}

function toConfigWire(c: SLAConfig): Record<string, unknown> {
  const due: Record<string, unknown> = {}
  for (const tier of DUE_TIERS) {
    due[tier] = { mitigate_within: daysToNs(c.dueRanges[tier].mitigateDays), remediate_within: daysToNs(c.dueRanges[tier].remediateDays) }
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
    thresholds: {
      emergency: c.thresholds.emergency,
      critical: c.thresholds.critical,
      high: c.thresholds.high,
      medium: c.thresholds.medium,
    },
    due_ranges: due,
  }
}

export interface SLAActivateResult {
  policy: SLAPolicy | null
  created: boolean
}

export const slaApi = {
  /** null when the deployment does not expose SLA governance (route 404). */
  slaPolicies: async (): Promise<SLAPoliciesView | null> => {
    try {
      const r = await req('/sla/policies')
      return {
        active: mapPolicy(r?.active),
        policies: Array.isArray(r?.policies) ? r.policies.map(mapPolicy).filter((p: SLAPolicy | null): p is SLAPolicy => p !== null) : [],
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },
  activateSLAPolicy: async (config: SLAConfig): Promise<SLAActivateResult> => {
    const r = await req('/sla/policies', { method: 'POST', body: JSON.stringify({ config: toConfigWire(config) }) })
    return { policy: mapPolicy(r?.policy), created: r?.created === true }
  },
}
