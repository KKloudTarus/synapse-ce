import { req } from './client'

/**
 * Blue-team governed response (#425) + the offensive kill switch. The response loop is admission-gated,
 * human-approved, audited, and reversible. NOTE: the shipped executor is a SIMULATION (no host effect); the
 * governance workflow — plan, approve, apply, verify, revert — is real. Routes register only when the fleet
 * subsystem is enabled, so the client treats a 404 as "not enabled".
 */
export type ResponseKind = 'isolate_host' | 'quarantine_file' | 'stop_process'
export type ResponseState = 'pending' | 'applied' | 'reverted' | 'failed' | 'expired'

export interface ResponseRecord {
  id: string
  kind: string
  target: string
  state: string
  approver?: string
  verification?: string
  evidenceId?: string
}

export interface ResponsePlanStep {
  label: string
  argv: string[]
  blastRadius: string
}

export interface ResponsePlan {
  kind: string
  target: string
  steps: ResponsePlanStep[]
}

export interface HaltResult {
  halted: boolean
  withinBound: boolean
  durationMs: number
  ordersHalted?: string[]
  chainsHalted?: string[]
}

function mapRecord(r: any): ResponseRecord {
  return {
    id: r?.id ?? '',
    kind: r?.kind ?? '',
    target: r?.target ?? '',
    state: r?.state ?? '',
    approver: r?.approver || undefined,
    verification: r?.verification || undefined,
    evidenceId: r?.evidence_id || undefined,
  }
}

function mapPlan(r: any): ResponsePlan {
  return {
    kind: r?.kind ?? '',
    target: r?.target ?? '',
    steps: Array.isArray(r?.steps)
      ? r.steps.map((s: any) => ({ label: s?.label ?? '', argv: Array.isArray(s?.argv) ? s.argv : [], blastRadius: s?.blast_radius ?? '' }))
      : [],
  }
}

export interface ApplyOutcome {
  record: ResponseRecord
  pending: boolean // 202: recorded, awaiting a second human approval
}

export const blueteamApi = {
  /** null when the deployment does not expose governed response (route 404). */
  listResponses: async (state?: ResponseState): Promise<ResponseRecord[] | null> => {
    try {
      const q = state ? `?state=${encodeURIComponent(state)}` : ''
      const res = await req(`/blueteam/response${q}`)
      return Array.isArray(res?.responses) ? res.responses.map(mapRecord) : []
    } catch (e: any) {
      if (e?.status === 404) return null
      throw e
    }
  },
  planResponse: async (engagementId: string, body: { kind: ResponseKind; target: string; target_kind?: string }): Promise<ResponsePlan> =>
    mapPlan(await req(`/blueteam/engagements/${encodeURIComponent(engagementId)}/response/plan`, { method: 'POST', body: JSON.stringify(body) })),
  applyResponse: async (engagementId: string, body: { kind: ResponseKind; target: string; target_kind?: string }): Promise<ApplyOutcome> => {
    // The apply route returns the record for both 202 (recorded, awaiting a second human) and 200 (applied);
    // the record's state distinguishes them.
    const record = mapRecord(await req(`/blueteam/engagements/${encodeURIComponent(engagementId)}/response/apply`, { method: 'POST', body: JSON.stringify(body) }))
    return { record, pending: record.state === 'pending' }
  },
  revertResponse: async (id: string, body: { target: string; target_kind?: string }): Promise<ResponseRecord> =>
    mapRecord(await req(`/blueteam/response/${encodeURIComponent(id)}/revert`, { method: 'POST', body: JSON.stringify(body) })),
  /** Halt every offensive path fleet-wide (kill switch). PermAdminister. */
  haltOffensive: async (reason: string): Promise<HaltResult> => {
    const r = await req('/redteam/halt', { method: 'POST', body: JSON.stringify({ reason }) })
    return { halted: r?.halted === true, withinBound: r?.within_bound === true, durationMs: r?.duration_ms ?? 0, ordersHalted: r?.orders_halted, chainsHalted: r?.chains_halted }
  },
}
