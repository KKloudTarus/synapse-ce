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

// Purple-team coverage (#426): for each executed attack technique, whether the expected detection fired.
// covered = executed and detected; gap = executed but undetected (produces a work item); unknown = not
// executed this run; out_of_reach = the platform cannot emulate it.
export type PurpleVerdict = 'out_of_reach' | 'unknown' | 'covered' | 'gap'

export interface PurpleCoverageRow {
  runId: string
  assetId: string
  techniqueId: string
  taxonomyRef: string
  expected: string
  actual: string[]
  verdict: PurpleVerdict
  computedAt: string
}

export interface PurpleWorkItem {
  techniqueId: string
  taxonomyRef: string
  missingDetection: string
}

// The coverage records carry no JSON tags server-side, so the wire keys are PascalCase; tolerate a
// snake_case shape too in case tags are added later.
function mapPurpleRow(r: any): PurpleCoverageRow {
  return {
    runId: r?.RunID ?? r?.run_id ?? '',
    assetId: r?.AssetID ?? r?.asset_id ?? '',
    techniqueId: r?.TechniqueID ?? r?.technique_id ?? '',
    taxonomyRef: r?.TaxonomyRef ?? r?.taxonomy_ref ?? '',
    expected: r?.Expected ?? r?.expected ?? '',
    actual: Array.isArray(r?.Actual) ? r.Actual : Array.isArray(r?.actual) ? r.actual : [],
    verdict: (r?.Verdict ?? r?.verdict ?? 'unknown') as PurpleVerdict,
    computedAt: r?.ComputedAt ?? r?.computed_at ?? '',
  }
}

function mapPurpleWorkItem(r: any): PurpleWorkItem {
  return {
    techniqueId: r?.TechniqueID ?? r?.technique_id ?? '',
    taxonomyRef: r?.TaxonomyRef ?? r?.taxonomy_ref ?? '',
    missingDetection: r?.MissingDetection ?? r?.missing_detection ?? '',
  }
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
  // Purple-team coverage trend for an engagement (all coverage records across runs). Returns [] when the
  // feature is not enabled (the route answers an empty set rather than 404).
  purpleCoverage: async (engagementId: string): Promise<PurpleCoverageRow[]> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/purple-coverage`)
    return Array.isArray(r?.coverage) ? r.coverage.map(mapPurpleRow) : []
  },
  // The gap work items (one per undetected technique) for a single run.
  purpleWorkItems: async (engagementId: string, runId: string): Promise<PurpleWorkItem[]> => {
    const r = await req(
      `/engagements/${encodeURIComponent(engagementId)}/purple-coverage?run=${encodeURIComponent(runId)}`,
    )
    return Array.isArray(r?.work_items) ? r.work_items.map(mapPurpleWorkItem) : []
  },
  /** Run adversary emulation against a target asset, producing purple coverage. PermOperate. Returns a
   *  small summary; the coverage itself is read back through purpleCoverage. */
  runEmulation: async (
    engagementId: string,
    target: string,
  ): Promise<{ runId: string; techniques: number; executed: number }> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/emulation`, {
      method: 'POST',
      body: JSON.stringify({ target }),
    })
    // demu.Run carries no json tags, so keys are the capitalized Go field names; read defensively.
    const run = r?.run ?? {}
    const coverage: unknown[] = Array.isArray(run.Coverage) ? run.Coverage : Array.isArray(run.coverage) ? run.coverage : []
    const executed = coverage.filter((c) => {
      const rec = c as Record<string, unknown>
      return rec?.Executed === true || rec?.executed === true
    }).length
    return { runId: run.ID ?? run.id ?? '', techniques: coverage.length, executed }
  },
  /** Halt every offensive path fleet-wide (kill switch). PermAdminister. */
  haltOffensive: async (reason: string): Promise<HaltResult> => {
    const r = await req('/redteam/halt', { method: 'POST', body: JSON.stringify({ reason }) })
    return { halted: r?.halted === true, withinBound: r?.within_bound === true, durationMs: r?.duration_ms ?? 0, ordersHalted: r?.orders_halted, chainsHalted: r?.chains_halted }
  },
}
