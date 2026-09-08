import { req } from './client'

// The authenticated DAST scanner and the per-judgment runtime-verification workflow. Requests carry
// json tags (snake_case); the Proposal / ApprovalDecision / runner Result responses have no Go json
// tags, so they arrive PascalCase and the mappers read that.

export interface DastScanInput {
  target: string
  ratePerSec?: number
  concurrency?: number
  maxDepth?: number
  maxPages?: number
  maxRequests?: number
  wallClock?: string
  selectedCheckIds?: string[]
}

/** A proposed action awaiting a human decision (from a scan or a runtime-verification proposal). */
export interface DastProposal {
  actionId: string
  tool: string
  action: string
  targetKind: string
  targetValue: string
  egressPreview: string
  risk: string
  rationale: string
  proposedAt: string
  decisionState: string
  decidedBy: string
  decisionReason: string
}

export interface DastDecision {
  actionId: string
  state: string
  decidedBy: string
  reason: string
  decidedAt: string
}

export interface DastProof {
  checkId: string
  version: string
  normalizedEndpoint: string
  hash: string
}

export interface DastScanResult {
  digest: string
  incomplete: boolean
  reason: string
  requestCount: number
  coverageCount: number
  proofs: DastProof[]
}

export interface DastRun {
  id: string
  status: string
  verdict: string
  httpStatus: number
  evidenceId: string
  errorCode: string
  startedAt: string
  finishedAt: string
}

export interface RuntimeVerifyInput {
  url: string
  method: string
  expectedStatus: number
  expectedBodyContains?: string
  scoreIfConfirmed: number
  scoreIfRefuted: number
  version: number
  rationale?: string
}

/** The outcome of running a runtime verification: either a durable run to poll, or an in-memory result. */
export interface RuntimeVerifyOutcome {
  durable: boolean
  run: DastRun | null
  proof: string
  status: number
  evidenceId: string
}

function mapProposal(raw: any): DastProposal {
  const action = raw?.Action ?? {}
  const decision = raw?.Decision ?? {}
  return {
    actionId: action?.ID ?? '',
    tool: action?.Tool ?? '',
    action: action?.Action ?? '',
    targetKind: action?.Target?.Kind ?? '',
    targetValue: action?.Target?.Value ?? '',
    egressPreview: action?.EgressPreview ?? '',
    risk: action?.Risk ?? '',
    rationale: action?.Rationale ?? '',
    proposedAt: action?.ProposedAt ?? '',
    decisionState: decision?.State ?? 'pending',
    decidedBy: decision?.DecidedBy ?? '',
    decisionReason: decision?.Reason ?? '',
  }
}

function mapDecision(raw: any): DastDecision {
  return {
    actionId: raw?.ActionID ?? '',
    state: raw?.State ?? '',
    decidedBy: raw?.DecidedBy ?? '',
    reason: raw?.Reason ?? '',
    decidedAt: raw?.DecidedAt ?? '',
  }
}

function mapRun(raw: any): DastRun {
  return {
    id: raw?.id ?? '',
    status: raw?.status ?? '',
    verdict: raw?.verdict ?? '',
    httpStatus: raw?.http_status ?? 0,
    evidenceId: raw?.evidence_id ?? '',
    errorCode: raw?.error_code ?? '',
    startedAt: raw?.started_at ?? '',
    finishedAt: raw?.finished_at ?? '',
  }
}

function mapScanResult(raw: any): DastScanResult {
  return {
    digest: raw?.config_sha256 ?? '',
    incomplete: Boolean(raw?.incomplete),
    reason: raw?.reason ?? '',
    requestCount: Array.isArray(raw?.surface?.Requests) ? raw.surface.Requests.length : 0,
    coverageCount: Array.isArray(raw?.coverage?.Entries) ? raw.coverage.Entries.length : 0,
    proofs: (Array.isArray(raw?.proofs) ? raw.proofs : []).map((p: any) => ({
      checkId: p?.check_id ?? '',
      version: p?.version ?? '',
      normalizedEndpoint: p?.normalized_endpoint ?? '',
      hash: p?.hash ?? '',
    })),
  }
}

function scanBody(input: DastScanInput) {
  return {
    target: input.target,
    session: {},
    crawler: {
      seeds: input.target ? [{ Method: 'GET', URL: input.target }] : [],
      rate_per_sec: input.ratePerSec ?? 2,
      concurrency: input.concurrency ?? 2,
      max_depth: input.maxDepth ?? 3,
      max_pages: input.maxPages ?? 50,
      max_requests: input.maxRequests ?? 200,
      wall_clock: input.wallClock ?? '30s',
    },
    selected_check_ids: input.selectedCheckIds ?? [],
  }
}

function runtimeBody(input: RuntimeVerifyInput) {
  return {
    url: input.url,
    method: input.method || 'GET',
    expected_status: input.expectedStatus,
    expected_body_contains: input.expectedBodyContains ?? '',
    score_if_confirmed: input.scoreIfConfirmed,
    score_if_refuted: input.scoreIfRefuted,
    version: input.version,
    rationale: input.rationale ?? '',
  }
}

export const dastApi = {
  proposeDastScan: async (engagementId: string, input: DastScanInput): Promise<DastProposal> =>
    mapProposal(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/proposals`, { method: 'POST', body: JSON.stringify(scanBody(input)) })),

  runDastScan: async (engagementId: string, actionId: string, input: DastScanInput): Promise<DastScanResult> =>
    mapScanResult(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/proposals/${encodeURIComponent(actionId)}/run`, { method: 'POST', body: JSON.stringify(scanBody(input)) })),

  getDastRun: async (engagementId: string, runId: string): Promise<DastRun> =>
    mapRun(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/runs/${encodeURIComponent(runId)}`)),

  // Approve or deny a proposed action (a scan or a runtime-verification probe). Separation of duties:
  // the reviewer here must not be the operator who proposed it.
  decideDastApproval: async (engagementId: string, actionId: string, approve: boolean, reason: string): Promise<DastDecision> =>
    mapDecision(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/approvals/${encodeURIComponent(actionId)}/decide`, { method: 'POST', body: JSON.stringify({ approve, reason }) })),

  proposeRuntimeVerification: async (engagementId: string, judgmentId: string, input: RuntimeVerifyInput): Promise<DastProposal> =>
    mapProposal(await req(`/engagements/${encodeURIComponent(engagementId)}/judgments/${encodeURIComponent(judgmentId)}/runtime-verification/proposals`, { method: 'POST', body: JSON.stringify(runtimeBody(input)) })),

  runRuntimeVerification: async (engagementId: string, judgmentId: string, actionId: string, input: RuntimeVerifyInput): Promise<RuntimeVerifyOutcome> => {
    const raw = await req(`/engagements/${encodeURIComponent(engagementId)}/judgments/${encodeURIComponent(judgmentId)}/runtime-verification/proposals/${encodeURIComponent(actionId)}/run`, { method: 'POST', body: JSON.stringify(runtimeBody(input)) })
    // Durable path answers a dastrun.Run (snake_case, has an id/status); the in-memory path answers a
    // runner Result (PascalCase Proof/Status/Evidence).
    if (raw && (raw.status !== undefined || raw.id !== undefined) && raw.Proof === undefined) {
      return { durable: true, run: mapRun(raw), proof: '', status: 0, evidenceId: '' }
    }
    return { durable: false, run: null, proof: raw?.Proof ?? '', status: raw?.Status ?? 0, evidenceId: raw?.Evidence ?? '' }
  },
}
