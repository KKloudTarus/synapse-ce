import { req } from './client'

// The authenticated DAST scanner and the per-judgment runtime-verification workflow. Requests carry
// json tags (snake_case). Proposals have a lowercase envelope with PascalCase nested
// action/decision fields; older envelopes and runner results use PascalCase.

export interface DastSessionConfig {
  scheme: 'form' | 'basic' | 'bearer' | 'header' | 'cookie'
  credentials: { name: string; reference: string; field: string }[]
  login_request: { method: string; path: string }
  success: { status_code?: number; body_contains?: string; header_present?: string; cookie_present?: string }
  check_request: { method: string; path: string }
  deny_paths?: string[]
  max_reauth?: number
}

export interface DastScanInput {
  target: string
  session: DastSessionConfig
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
  version: number
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

export interface DastScanRun {
  id: string
  kind: 'authenticated_scan'
  engagementId: string
  actionId: string
  actor: string
  status: 'queued' | 'running' | 'succeeded' | 'incomplete' | 'failed'
  evidenceId: string
  errorCode: string
  startedAt: string
  finishedAt: string
  result: DastScanResult | null
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
  const action = raw?.action ?? raw?.Action ?? {}
  const decision = raw?.decision ?? raw?.Decision ?? {}
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

function mapScanResult(data: Record<string, unknown>): DastScanResult {
  const surface = data.surface as Record<string, unknown>
  const coverage = data.coverage as Record<string, unknown>
  const proofs = data.proofs == null ? [] : data.proofs
  if (!Array.isArray(proofs) ||
      (surface.Requests != null && !Array.isArray(surface.Requests)) ||
      (coverage.Entries != null && !Array.isArray(coverage.Entries))) throw new Error('Invalid authenticated scan result')
  return {
    digest: data.config_sha256 as string,
    incomplete: data.incomplete as boolean,
    reason: typeof data.reason === 'string' ? data.reason : '',
    requestCount: Array.isArray(surface.Requests) ? surface.Requests.length : 0,
    coverageCount: Array.isArray(coverage.Entries) ? coverage.Entries.length : 0,
    proofs: proofs.map((value: unknown) => {
      if (!value || typeof value !== 'object') throw new Error('Invalid authenticated scan proof')
      const proof = value as Record<string, unknown>
      if (typeof proof.check_id !== 'string' || typeof proof.version !== 'number' || !Number.isInteger(proof.version) ||
          typeof proof.normalized_endpoint !== 'string' || typeof proof.hash !== 'string') throw new Error('Invalid authenticated scan proof')
      return { checkId: proof.check_id, version: proof.version, normalizedEndpoint: proof.normalized_endpoint, hash: proof.hash }
    }),
  }
}

function mapScanRun(value: unknown): DastScanRun {
  if (!value || typeof value !== 'object') throw new Error('Invalid authenticated scan run response')
  const raw = value as Record<string, unknown>
  const status = raw.status
  if (raw.kind !== 'authenticated_scan' ||
      (status !== 'queued' && status !== 'running' && status !== 'succeeded' && status !== 'incomplete' && status !== 'failed') ||
      typeof raw.id !== 'string' || !raw.id || typeof raw.engagement_id !== 'string' || !raw.engagement_id ||
      typeof raw.action_id !== 'string' || !raw.action_id || typeof raw.actor !== 'string') {
    throw new Error('Invalid authenticated scan run response')
  }
  const terminalResult = status === 'succeeded' || status === 'incomplete'
  const result = raw.result
  let mappedResult: DastScanResult | null = null
  if (terminalResult || (status === 'failed' && result != null)) {
    if (!result || typeof result !== 'object') throw new Error('Invalid authenticated scan result')
    const data = result as Record<string, unknown>
    if (typeof data.config_sha256 !== 'string' || !data.config_sha256 ||
        typeof data.incomplete !== 'boolean' || data.incomplete !== (status !== 'succeeded') ||
        !data.surface || typeof data.surface !== 'object' || !data.coverage || typeof data.coverage !== 'object' ||
        (data.proofs != null && !Array.isArray(data.proofs))) throw new Error('Invalid authenticated scan result')
    mappedResult = mapScanResult(data)
  } else if (status !== 'failed' && result != null) {
    throw new Error('Invalid authenticated scan result')
  }
  return {
    id: raw.id, kind: 'authenticated_scan', engagementId: raw.engagement_id, actionId: raw.action_id,
    actor: raw.actor, status, evidenceId: typeof raw.evidence_id === 'string' ? raw.evidence_id : '',
    errorCode: typeof raw.error_code === 'string' ? raw.error_code : '',
    startedAt: typeof raw.started_at === 'string' ? raw.started_at : '',
    finishedAt: typeof raw.finished_at === 'string' ? raw.finished_at : '',
    result: mappedResult,
  }
}

function scanBody(input: DastScanInput) {
  return {
    target: input.target,
    session: input.session,
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

  runDastScan: async (engagementId: string, actionId: string, input: DastScanInput): Promise<DastScanRun> =>
    mapScanRun(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/proposals/${encodeURIComponent(actionId)}/run`, { method: 'POST', body: JSON.stringify(scanBody(input)) })),

  getDastScanRun: async (engagementId: string, runId: string): Promise<DastScanRun> =>
    mapScanRun(await req(`/engagements/${encodeURIComponent(engagementId)}/dast/scans/runs/${encodeURIComponent(runId)}`)),

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
