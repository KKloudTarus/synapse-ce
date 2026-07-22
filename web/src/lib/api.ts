import type {
  AgentDecision,
  AgentReadiness,
  AgentPlan,
  AgentMessage,
  AgentSession,
  AupStatus,
  CodeQualityView,
  CodeQualityReport,
  CodeRating,
  Component,
  PendingApproval,
  CreateEngagementInput,
  CreateProjectInput,
  Engagement,
  Project,
  ProjectAnalysis,
  ProjectAnalysisCursor,
  ProjectAnalysisPage,
  LatestProjectAnalysis,
  EvidenceItem,
  EvidenceLedger,
  Finding,
  FindingComment,
  ImportedSBOMMetadata,
  Judgment,
  ScanJob,
  ScanResult,
  Severity,
  AuditEntry,
  AuditReport,
  CurrentUser,
  ReconRun,
  ReconTool,
  Retest,
  RetestOutcome,
  ScopeTarget,
  User,
  UserRole,
  Vulnerability,
  Writeup,
  ThreatModel,
  RuleSummary,
  RuleDetail,
  RuleListFilters,
  RuleType,
  RuleQuality,
  RuleSeverity,
  RuleDetection,
  QualityGate,
  QualityProfile,
  Grade,
  Hotspot,
  HotspotStatus,
  HotspotListFilter,
  HotspotPage,
  HotspotReviewEvent,
  ProjectIssue,
  IssueStatus,
  IssueListFilter,
  IssuePage,
  IssueReviewEvent,
} from './types'
import { mapProjectOverviewResponse, type ProjectOverview } from './projectOverview'
import { mapProjectMeasureResponse, type MeasuresQuery, type ProjectMeasureResponse } from './projectMeasures'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

let token = ''
let onUnauthorized: (() => void) | null = null

export function setToken(t: string): void {
  token = t
}
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn
}

async function req(path: string, init?: RequestInit): Promise<any> {
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {}),
      },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body?.error) msg = body.error
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204) return null
  return res.json()
}

export async function projectMeasures(projectKey: string, query: MeasuresQuery, signal?: AbortSignal): Promise<ProjectMeasureResponse> {
  const q = new URLSearchParams()
  if (query.path) q.set('path', query.path)
  if (query.limit) q.set('limit', query.limit.toString())
  if (query.cursor) q.set('cursor', query.cursor) // Never decode or mutate cursor
  if (query.domain) {
    for (const d of query.domain) {
      if (d) q.append('domain', d)
    }
  }
  const qs = q.toString()
  const raw = await req(`/projects/${encodeURIComponent(projectKey)}/measures${qs ? `?${qs}` : ''}`, { signal })
  return mapProjectMeasureResponse(raw)
}


// ---- mappers: raw API JSON (mixed casing) → clean types ----

function mapQualityProfile(r: any): QualityProfile {
  const activatedRules: Record<string, { severity: string }> = {}
  for (const [k, v] of Object.entries(r?.activated_rules ?? {})) {
    activatedRules[k] = { severity: (v as any)?.severity ?? '' }
  }
  return {
    key: r?.key ?? '',
    name: r?.name ?? '',
    language: r?.language ?? '',
    parent: r?.parent ?? '',
    activatedRules,
    builtIn: r?.built_in ?? false,
  }
}

function mapQualityGate(r: any): QualityGate {
  return {
    key: r.key ?? '',
    name: r.name ?? '',
    conditions: (r.conditions ?? []).map((condition: any) => ({ metric: condition.metric ?? '', op: condition.op ?? '<=', threshold: condition.threshold ?? 0 })),
    builtIn: r.built_in ?? false,
  }
}

function mapProject(r: any): Project {
  return {
    id: r.ID ?? '',
    name: r.Name ?? '',
    key: r.Key ?? '',
    sourceBinding: {
      kind: r.SourceBinding?.Kind ?? 'local',
      value: r.SourceBinding?.Value ?? '',
      ref: r.SourceBinding?.Ref ?? '',
    },
    defaultProfileByLang: r.DefaultProfileByLang ?? {},
    gateId: r.GateID ?? '',
    createdAt: r.Audit?.CreatedAt ?? null,
    latestAnalysis: r.latest_analysis ? mapProjectSummaryAnalysis(r.latest_analysis) : null,
    latestJob: r.latest_job ? mapScanJob(r.latest_job) : null,
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
    createdAt: r.Audit?.CreatedAt ?? null,
  }
}

function mapFinding(r: any): Finding {
  return {
    id: r.ID,
    engagementId: r.EngagementID ?? '',
    title: r.Title ?? '',
    description: r.Description ?? '',
    severity: r.Severity ?? 'unknown',
    cvssVector: r.CVSSVector ?? '',
    cwe: r.CWE ?? '',
    status: r.Status ?? 'open',
    dedupKey: r.DedupKey ?? '',
    kev: r.KEV ?? false,
    riskScore: r.RiskScore ?? 0,
    class: r.Class ?? 'third_party',
    scope: r.Scope ?? 'unknown',
    reachability: r.Reachability ?? 'unknown',
    impact: r.Impact ?? '',
    priority: r.Priority ?? 3,
    assignee: r.Assignee ?? '',
    version: r.Version ?? 1,
    kind: r.Kind ?? '',
    evidenceScore: r.EvidenceScore ?? 0,
    proposedBy: r.ProposedBy ?? '',
    // server augments the findings list with compliance_controls (compliance.Control has no
    // json tags → PascalCase Framework/ID/Title); absent on findings whose CWE maps to nothing.
    complianceControls: (r.compliance_controls ?? []).map((c: any) => ({
      framework: c.Framework ?? '',
      id: c.ID ?? '',
      title: c.Title ?? '',
    })),
  }
}

function mapComment(r: any): FindingComment {
  return {
    id: r.ID ?? '',
    findingId: r.FindingID ?? '',
    author: r.Author ?? '',
    body: r.Body ?? '',
    createdAt: r.CreatedAt ?? null,
  }
}

function mapVuln(r: any): Vulnerability {
  return {
    id: r.ID,
    source: r.Source ?? '',
    severity: r.Severity ?? 'unknown',
    cvssVector: r.CVSSVector ?? '',
    cvssScore: r.CVSSScore ?? 0,
    component: r.Component ?? '',
    version: r.Version ?? '',
    fixedVersion: r.FixedVersion ?? '',
    description: r.Description ?? '',
    kev: r.KEV ?? false,
    epss: r.EPSS ?? 0,
    path: r.Path ?? [],
    direct: r.Direct ?? false,
    sources: r.Sources ?? [],
    confidence: r.Confidence ?? '',
    detections: (r.Detections ?? []).map((d: any) => ({
      source: d.Source ?? '',
      advisoryId: d.AdvisoryID ?? '',
      severity: d.Severity ?? 'unknown',
      fixedVersion: d.FixedVersion ?? '',
    })),
    firstParty: r.FirstParty ?? false,
    unversioned: r.Unversioned ?? false,
  }
}

function mapComponent(r: any): Component {
  return {
    name: r.Name ?? '',
    version: r.Version ?? '',
    purl: r.PURL ?? '',
    licenses: (r.Licenses ?? []).map((l: any) => ({
      spdxId: l.SPDXID ?? '',
      name: l.Name ?? '',
      category: l.Category ?? 'unknown',
    })),
    licenseSource: r.LicenseSource ?? '',
    licenseConfidence: r.LicenseConfidence ?? '',
    unknownReason: r.UnknownReason ?? '',
    firstParty: r.FirstParty ?? false,
    location: r.Location ?? '',
  }
}

/** Fetch a SARIF/OpenVEX export with the bearer token and trigger a browser download. */
async function blobDownload(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { headers: token ? { authorization: `Bearer ${token}` } : {} })
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const b = await res.json()
      if (b?.error) msg = b.error
    } catch {
      /* non-JSON */
    }
    throw new ApiError(res.status, msg)
  }
  const blob = await res.blob()
  const cd = res.headers.get('content-disposition') ?? ''
  const filename = /filename="([^"]+)"/.exec(cd)?.[1] ?? fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export async function downloadExport(engagementId: string, format: 'sarif' | 'openvex' | 'spdx' | 'cyclonedx'): Promise<void> {
  const id = encodeURIComponent(engagementId)
  await blobDownload(`/api/v1/engagements/${id}/export/${format}`, `synapse-${engagementId}.${format}.json`)
}

export async function downloadReport(engagementId: string): Promise<void> {
  const id = encodeURIComponent(engagementId)
  await blobDownload(`/api/v1/engagements/${id}/report.pdf`, `synapse-${engagementId}-report.pdf`)
}

/** Download a portable engagement bundle (scope + findings + evidence chain). */
export async function downloadBundle(engagementId: string): Promise<void> {
  const id = encodeURIComponent(engagementId)
  await blobDownload(`/api/v1/engagements/${id}/bundle`, `synapse-${engagementId}-bundle.json`)
}

// ReportType is the deliverable variant. Empty = sca default.
export type ReportType = 'sca' | 'external' | 'internal' | 'retest'

// Options for the report builder. Empty arrays/title mean "everything" /
// the type default – they are only narrowing filters server-side.
export interface ReportBuildOptions {
  type?: ReportType
  sections?: string[]
  statuses?: string[]
  title?: string
}

/** Build + download a customized HTML or DOCX report. */
export async function downloadReportDoc(
  engagementId: string,
  format: 'html' | 'docx',
  opts: ReportBuildOptions = {},
): Promise<void> {
  const id = encodeURIComponent(engagementId)
  const q = new URLSearchParams()
  if (opts.type && opts.type !== 'sca') q.set('type', opts.type)
  for (const s of opts.sections ?? []) q.append('section', s)
  for (const s of opts.statuses ?? []) q.append('status', s)
  if (opts.title?.trim()) q.set('title', opts.title.trim())
  const qs = q.toString()
  await blobDownload(
    `/api/v1/engagements/${id}/report.${format}${qs ? `?${qs}` : ''}`,
    `synapse-${engagementId}-report.${format}`,
  )
}

// ReconLogEvent is one parsed SSE frame from a run's live log stream.
export interface ReconLogEvent {
  id: number
  line?: string
  done?: boolean
}

/**
 * Stream a recon run's logs over SSE. We use fetch (not EventSource) because the
 * browser EventSource API cannot attach the bearer token header. Resolves when the
 * stream ends (done event or the body closes); reconnect by calling again with the
 * last seen event id. Abort via opts.signal.
 */
export async function streamReconLogs(
  engagementId: string,
  runId: string,
  opts: { lastEventId?: number; signal?: AbortSignal; onEvent: (e: ReconLogEvent) => void },
): Promise<void> {
  const id = encodeURIComponent(engagementId)
  const rid = encodeURIComponent(runId)
  const qs = opts.lastEventId ? `?lastEventId=${opts.lastEventId}` : ''
  const res = await fetch(`/api/v1/engagements/${id}/recon/runs/${rid}/logs${qs}`, {
    headers: token ? { authorization: `Bearer ${token}`, accept: 'text/event-stream' } : { accept: 'text/event-stream' },
    signal: opts.signal,
  })
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok || !res.body) throw new ApiError(res.status, `log stream HTTP ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += decoder.decode(value, { stream: true })
    let sep
    while ((sep = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, sep)
      buf = buf.slice(sep + 2)
      let evId = 0
      let event = ''
      let data = ''
      for (const ln of frame.split('\n')) {
        if (ln.startsWith('id:')) evId = parseInt(ln.slice(3).trim(), 10) || 0
        else if (ln.startsWith('event:')) event = ln.slice(6).trim()
        else if (ln.startsWith('data:')) data += ln.slice(5).trim()
      }
      if (event === 'done') {
        opts.onEvent({ id: evId, done: true })
        return
      }
      try {
        const parsed = JSON.parse(data) as { line?: string }
        opts.onEvent({ id: evId, line: parsed.line })
      } catch {
        /* keep-alive / non-JSON frame */
      }
    }
  }
}

// --- AI agent orchestration ---

// agent.Session has no json tags → PascalCase Go field names.
function mapAgentSession(r: any): AgentSession {
  return {
    id: r.ID ?? '',
    engagementId: r.EngagementID ?? '',
    initiatedBy: r.InitiatedBy ?? '',
    goal: r.Goal ?? '',
    model: r.Model ?? '',
    status: r.Status ?? '',
    steps: r.Steps ?? 0,
    tokensUsed: r.TokensUsed ?? 0,
    createdAt: r.CreatedAt ?? null,
    updatedAt: r.UpdatedAt ?? null,
  }
}

// agent.Message HAS json tags → snake_case/lowercase keys.
function mapAgentMessage(r: any): AgentMessage {
  return {
    role: r.role ?? '',
    content: r.content ?? '',
    toolCalls: (r.tool_calls ?? []).map((c: any) => ({ id: c.id ?? '', name: c.name ?? '' })),
    toolCallId: r.tool_call_id ?? '',
  }
}

// agent.ProposedAction has no json tags → PascalCase; Target is {Kind,Value}.
function mapProposedAction(r: any): PendingApproval {
  return {
    id: r.ID ?? '',
    sessionId: r.SessionID ?? '',
    tool: r.Tool ?? '',
    action: r.Action ?? '',
    target: r.Target?.Value ?? '',
    argv: r.Argv ?? [],
    egressPreview: r.EgressPreview ?? [],
    risk: r.Risk ?? '',
    rationale: r.Rationale ?? '',
  }
}

// AgentStreamEvent is one transcript message (or the terminal marker) on the session stream.
export interface AgentStreamEvent {
  id: number
  message?: AgentMessage
  done?: boolean
  status?: string
}

// streamAgentSession tails a session's transcript as SSE (poll-backed server side). Reconnect
// via lastEventId (the message sequence). Mirrors streamReconLogs.
export async function streamAgentSession(
  engagementId: string,
  sessionId: string,
  opts: { lastEventId?: number; signal?: AbortSignal; onEvent: (e: AgentStreamEvent) => void },
): Promise<void> {
  const id = encodeURIComponent(engagementId)
  const sid = encodeURIComponent(sessionId)
  const qs = opts.lastEventId ? `?lastEventId=${opts.lastEventId}` : ''
  const res = await fetch(`/api/v1/engagements/${id}/agent/sessions/${sid}/stream${qs}`, {
    headers: token ? { authorization: `Bearer ${token}`, accept: 'text/event-stream' } : { accept: 'text/event-stream' },
    signal: opts.signal,
  })
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok || !res.body) throw new ApiError(res.status, `agent stream HTTP ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += decoder.decode(value, { stream: true })
    let sep
    while ((sep = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, sep)
      buf = buf.slice(sep + 2)
      let evId = 0
      let event = ''
      let data = ''
      for (const ln of frame.split('\n')) {
        if (ln.startsWith('id:')) evId = parseInt(ln.slice(3).trim(), 10) || 0
        else if (ln.startsWith('event:')) event = ln.slice(6).trim()
        else if (ln.startsWith('data:')) data += ln.slice(5).trim()
      }
      if (event === 'done') {
        let status = ''
        try {
          status = (JSON.parse(data) as { status?: string }).status ?? ''
        } catch {
          /* ignore */
        }
        opts.onEvent({ id: evId, done: true, status })
        return
      }
      try {
        opts.onEvent({ id: evId, message: mapAgentMessage(JSON.parse(data)) })
      } catch {
        /* keep-alive / non-JSON frame */
      }
    }
  }
}

// Evidence links serialize with PascalCase keys (domain struct, no json tags);
// the ledger wrapper uses lowercase (it has tags).
function mapEvidenceItem(r: any): EvidenceItem {
  return {
    id: r.ID ?? '',
    kind: r.Kind ?? '',
    contentBase64: r.Content ?? '',
    hash: r.Hash ?? '',
    previousHash: r.PreviousHash ?? '',
    storageRef: r.StorageRef ?? '',
    createdBy: r.CreatedBy ?? '',
    createdAt: r.CreatedAt ?? null,
  }
}

function mapScanJob(r: any): ScanJob {
  return {
    id: r.id ?? '',
    engagementId: r.engagement_id ?? '',
    target: r.target ?? '',
    kind: r.kind ?? '',
    status: r.status ?? 'running',
    stage: r.stage ?? '',
    progress: r.progress ?? 0,
    startedAt: r.started_at ?? null,
    finishedAt: r.finished_at ?? null,
    error: r.error ?? '',
    debugEvents: (r.debug_events ?? []).map(mapScanDebugEvent),
  }
}

function mapScanDebugEvent(r: any) {
  return {
    stage: r.stage ?? '',
    step: r.step ?? '',
    status: r.status ?? 'running',
    message: r.message ?? '',
    tool: r.tool ?? '',
    counts: r.counts ?? {},
    startedAt: r.started_at ?? null,
    finishedAt: r.finished_at ?? null,
    durationMs: r.duration_ms ?? 0,
    error: r.error ?? '',
  }
}

function mapCodeQualityReport(rep: any): CodeQualityReport {
  return {
    inventory: (rep?.inventory?.languages ?? []).map((l: any) => ({
      language: l.language,
      files: l.files ?? 0,
      codeLines: l.code_lines ?? 0,
      commentLines: l.comment_lines ?? 0,
      blankLines: l.blank_lines ?? 0,
      functions: l.functions ?? 0,
      functionsKnown: !!l.functions_known,
    })),
    findings: (rep?.findings ?? []).map(mapFinding),
    duplication: {
      blocks: (rep?.duplication?.blocks ?? []).map((b: any) => ({
        tokens: b.tokens ?? 0,
        occurrences: (b.occurrences ?? []).map((o: any) => ({ file: o.file, startLine: o.start_line ?? 0, endLine: o.end_line ?? 0 })),
      })),
      duplicatedLines: rep?.duplication?.duplicated_lines ?? 0,
      totalLines: rep?.duplication?.total_lines ?? 0,
      files: rep?.duplication?.files ?? 0,
    },
    rating: {
      security: (rep?.rating?.security ?? '?') as CodeRating['security'],
      reliability: (rep?.rating?.reliability ?? '?') as CodeRating['reliability'],
      maintainability: (rep?.rating?.maintainability ?? '?') as CodeRating['maintainability'],
      techDebtMinutes: rep?.rating?.tech_debt_minutes ?? 0,
      debtRatioPct: rep?.rating?.debt_ratio_pct ?? 0,
      linesOfCode: rep?.rating?.lines_of_code ?? 0,
    },
  }
}

function mapProjectSummaryAnalysis(r: any): ProjectAnalysis {
  const counts = (value: any) => ({ total: value?.total ?? 0, byKind: value?.by_kind ?? {}, bySeverity: value?.by_severity ?? {}, byStatus: value?.by_status ?? {} })
  const grade = (value: any): CodeRating => ({ security: (value?.security ?? '?') as CodeRating['security'], reliability: (value?.reliability ?? '?') as CodeRating['reliability'], maintainability: (value?.maintainability ?? '?') as CodeRating['maintainability'], techDebtMinutes: 0, debtRatioPct: 0, linesOfCode: 0 })
  return { id: r.id ?? '', createdAt: r.created_at ?? '', sourceRef: '', sourceCommit: r.source_commit ?? '', gate: { passed: r.gate_passed ?? false, results: [] }, gateInfo: { key: r.gate_info?.key ?? '', name: r.gate_info?.name ?? 'Quality gate', source: r.gate_info?.source ?? '' }, issues: counts(r.issues), newCode: { previousId: '', counts: { ...counts(null), total: r.new_issues ?? 0 }, rating: { security: '?', reliability: '?', maintainability: null } }, delta: null, measures: {}, coverage: null, duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 }, rating: grade(r.rating) }
}

function mapProjectAnalysis(r: any): ProjectAnalysis {
  const counts = (value: any) => ({ total: value?.total ?? 0, byKind: value?.by_kind ?? {}, bySeverity: value?.by_severity ?? {}, byStatus: value?.by_status ?? {} })
  const rating = (value: any): CodeRating => ({
    security: (value?.security ?? '?') as CodeRating['security'], reliability: (value?.reliability ?? '?') as CodeRating['reliability'],
    maintainability: (value?.maintainability ?? '?') as CodeRating['maintainability'], techDebtMinutes: value?.tech_debt_minutes ?? 0,
    debtRatioPct: value?.debt_ratio_pct ?? 0, linesOfCode: value?.lines_of_code ?? 0,
  })
  return {
    id: r.id ?? '', createdAt: r.created_at ?? '', sourceRef: r.source_ref ?? '', sourceCommit: r.source_commit ?? '',
    gate: { passed: r.gate?.passed ?? false, results: (r.gate?.results ?? []).map((result: any) => ({ condition: { metric: result.metric ?? '', op: result.op ?? '', threshold: result.threshold ?? 0 }, actual: result.actual ?? 0, passed: result.passed ?? false })) },
    gateInfo: { key: r.gate_info?.key ?? '', name: r.gate_info?.name ?? 'Quality gate', source: r.gate_info?.source ?? '' },
    issues: counts(r.issues), newCode: { previousId: r.new_code?.previous_id ?? '', counts: counts(r.new_code?.counts), rating: { security: (r.new_code?.rating?.security ?? '?') as Grade, reliability: (r.new_code?.rating?.reliability ?? '?') as Grade, maintainability: r.new_code?.rating?.maintainability ? r.new_code.rating.maintainability as Grade : null } },
    delta: r.delta ? { issues: counts(r.delta.issues), measures: r.delta.measures ?? {}, ratings: r.delta.ratings ?? {} } : null, measures: r.measures ?? {},
    coverage: r.coverage ? { coveredLines: r.coverage.covered_lines ?? 0, totalLines: r.coverage.total_lines ?? 0 } : null,
    duplication: { blocks: [], duplicatedLines: r.duplication?.duplicated_lines ?? 0, totalLines: r.duplication?.total_lines ?? 0, files: r.duplication?.files ?? 0 }, rating: rating(r.rating),
  }
}

function mapScanResult(r: any): ScanResult {
  return {
    target: r.target ?? '',
    scanMode: r.scan_mode ?? 'full',
    languages: (r.languages ?? []).map((l: any) => ({ name: l.Name ?? '', percent: l.Percent ?? 0 })),
    components: (r.sbom?.Components ?? []).map(mapComponent),
    dependencies: (r.sbom?.Dependencies ?? []).map((d: any) => ({ ref: d.Ref ?? '', dependsOn: d.DependsOn ?? [] })),
    vulnerabilities: (r.vulnerabilities ?? []).map(mapVuln),
    licenses: (r.licenses ?? []).map((l: any) => ({
      license: l.license ?? '',
      category: l.category ?? 'unknown',
      verdict: l.verdict ?? 'warn',
      components: l.components ?? [],
    })),
    findings: (r.findings ?? []).map(mapFinding),
    toolVersions: r.tool_versions ?? {},
    vulnDBSnapshot: r.vuln_db_snapshot ?? '',
    completeness: {
      lockfiles: r.completeness?.lockfiles ?? [],
      componentsTotal: r.completeness?.components_total ?? 0,
      componentsResolved: r.completeness?.components_resolved ?? 0,
      confident: r.completeness?.confident ?? true,
      warning: r.completeness?.warning ?? '',
    },
    licenseCoverage: {
      total: r.license_coverage?.total ?? 0,
      detected: r.license_coverage?.detected ?? 0,
      unknown: r.license_coverage?.unknown ?? 0,
      pct: r.license_coverage?.pct ?? 0,
    },
    findingQuality: {
      rawFindings: r.finding_quality?.raw_findings ?? 0,
      actionable: r.finding_quality?.actionable ?? 0,
      background: r.finding_quality?.background ?? 0,
      production: r.finding_quality?.production ?? 0,
      development: r.finding_quality?.development ?? 0,
      exampleTest: r.finding_quality?.example_test ?? 0,
      thirdParty: r.finding_quality?.third_party ?? 0,
      firstPartyHistorical: r.finding_quality?.first_party_historical ?? 0,
      versionCoveragePct: r.finding_quality?.version_coverage_pct ?? 0,
      pathCoveragePct: r.finding_quality?.path_coverage_pct ?? 0,
      confidence: r.finding_quality?.confidence ?? '',
      byPriority: r.finding_quality?.by_priority ?? {},
    },
    manifest: {
      toolVersions: r.manifest?.tool_versions ?? {},
      vulnDBSnapshot: r.manifest?.vuln_db_snapshot ?? '',
      grypeDBVersion: r.manifest?.grype_db_version ?? '',
      correlationVersion: r.manifest?.correlation_version ?? 0,
      sbomSha256: r.manifest?.sbom_sha256 ?? '',
      reproScore: r.manifest?.repro_score ?? 0,
      pinnedInputs: r.manifest?.pinned_inputs ?? [],
      unpinnedInputs: r.manifest?.unpinned_inputs ?? [],
    },
    codeQuality: r.code_quality ? mapCodeQualityReport(r.code_quality) : undefined,
    debugEvents: (r.debug_events ?? []).map(mapScanDebugEvent),
  }
}

function mapImportedSBOMMetadata(r: any): ImportedSBOMMetadata {
  return {
    id: r.id ?? '',
    engagementId: r.engagement_id ?? '',
    filename: r.filename ?? 'SBOM.json',
    format: r.format ?? '',
    specVersion: r.spec_version ?? '',
    targetRef: r.target_ref ?? '',
    componentCount: r.component_count ?? 0,
    dependencyCount: r.dependency_count ?? 0,
    sha256: r.sha256 ?? '',
    createdBy: r.created_by ?? '',
    createdAt: r.created_at ?? null,
  }
}

// threatmodel.Model has json tags → lowercase keys; data_asset is snake_case.
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

// judgment.Judgment has NO json tags → PascalCase keys; the Claim's own fields DO have json tags
// (lowercase), so claim arrives as e.g. {drivers,priority} (risk_narrative) or {verdict,driver,
// confidence} (critique). The renderer narrows on `capability`.
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

// --- Rules ---

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => asString(v)) : []
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' ? value : fallback
}

function asRuleType(value: unknown): RuleType {
  const s = asString(value)
  return ['bug', 'vulnerability', 'code_smell', 'security_hotspot'].includes(s) ? (s as RuleType) : 'code_smell'
}

function asRuleQualityArray(value: unknown): RuleQuality[] {
  const arr = asStringArray(value)
  return arr.filter((s) => ['security', 'reliability', 'maintainability'].includes(s)) as RuleQuality[]
}

function asRuleSeverity(value: unknown): RuleSeverity {
  const s = asString(value)
  return ['low', 'medium', 'high', 'critical'].includes(s) ? (s as RuleSeverity) : 'medium'
}

function asRuleDetection(value: unknown): RuleDetection {
  const s = asString(value)
  return s === 'ast' || s === 'pattern' || s === 'metric' ? s : 'pattern'
}

function mapRuleSummary(raw: any): RuleSummary {
  return {
    key: asString(raw?.key),
    name: asString(raw?.name),
    language: asString(raw?.language),
    type: asRuleType(raw?.type),
    qualities: asRuleQualityArray(raw?.qualities),
    defaultSeverity: asRuleSeverity(raw?.default_severity),
    tags: asStringArray(raw?.tags),
    cwe: asStringArray(raw?.cwe),
    owasp: asStringArray(raw?.owasp),
    description: asString(raw?.description),
    remediationEffort: asNumber(raw?.remediation_effort),
    detection: asRuleDetection(raw?.detection),
  }
}

function mapRuleDetail(raw: any): RuleDetail {
  return {
    ...mapRuleSummary(raw),
    rationale: asString(raw?.rationale),
    remediation: asString(raw?.remediation),
    compliantExample: asString(raw?.compliant_example),
    noncompliantExample: asString(raw?.noncompliant_example),
  }
}

function mapHotspot(r: any): Hotspot {
  return {
    id: r.id ?? '',
    ruleKey: r.rule_key ?? '',
    ruleName: r.rule_name ?? '',
    title: r.title ?? '',
    description: r.description ?? '',
    severity: (r.severity ?? 'unknown') as Severity,
    kind: r.finding_kind ?? '',
    cwe: r.cwe ?? '',
    location: r.location ?? '',
    status: (r.status ?? 'to_review') as HotspotStatus,
    version: r.version ?? 1,
    firstSeenAnalysisId: r.first_seen_analysis_id ?? '',
    lastSeenAnalysisId: r.last_seen_analysis_id ?? '',
    firstSeenAt: r.first_seen_at ?? '',
    lastSeenAt: r.last_seen_at ?? '',
  }
}

function mapHotspotReviewEvent(r: any): HotspotReviewEvent {
  return {
    actor: r.actor ?? '',
    status: (r.to || r.status || 'to_review') as HotspotStatus,
    rationale: r.rationale ?? '',
    version: r.version ?? (r.previous_version ? r.previous_version + 1 : 1),
    at: r.created_at || r.at || '',
  }
}

function mapProjectIssue(r: any): ProjectIssue {
  return {
    id: r.id ?? '',
    ruleKey: r.rule_key ?? '',
    ruleName: r.rule_name ?? '',
    type: asRuleType(r.type),
    title: r.title ?? '',
    description: r.description ?? '',
    severity: (r.severity ?? 'unknown') as Severity,
    findingKind: r.finding_kind ?? '',
    cwe: r.cwe ?? '',
    language: r.language ?? '',
    file: r.file ?? '',
    location: r.location ?? '',
    status: (r.status ?? 'open') as IssueStatus,
    version: r.version ?? 1,
    isNew: r.is_new ?? false,
    firstSeenAnalysisId: r.first_seen_analysis_id ?? '',
    lastSeenAnalysisId: r.last_seen_analysis_id ?? '',
    firstSeenAt: r.first_seen_at ?? '',
    lastSeenAt: r.last_seen_at ?? '',
  }
}

function mapIssueReviewEvent(r: any): IssueReviewEvent {
  return {
    from: (r.from ?? 'open') as IssueStatus,
    to: (r.to ?? 'open') as IssueStatus,
    actor: r.actor ?? '',
    rationale: r.rationale ?? '',
    version: r.version ?? 1,
    createdAt: r.created_at ?? '',
  }
}

export const api = {
  projectMeasures,
  aup: (): Promise<AupStatus> => req('/aup'),

  // --- Quality gates ---
  listQualityGates: async (): Promise<QualityGate[]> =>
    ((await req('/quality-gates')) ?? []).map(mapQualityGate),

  createQualityGate: async (gate: Omit<QualityGate, 'builtIn'>): Promise<QualityGate> =>
    mapQualityGate(await req('/quality-gates', { method: 'POST', body: JSON.stringify(gate) })),

  updateQualityGate: async (key: string, gate: Omit<QualityGate, 'key' | 'builtIn'>): Promise<QualityGate> =>
    mapQualityGate(await req(`/quality-gates/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify(gate) })),

  deleteQualityGate: async (key: string): Promise<void> => {
    await req(`/quality-gates/${encodeURIComponent(key)}`, { method: 'DELETE' })
  },

  // --- Quality profiles ---
  listQualityProfiles: async (language?: string): Promise<QualityProfile[]> =>
    ((await req(`/quality-profiles${language ? `?language=${encodeURIComponent(language)}` : ''}`)) ?? []).map(mapQualityProfile),

  copyQualityProfile: async (sourceKey: string, key: string, name: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(sourceKey)}/copy`, { method: 'POST', body: JSON.stringify({ key, name }) })),

  activateProfileRule: async (key: string, rule: string, severity = ''): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/activate`, { method: 'POST', body: JSON.stringify({ rule, severity }) })),

  deactivateProfileRule: async (key: string, rule: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/deactivate`, { method: 'POST', body: JSON.stringify({ rule }) })),

  setProfileRuleSeverity: async (key: string, rule: string, severity: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/severity`, { method: 'POST', body: JSON.stringify({ rule, severity }) })),

  deleteQualityProfile: async (key: string): Promise<void> => {
    await req(`/quality-profiles/${encodeURIComponent(key)}`, { method: 'DELETE' })
  },

  assignProjectProfile: async (projectKey: string, language: string, profile: string): Promise<void> => {
    await req(`/projects/${encodeURIComponent(projectKey)}/profiles/${encodeURIComponent(language)}`, { method: 'PUT', body: JSON.stringify({ profile }) })
  },

  // --- Rules ---
  listRules: async (filters: Partial<RuleListFilters> = {}): Promise<RuleSummary[]> => {
    const q = new URLSearchParams()
    if (filters.query?.trim()) q.set('q', filters.query.trim())
    for (const value of filters.languages ?? []) q.append('language', value)
    for (const value of filters.types ?? []) q.append('type', value)
    for (const value of filters.severities ?? []) q.append('severity', value)
    for (const value of filters.tags ?? []) q.append('tag', value)
    for (const value of filters.cwe ?? []) q.append('cwe', value)
    const qs = q.toString()
    const res = await req(`/rules${qs ? `?${qs}` : ''}`)
    return Array.isArray(res) ? res.map(mapRuleSummary) : []
  },

  getRule: async (key: string): Promise<RuleDetail> => {
    return mapRuleDetail(await req(`/rules/${encodeURIComponent(key)}`))
  },

  listProjects: async (): Promise<Project[]> =>
    ((await req('/projects')) ?? []).map(mapProject),

  createProject: async (input: CreateProjectInput): Promise<Project> =>
    mapProject(
      await req('/projects', {
        method: 'POST',
        body: JSON.stringify({
          name: input.name,
          key: input.key,
          source_binding: {
            Kind: input.sourceBinding.kind,
            Value: input.sourceBinding.value,
            Ref: input.sourceBinding.ref,
          },
          gate_id: input.gateId ?? '',
        }),
      }),
    ),

  createProjectFromArchive: async (name: string, key: string, archive: File, gateId = ''): Promise<Project> => {
    const form = new FormData()
    form.append('name', name)
    form.append('key', key)
    form.append('gate_id', gateId)
    form.append('archive', archive)
    const res = await fetch('/api/v1/projects', {
      method: 'POST',
      headers: token ? { authorization: `Bearer ${token}` } : {},
      body: form,
    })
    if (res.status === 401 && onUnauthorized) onUnauthorized()
    if (!res.ok) {
      let message = `HTTP ${res.status}`
      try { message = (await res.json())?.error ?? message } catch { /* non-JSON */ }
      throw new ApiError(res.status, message)
    }
    return mapProject(await res.json())
  },

  getProject: async (key: string): Promise<Project> =>
    mapProject(await req(`/projects/${encodeURIComponent(key)}`)),

  projectOverview: async (key: string): Promise<ProjectOverview> =>
    mapProjectOverviewResponse(await req(`/projects/${encodeURIComponent(key)}/overview`)),

  // --- Hotspots ---
  listProjectHotspots: async (projectKey: string, lens: 'overall' | 'new-code', filter: HotspotListFilter): Promise<HotspotPage> => {
    const q = new URLSearchParams()
    q.set('lens', lens)
    if (filter.status) q.set('status', filter.status)
    if (filter.rule) q.set('rule', filter.rule)
    if (filter.severity) q.set('severity', filter.severity)
    if (filter.search?.trim()) q.set('search', filter.search.trim())
    if (filter.limit) q.set('limit', String(filter.limit))
    if (filter.before_last_seen_at) q.set('before_last_seen_at', filter.before_last_seen_at)
    if (filter.before_id) q.set('before_id', filter.before_id)
    const qs = q.toString()
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots${qs ? `?${qs}` : ''}`)
    return {
      items: (res.items ?? []).map(mapHotspot),
      next: res.next ? { beforeLastSeenAt: res.next.before_last_seen_at ?? '', beforeId: res.next.before_id ?? '' } : null,
      facets: {
        statuses: res.facets?.statuses ?? {},
        ruleKeys: res.facets?.rule_keys ?? {},
        severities: res.facets?.severities ?? {},
      },
      summary: {
        total: res.summary?.total ?? 0,
        reviewed: res.summary?.reviewed ?? 0,
        reviewedPct: res.summary?.reviewed_pct ?? 100,
        grade: (res.summary?.grade ?? 'A') as Grade,
      },
    }
  },

  getProjectHotspot: async (projectKey: string, id: string): Promise<Hotspot> => {
    return mapHotspot(await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}`))
  },

  transitionProjectHotspot: async (projectKey: string, id: string, status: HotspotStatus, rationale: string, expectedVersion: number): Promise<{ hotspot: Hotspot, event: HotspotReviewEvent }> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}/transitions`, {
      method: 'POST',
      body: JSON.stringify({ to: status, rationale, expected_version: expectedVersion }),
    })
    return {
      hotspot: mapHotspot(res.hotspot),
      event: mapHotspotReviewEvent(res.event)
    }
  },

  getProjectHotspotHistory: async (projectKey: string, id: string): Promise<HotspotReviewEvent[]> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}/history`)
    return (res ?? []).map(mapHotspotReviewEvent)
  },

  listProjectIssues: async (projectKey: string, filter: IssueListFilter): Promise<IssuePage> => {
    const q = new URLSearchParams()
    if (filter.lens) q.set('lens', filter.lens)
    if (filter.status) q.set('status', filter.status)
    if (filter.type) q.set('type', filter.type)
    if (filter.severity) q.set('severity', filter.severity)
    if (filter.rule) q.set('rule', filter.rule)
    if (filter.language) q.set('language', filter.language)
    if (filter.path) q.set('path', filter.path)
    if (filter.newCode) q.set('new_code', 'true')
    if (filter.search?.trim()) q.set('search', filter.search.trim())
    if (filter.limit) q.set('limit', String(filter.limit))
    if (filter.before_last_seen_at) q.set('before_last_seen_at', filter.before_last_seen_at)
    if (filter.before_id) q.set('before_id', filter.before_id)
    const qs = q.toString()
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/issues${qs ? `?${qs}` : ''}`)
    return {
      items: (res.items ?? []).map(mapProjectIssue),
      next: res.next ? { beforeLastSeenAt: res.next.before_last_seen_at ?? '', beforeId: res.next.before_id ?? '' } : null,
      facets: {
        types: res.facets?.types ?? {},
        statuses: res.facets?.statuses ?? {},
        severities: res.facets?.severities ?? {},
        ruleKeys: res.facets?.rule_keys ?? {},
        languages: res.facets?.languages ?? {},
      },
      summary: {
        total: res.summary?.total ?? 0,
        open: res.summary?.open ?? 0,
        resolved: res.summary?.resolved ?? 0,
      },
    }
  },

  getProjectIssue: async (projectKey: string, id: string): Promise<ProjectIssue> =>
    mapProjectIssue(await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}`)),

  transitionProjectIssue: async (projectKey: string, id: string, status: IssueStatus, rationale: string, expectedVersion: number): Promise<ProjectIssue> =>
    mapProjectIssue(await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}/transitions`, {
      method: 'POST',
      body: JSON.stringify({ to: status, rationale, expected_version: expectedVersion }),
    })),

  getProjectIssueHistory: async (projectKey: string, id: string): Promise<IssueReviewEvent[]> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}/history`)
    return (res ?? []).map(mapIssueReviewEvent)
  },

  assignProjectGate: async (key: string, gateId: string): Promise<Project> =>
    mapProject(await req(`/projects/${encodeURIComponent(key)}/gate`, { method: 'PUT', body: JSON.stringify({ gate_id: gateId }) })),

  startProjectAnalysis: async (key: string, coverage?: File): Promise<ScanJob> => {
    const path = `/projects/${encodeURIComponent(key)}/analyses`
    if (!coverage) return mapScanJob(await req(path, { method: 'POST' }))
    const form = new FormData()
    form.append('coverage', coverage)
    const res = await fetch(`/api/v1${path}`, { method: 'POST', headers: token ? { authorization: `Bearer ${token}` } : {}, body: form })
    if (res.status === 401 && onUnauthorized) onUnauthorized()
    if (!res.ok) {
      let message = `HTTP ${res.status}`
      try { message = (await res.json())?.error ?? message } catch { /* non-JSON */ }
      throw new ApiError(res.status, message)
    }
    return mapScanJob(await res.json())
  },

  projectAnalyses: async (key: string, cursor: ProjectAnalysisCursor | null = null): Promise<ProjectAnalysisPage> => {
    const query = new URLSearchParams({ limit: '25' })
    if (cursor) {
      query.set('before_created_at', cursor.beforeCreatedAt)
      query.set('before_id', cursor.beforeId)
    }
    const page = await req(`/projects/${encodeURIComponent(key)}/analyses?${query}`)
    return {
      items: (page?.items ?? []).map(mapProjectAnalysis),
      next: page?.next ? { beforeCreatedAt: page.next.before_created_at ?? '', beforeId: page.next.before_id ?? '' } : null,
    }
  },

  projectAnalysis: async (key: string, id: string): Promise<ProjectAnalysis> =>
    mapProjectAnalysis(await req(`/projects/${encodeURIComponent(key)}/analyses/${encodeURIComponent(id)}`)),

  projectAnalysisStatus: async (key: string): Promise<ScanJob | null> => {
    try {
      return mapScanJob(await req(`/projects/${encodeURIComponent(key)}/analysis-status`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  latestProjectAnalysis: async (key: string): Promise<LatestProjectAnalysis | null> => {
    try {
      const latest = await req(`/projects/${encodeURIComponent(key)}/analysis`)
      return { analysis: mapProjectAnalysis(latest.analysis), result: mapScanResult(latest.result) }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  // The latest stored code-quality report (inventory + findings + duplication + A-E ratings). A missing
  // opted-in scan returns available=false; 404 remains unavailable for an absent engagement or older server.
  codeQuality: async (engagementId: string): Promise<CodeQualityView> => {
    let r: any
    try {
      r = await req(`/engagements/${encodeURIComponent(engagementId)}/code-quality`)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return { available: false, reason: 'code quality is not enabled on this server' }
      throw e
    }
    if (!r?.available || !r.report) return { available: false, reason: r?.reason }
    return { available: true, report: mapCodeQualityReport(r.report) }
  },

  // the engagement's architecture threat model (DFD). 404 (not ingested) → null.
  threatModel: async (engagementId: string): Promise<ThreatModel | null> => {
    try {
      return mapThreatModel(await req(`/engagements/${encodeURIComponent(engagementId)}/threat-model`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  // the engagement's AI judgments (risk narrative, critique, …) for the explain surface.
  // Read-only. 404 (the route isn't registered when judgments are disabled) → empty list, so the
  // explain panel simply renders nothing rather than erroring.
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

  acceptAup: (version: string): Promise<unknown> =>
    req('/aup/accept', { method: 'POST', body: JSON.stringify({ version }) }),

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
        }),
      }),
    ),

  findings: async (engagementId: string): Promise<Finding[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/findings`)) ?? []).map(mapFinding),

  updateFindingStatus: async (
    engagementId: string,
    findingId: string,
    status: string,
    version: number,
    note?: string,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, note, version }),
      }),
    ),

  // a DISTINCT verifier applies an adversarial verdict to an exploitation finding –
  // seals the verdict into the evidence chain and (if score >= 75) makes it promotable. The
  // verifier is the authenticated human; the server rejects verifier == proposed_by + machine roles.
  verifyFinding: async (
    engagementId: string,
    findingId: string,
    score: number,
    rationale: string,
    version: number,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/verify`, {
        method: 'POST',
        body: JSON.stringify({ score, rationale, version }),
      }),
    ),

  createFinding: async (
    engagementId: string,
    input: { title: string; description: string; severity: string; cvssVector: string; cwe: string },
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings`, {
        method: 'POST',
        body: JSON.stringify({
          title: input.title,
          description: input.description,
          severity: input.severity,
          cvss_vector: input.cvssVector,
          cwe: input.cwe,
        }),
      }),
    ),

  setFindingAssignee: async (
    engagementId: string,
    findingId: string,
    assignee: string,
    version: number,
  ): Promise<Finding> =>
    mapFinding(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/assignee`, {
        method: 'PUT',
        body: JSON.stringify({ assignee, version }),
      }),
    ),

  findingComments: async (engagementId: string, findingId: string): Promise<FindingComment[]> =>
    (
      (await req(
        `/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/comments`,
      )) ?? []
    ).map(mapComment),

  addFindingComment: async (engagementId: string, findingId: string, body: string): Promise<FindingComment> =>
    mapComment(
      await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      }),
    ),

  cvssScore: async (vector: string): Promise<{ score: number; severity: string }> => {
    const r = await req(`/cvss?vector=${encodeURIComponent(vector)}`)
    return { score: r.score ?? 0, severity: r.severity ?? 'unknown' }
  },

  // writeups returns the built-in finding-writeup library; keys are already
  // camelCase (json tags) so no mapping is needed.
  writeups: async (): Promise<Writeup[]> => (await req('/writeups')) ?? [],

  // ---- Export/import · audit · retest ----

  // importBundle posts a portable bundle (raw JSON from the uploaded file) and
  // returns the newly materialized engagement (its evidence chain re-verified).
  importBundle: async (bundleJSON: string): Promise<Engagement> =>
    mapEngagement(await req('/engagements/import', { method: 'POST', body: bundleJSON })),

  recentAudit: async (limit = 200): Promise<AuditEntry[]> => (await req(`/audit?limit=${limit}`)) ?? [],

  // verifyAudit re-derives the audit hash chain server-side and
  // reports whether the append-only log is intact.
  verifyAudit: async (): Promise<AuditReport> => await req('/audit/verify'),

  // ---- Identity / team ----

  me: async (): Promise<CurrentUser> => req('/me'),

  listUsers: async (): Promise<User[]> => (await req('/users')) ?? [],

  createUser: async (name: string, role: UserRole): Promise<{ user: User; apiKey: string }> =>
    req('/users', { method: 'POST', body: JSON.stringify({ name, role }) }),

  // importSBOM ingests a client CycloneDX SBOM (raw JSON) as the engagement's scan
  // result; applyVEX applies an OpenVEX document (raw JSON) to the findings.
  importedSBOM: async (engagementId: string): Promise<ImportedSBOMMetadata> =>
    mapImportedSBOMMetadata(await req(`/engagements/${encodeURIComponent(engagementId)}/sbom`)),

  importSBOM: async (engagementId: string, cdxJSON: string): Promise<{ target: string; components: number; dependencies: number }> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/sbom`, { method: 'POST', body: cdxJSON }),

  applyVEX: async (engagementId: string, vexJSON: string): Promise<{ statements: number; matched: number; applied: number }> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/vex`, { method: 'POST', body: vexJSON }),

  findingRetests: async (engagementId: string, findingId: string): Promise<Retest[]> =>
    (await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/retests`)) ?? [],

  recordRetest: async (
    engagementId: string,
    findingId: string,
    outcome: RetestOutcome,
    note: string,
    version: number,
  ): Promise<{ retest: Retest; finding: Finding }> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/findings/${encodeURIComponent(findingId)}/retests`, {
      method: 'POST',
      body: JSON.stringify({ outcome, note, version }),
    })
    return { retest: r.retest as Retest, finding: mapFinding(r.finding) }
  },

  // ---- Recon ----

  reconTools: async (): Promise<ReconTool[]> => (await req('/recon/tools')) ?? [],

  startReconRun: async (engagementId: string, tool: string, target: string): Promise<ReconRun> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs`, {
      method: 'POST',
      body: JSON.stringify({ tool, target }),
    }),

  reconRuns: async (engagementId: string): Promise<ReconRun[]> =>
    (await req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs`)) ?? [],

  reconRun: async (engagementId: string, runId: string): Promise<ReconRun> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs/${encodeURIComponent(runId)}`),

  setLiveRecon: async (engagementId: string, enabled: boolean): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(engagementId)}/live-recon`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }),
    ),

  // --- AI agent orchestration ---
  agentReadiness: async (engagementId: string): Promise<AgentReadiness | null> => {
    try {
      return (await req(`/engagements/${encodeURIComponent(engagementId)}/agent/readiness`)) as AgentReadiness
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  startAgentSession: async (engagementId: string, goal: string): Promise<AgentSession> =>
    mapAgentSession(
      await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions`, {
        method: 'POST',
        body: JSON.stringify({ goal }),
      }),
    ),

  agentSessions: async (engagementId: string): Promise<AgentSession[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions`)) ?? []).map(mapAgentSession),

  agentSession: async (
    engagementId: string,
    sessionId: string,
  ): Promise<{ session: AgentSession; transcript: AgentMessage[] }> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}`)
    return { session: mapAgentSession(r.session), transcript: (r.transcript ?? []).map(mapAgentMessage) }
  },

  agentApprovals: async (engagementId: string): Promise<PendingApproval[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/agent/approvals`)) ?? []).map(mapProposedAction),

  // the structured decision log for a session (why-tool / why-target / why-stopped).
  agentDecisions: async (engagementId: string, sessionId: string): Promise<AgentDecision[]> => {
    const r = await req(
      `/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}/decisions`,
    )
    return (r?.decisions ?? []) as AgentDecision[]
  },

  // the session's execution plan DAG (null when the run was reactive / single-step).
  agentPlan: async (engagementId: string, sessionId: string): Promise<AgentPlan | null> => {
    const r = await req(
      `/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}/plan`,
    )
    return (r?.plan ?? null) as AgentPlan | null
  },

  decideAgentApproval: async (engagementId: string, actionId: string, approve: boolean, reason: string): Promise<void> => {
    await req(`/engagements/${encodeURIComponent(engagementId)}/agent/approvals/${encodeURIComponent(actionId)}/decide`, {
      method: 'POST',
      body: JSON.stringify({ approve, reason }),
    })
  },

  startScan: async (engagementId: string, target: string, kind: string, ref = '', mode = 'full', codeQuality = false): Promise<ScanJob> => {
    const r = await req('/sca/scans', {
      method: 'POST',
      body: JSON.stringify({ engagement_id: engagementId, target, kind, ref, mode, code_quality: codeQuality }),
    })
    return mapScanJob(r)
  },

  scanStatus: async (engagementId: string): Promise<ScanJob | null> => {
    try {
      return mapScanJob(await req(`/engagements/${encodeURIComponent(engagementId)}/scan-status`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  evidence: async (
    engagementId: string,
  ): Promise<{ intact: boolean; verified: number; head: string; attestation?: { key_id: string; algorithm: string } } | null> => {
    try {
      const r = await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`)
      return {
        intact: r.intact ?? true,
        verified: r.verified ?? 0,
        head: r.head ?? '',
        attestation: r.attestation ? { key_id: r.attestation.key_id, algorithm: r.attestation.algorithm } : undefined,
      }
    } catch {
      return null
    }
  },

  latestScan: async (engagementId: string): Promise<ScanResult | null> => {
    try {
      const r = await req(`/engagements/${encodeURIComponent(engagementId)}/scan`)
      return mapScanResult(r)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  getEngagement: async (id: string): Promise<Engagement> =>
    mapEngagement(await req(`/engagements/${encodeURIComponent(id)}`)),

  // ---- scope CRUD, authorization window, lifecycle (all audited server-side) ----

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

  // ---- tamper-evident evidence vault ----

  evidenceLedger: async (engagementId: string): Promise<EvidenceLedger> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`)
    return {
      items: (r.items ?? []).map(mapEvidenceItem),
      intact: r.intact ?? true,
      head: r.head ?? '',
      verified: r.verified ?? 0,
      error: r.error ?? '',
    }
  },

  captureEvidence: async (
    engagementId: string,
    kind: string,
    filename: string,
    note: string,
    contentBase64: string,
  ): Promise<EvidenceItem> =>
    mapEvidenceItem(
      await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`, {
        method: 'POST',
        body: JSON.stringify({ kind, filename, note, content_base64: contentBase64 }),
      }),
    ),

  downloadArtifact: async (engagementId: string, sha: string, filename: string): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    await blobDownload(`/api/v1/engagements/${id}/evidence/${encodeURIComponent(sha)}`, filename || `${sha.slice(0, 12)}.bin`)
  },
}
