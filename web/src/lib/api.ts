import type {
  AgentDecision,
  AgentReadiness,
  AgentPlan,
  AgentMessage,
  AgentSession,
  AupStatus,
  CodeQualityView,
  CodeRating,
  Component,
  PendingApproval,
  CreateEngagementInput,
  Engagement,
  EvidenceItem,
  EvidenceLedger,
  Finding,
  FindingComment,
  ImportedSBOMMetadata,
  Judgment,
  ScanJob,
  ScanResult,
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
} from './types'

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
  } catch {
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

// ---- mappers: raw API JSON (mixed casing) → clean types ----

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

export const api = {
  aup: (): Promise<AupStatus> => req('/aup'),

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

  // the engagement's code-quality report (inventory + findings + duplication + A-E ratings). Computed
  // over an in-scope local source directory; an engagement without one returns available=false. 404 (the
  // route is not registered when code quality is disabled) → also available=false.
  codeQuality: async (engagementId: string): Promise<CodeQualityView> => {
    let r: any
    try {
      r = await req(`/engagements/${encodeURIComponent(engagementId)}/code-quality`)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return { available: false, reason: 'code quality is not enabled on this server' }
      throw e
    }
    if (!r?.available || !r.report) return { available: false, reason: r?.reason }
    const rep = r.report
    return {
      available: true,
      report: {
        inventory: (rep.inventory?.languages ?? []).map((l: any) => ({
          language: l.language,
          files: l.files ?? 0,
          codeLines: l.code_lines ?? 0,
          commentLines: l.comment_lines ?? 0,
          blankLines: l.blank_lines ?? 0,
          functions: l.functions ?? 0,
          functionsKnown: !!l.functions_known,
        })),
        findings: (rep.findings ?? []).map(mapFinding),
        duplication: {
          blocks: (rep.duplication?.blocks ?? []).map((b: any) => ({
            tokens: b.tokens ?? 0,
            occurrences: (b.occurrences ?? []).map((o: any) => ({ file: o.file, startLine: o.start_line ?? 0, endLine: o.end_line ?? 0 })),
          })),
          duplicatedLines: rep.duplication?.duplicated_lines ?? 0,
          totalLines: rep.duplication?.total_lines ?? 0,
          files: rep.duplication?.files ?? 0,
        },
        rating: {
          security: (rep.rating?.security ?? 'A') as CodeRating['security'],
          reliability: (rep.rating?.reliability ?? 'A') as CodeRating['reliability'],
          maintainability: (rep.rating?.maintainability ?? 'A') as CodeRating['maintainability'],
          techDebtMinutes: rep.rating?.tech_debt_minutes ?? 0,
          debtRatioPct: rep.rating?.debt_ratio_pct ?? 0,
          linesOfCode: rep.rating?.lines_of_code ?? 0,
        },
      },
    }
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

  startScan: async (engagementId: string, target: string, kind: string, ref = '', mode = 'full'): Promise<ScanJob> => {
    const r = await req('/sca/scans', {
      method: 'POST',
      body: JSON.stringify({ engagement_id: engagementId, target, kind, ref, mode }),
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
