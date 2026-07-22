// Clean front-end types. The Go API mixes PascalCase (domain structs) and
// lowercase (DTOs) JSON keys; api.ts normalizes everything to these shapes.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
export type Verdict = 'allow' | 'warn' | 'deny'
export type LicenseCategory =
  | 'permissive'
  | 'weak-copyleft'
  | 'copyleft'
  | 'proprietary'
  | 'unknown'

export interface ScopeTarget {
  kind: string
  value: string
}

export interface Blackout {
  from: string // RFC3339
  to: string // RFC3339
}

// RoE – rules of engagement the execution gate enforces. Empty
// allowedToolClasses means no tool-class restriction (all allowed).
export interface RoE {
  allowedToolClasses: string[]
  blackouts: Blackout[]
}

export interface Engagement {
  id: string
  name: string
  client: string
  status: string
  inScope: ScopeTarget[]
  outOfScope: ScopeTarget[]
  authorizedFrom: string | null
  authorizedTo: string | null
  roe: RoE
  liveReconEnabled: boolean
  createdAt: string | null
}

export interface CreateEngagementInput {
  name: string
  client: string
  inScope: ScopeTarget[]
  outOfScope: ScopeTarget[]
  authorizedFrom?: string // RFC3339
  authorizedTo?: string // RFC3339
  timezone?: string // IANA
}

export interface Finding {
  id: string
  engagementId: string
  title: string
  description: string
  severity: Severity
  cvssVector: string
  cwe: string
  status: string
  dedupKey: string
  kev: boolean
  riskScore: number
  class: string // 'third_party' | 'first_party_historical'
  scope: string
  reachability: string
  impact: string
  priority: number
  assignee: string
  version: number // optimistic-concurrency token
  kind: string // sca | recon | exploitation | manual (governs evidence-gated promotion)
  evidenceScore: number // 0-100; exploitation findings need >= 75 to be reportable
  proposedBy: string // for an agent-proposed exploitation finding, e.g. "agent:<sid>"
  complianceControls: ComplianceControl[] // curated regulatory/standard controls the CWE maps to
}

// ComplianceControl is one curated control a finding's CWE maps to: the framework, the
// control/category id, and its title – e.g. { OWASP-2021, A03:2021, Injection }. Deterministic
// reference data from the server's curated table (a lookup, not a model output).
export interface ComplianceControl {
  framework: string // 'OWASP-2021' | 'PCI-DSS-4.0' | 'ISO-27001-2022'
  id: string // e.g. 'A03:2021' | '6.2.4' | 'A.8.28'
  title: string
}

// --- E30: AI judgments (read-side "explain & advise"; the agent proposes, a human ratifies) ---

export type JudgmentState = 'proposed' | 'confirmed' | 'refuted'

// RiskNarrativeClaim (ungated): explains a finding's computed priority via closed driver
// tokens (never free prose, R8) – e.g. ["kev", "epss>0.5", "reachable"].
export interface RiskNarrativeClaim {
  drivers: string[]
  priority: number // 1..5
}

export type CritiqueVerdict = 'refuted' | 'sound' | 'uncertain'

// CritiqueClaim (gated): an adversarial review of a finding – verdict + a closed driver token.
export interface CritiqueClaim {
  verdict: CritiqueVerdict
  driver: string
  confidence: number // 0..100
}

export type ReachabilityState = 'reachable' | 'not_reachable' | 'unknown'
export type ReachabilityTier = 'tier-0' | 'tier-1' | 'tier-1.5' | 'tier-2'

// ReachabilityClaim (gated): whether the vulnerable symbol is reachable, at what tier (a
// deterministic Tier-2 call-graph proof supersedes an LLM Tier-1.5), and the call-path proof chain.
export interface ReachabilityClaim {
  reachable: ReachabilityState
  tier: ReachabilityTier
  path: string[] // "importPath.Symbol" chain – the call path from an entrypoint to the vulnerable symbol
  confidence: number // 0..100
}

// Judgment is one AI-proposed, human-ratified analysis over a subject (a finding, a data flow…).
// Read-only here; proposed = unverified AI output (score 0), confirmed = a distinct human verified
// (gated) or accepted (ungated) it. The UI labels the state – it never presents a proposal as fact.
export interface Judgment {
  id: string
  engagementId: string
  capability: string // 'risk_narrative' | 'critique' | 'reachability' | 'threat' | …
  subjectKind: string
  subjectId: string
  state: JudgmentState
  evidenceScore: number // 0..100
  proposedBy: string
  version: number
  claim: RiskNarrativeClaim | CritiqueClaim | ReachabilityClaim | Record<string, unknown>
}

// FindingComment is a persisted collaboration note on a finding.
export interface FindingComment {
  id: string
  findingId: string
  author: string
  body: string
  createdAt: string | null
}

export interface FindingQuality {
  rawFindings: number
  actionable: number
  background: number
  production: number
  development: number
  exampleTest: number
  thirdParty: number
  firstPartyHistorical: number
  versionCoveragePct: number
  pathCoveragePct: number
  confidence: string
  byPriority: Record<string, number>
}

export interface ComponentLicense {
  spdxId: string
  name: string
  category: string
}

export interface Component {
  name: string
  version: string
  purl: string
  licenses: ComponentLicense[]
  licenseSource: string
  licenseConfidence: string
  unknownReason: string
  firstParty: boolean
  location: string
}

export interface Detection {
  source: string
  advisoryId: string
  severity: Severity
  fixedVersion: string
}

export interface Vulnerability {
  id: string
  source: string
  severity: Severity
  cvssVector: string
  cvssScore: number
  component: string
  version: string
  fixedVersion: string
  description: string
  kev: boolean
  epss: number
  path: string[]
  direct: boolean
  // Multi-source detection.
  sources: string[]
  confidence: string
  detections: Detection[]
  // Trust classification.
  firstParty: boolean
  unversioned: boolean
}

export interface Completeness {
  lockfiles: string[]
  componentsTotal: number
  componentsResolved: number
  confident: boolean
  warning: string
}

export interface LicenseCoverage {
  total: number
  detected: number
  unknown: number
  pct: number
}

export interface ScanManifest {
  toolVersions: Record<string, string>
  vulnDBSnapshot: string
  grypeDBVersion: string
  correlationVersion: number
  sbomSha256: string
  reproScore: number
  pinnedInputs: string[]
  unpinnedInputs: string[]
}

export interface LicenseFinding {
  license: string
  category: LicenseCategory
  verdict: Verdict
  // Additive industry-standard risk classification (forbidden/restricted/reciprocal/
  // notice/permissive/unencumbered → critical/high/medium/low). Empty on pre-feature scans.
  riskCategory: string
  severity: string
  components: string[]
}

export interface DetectedLanguage {
  name: string
  percent: number
}

export interface Dependency {
  ref: string
  dependsOn: string[]
}

export interface ScanJob {
  id: string
  engagementId: string
  target: string
  kind: string
  status: 'running' | 'succeeded' | 'failed'
  stage: string
  progress: number
  error: string
  startedAt: string | null
  finishedAt: string | null
  debugEvents: ScanDebugEvent[]
}

export interface ScanDebugEvent {
  stage: string
  step: string
  status: 'running' | 'succeeded' | 'failed'
  message: string
  tool: string
  counts: Record<string, number>
  startedAt: string | null
  finishedAt: string | null
  durationMs: number
  error: string
}

export interface ScanResult {
  target: string
  scanMode: ScanMode
  languages: DetectedLanguage[]
  components: Component[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  licenses: LicenseFinding[]
  findings: Finding[]
  toolVersions: Record<string, string>
  vulnDBSnapshot: string
  completeness: Completeness
  licenseCoverage: LicenseCoverage
  manifest: ScanManifest
  findingQuality: FindingQuality
  codeQuality?: CodeQualityReport
  debugEvents: ScanDebugEvent[]
}

export type ScanMode = 'full' | 'vulnerabilities' | 'licenses'

export interface ImportedSBOMMetadata {
  id: string
  engagementId: string
  filename: string
  format: string
  specVersion: string
  targetRef: string
  componentCount: number
  dependencyCount: number
  sha256: string
  createdBy: string
  createdAt: string | null
}

export interface AupStatus {
  version: string
  accepted: boolean
  text: string
}

// EvidenceItem is one link in an engagement's tamper-evident hash chain.
export interface EvidenceItem {
  id: string
  kind: string
  contentBase64: string // sealed payload; Go encodes []byte as base64 in JSON
  hash: string
  previousHash: string
  storageRef: string // blob sha256 for an artifact; '' for a sealed summary
  createdBy: string
  createdAt: string | null
}

export interface EvidenceLedger {
  items: EvidenceItem[]
  intact: boolean
  head: string
  verified: number
  error?: string
}

// User: a real operator identity for attribution.
export type UserRole = 'admin' | 'member'

export interface User {
  id: string
  name: string
  role: UserRole
  disabled: boolean
  createdAt: string | null
}

export interface CurrentUser {
  id: string
  name: string
  role: string
}

// Audit: one append-only, attributable audit record.
export interface AuditEntry {
  actor: string
  action: string
  target: string
  metadata?: Record<string, string>
  at: string | null
  hash?: string
  previous_hash?: string
}

// AuditReport: the audit hash-chain verification status.
// attestation is present when the chain head is origin-signed (ed25519), at parity
// with the evidence chain.
export interface AuditReport {
  intact: boolean
  verified: number
  unchained: number
  head: string
  error?: string
  attestation?: { algorithm: string; key_id: string }
}

// Retest: one re-test verdict on a finding.
export type RetestOutcome = 'remediated' | 'still_vulnerable' | 'not_reproducible'

export interface Retest {
  id: string
  engagementId: string
  findingId: string
  outcome: RetestOutcome
  note?: string
  tester: string
  at: string | null
}

// Recon. A run is one argv-based tool execution against an in-scope target.
export type ReconStatus = 'queued' | 'running' | 'succeeded' | 'failed'

export interface ReconRun {
  id: string
  engagementId: string
  tool: string
  target: string
  status: ReconStatus
  stage: string
  error?: string
  resultCount: number
  containment?: string // confinement posture, e.g. "sandboxed-live · egress-restricted…"
  evidenceId?: string
  startedAt: string | null
  finishedAt: string | null
}

export interface ReconTool {
  name: string
  action: string
  capabilitySensitive: boolean
  acceptedKinds: string[]
}

// Writeup is one reusable finding template from the built-in library.
export interface Writeup {
  id: string
  title: string
  category: string
  cwe: string
  severity: Severity
  cvssVector: string
  description: string
  remediation: string
  references: string[]
}

// --- AI agent orchestration ---

// AgentSession is one autonomous run against an engagement, initiated by a human.
export interface AgentSession {
  id: string
  engagementId: string
  initiatedBy: string
  goal: string
  model: string
  status: string // running | awaiting_approval | succeeded | failed | cancelled
  steps: number
  tokensUsed: number
  createdAt: string | null
  updatedAt: string | null
}

export interface AgentToolCall {
  id: string
  name: string
}

// AgentMessage is one turn in the session transcript.
export interface AgentMessage {
  role: string // system | user | assistant | tool
  content: string
  toolCalls: AgentToolCall[]
  toolCallId: string
}

// AgentDecision is one row of the structured decision log: why a tool/target was chosen,
// the outcome, the evidence-chain hashes it links to, and (for the terminal row) why it stopped.
// agent.AgentDecision HAS json tags → snake_case keys.
export interface AgentDecision {
  seq: number
  kind: string // step | stop
  outcome?: string // executed | denied | read | error (step only)
  action_id?: string
  tool?: string
  action?: string
  target?: string
  risk?: string
  decided_by?: string
  stop_reason?: string // step? no – stop only (goal_reached | max_steps | budget | wall_clock | error | plan_settled)
  reason: { why_tool?: string; why_target?: string; summary?: string }
  refs: { step_hash?: string; admission_hash?: string; intent_hash?: string }
  created_at: string | null
}

// AgentPlanNode is one step of the agent's execution plan DAG. agent.PlanNode HAS json
// tags → snake_case keys.
export interface AgentPlanNode {
  id: string
  tool: string
  target: string
  depends_on?: string[]
  status: string // pending | running | awaiting | done | denied | skipped | failed
  risk: string // read | active | intrusive
  action_id: string
  rationale?: string
  failure?: string
}

// AgentPlan is the LLM-proposed, Go-validated execution DAG for a session.
export interface AgentPlan {
  id: string
  session_id: string
  goal: string
  status: string // draft | active | complete | failed
  revision: number
  nodes: AgentPlanNode[]
}

export interface AgentReadinessItem {
  id: string
  label: string
  ok: boolean
  blocking: boolean
  detail: string
  action?: string
}

export interface AgentWorkflowReadiness {
  id: string
  label: string
  description: string
  ready: boolean
  blockers?: string[]
  suggested_goal: string
}

export interface AgentReadiness {
  overall: 'ready' | 'partial' | 'blocked'
  items: AgentReadinessItem[]
  workflows: AgentWorkflowReadiness[]
  suggested_goals: string[]
  target_kinds: string[]
}

// PendingApproval is a proposed action awaiting a human decision (the diff-before-run).
export interface PendingApproval {
  id: string
  sessionId: string
  tool: string
  action: string
  target: string
  argv: string[]
  egressPreview: string[]
  risk: string // read | active | intrusive
  rationale: string
}

// ---- architecture threat model (DFD) ----

// ThreatComponent is a DFD node (an external entity, a process, or a data store).
export interface ThreatComponent {
  id: string
  name: string
  kind: string // external_entity | process | data_store
  boundary: string // TrustBoundary.id this node sits in ('' = none)
  assets: string[] // ThreatAsset.id refs
}

// ThreatFlow is a directed data flow between two components.
export interface ThreatFlow {
  id: string
  from: string // ThreatComponent.id (source)
  to: string // ThreatComponent.id (destination)
  data: string // human label, e.g. "user auth token"
  dataAsset: string // ThreatAsset.id carried ('' = none)
}

// TrustBoundary is a trust zone; a flow crossing one is attack surface.
export interface TrustBoundary {
  id: string
  name: string
}

// ThreatAsset is a thing of value (classification drives info-disclosure reasoning).
export interface ThreatAsset {
  id: string
  name: string
  classification: string // e.g. "pii", "secret"
}

// ThreatModel is the engagement's architecture DFD.
export interface ThreatModel {
  components: ThreatComponent[]
  flows: ThreatFlow[]
  boundaries: TrustBoundary[]
  assets: ThreatAsset[]
}

// ---- Code quality (Phase 6 dashboard) ----

export type ProjectSourceKind = 'local' | 'git' | 'archive'

export interface ProjectSourceBinding {
  kind: ProjectSourceKind
  value: string
  ref: string
}

export interface Project {
  id: string
  name: string
  key: string
  sourceBinding: ProjectSourceBinding
  defaultProfileByLang: Record<string, string>
  gateId: string
  createdAt: string | null
  latestAnalysis: ProjectAnalysis | null
  latestJob: ScanJob | null
}

export interface CreateProjectInput {
  name: string
  key: string
  sourceBinding: ProjectSourceBinding
  gateId?: string
}

export interface QualityGateCondition {
  metric: string
  op: '<=' | '>=' | '==' | '<' | '>'
  threshold: number
}

export interface QualityGate {
  key: string
  name: string
  conditions: QualityGateCondition[]
  builtIn: boolean
}

export interface QualityProfile {
  key: string
  name: string
  language: string
  parent: string
  activatedRules: Record<string, { severity: string }>
  builtIn: boolean
}

export interface LanguageInventory {
  language: string
  files: number
  codeLines: number
  commentLines: number
  blankLines: number
  functions: number
  functionsKnown: boolean
}

export interface DuplicationOccurrence {
  file: string
  startLine: number
  endLine: number
}

export interface DuplicationBlock {
  tokens: number
  occurrences: DuplicationOccurrence[]
}

export interface DuplicationSummary {
  blocks: DuplicationBlock[]
  duplicatedLines: number
  totalLines: number
  files: number
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'E' | '?'

export interface CodeRating {
  security: Grade
  reliability: Grade
  maintainability: Grade
  techDebtMinutes: number
  debtRatioPct: number
  linesOfCode: number
}

export interface CodeQualityReport {
  inventory: LanguageInventory[]
  findings: Finding[]
  duplication?: DuplicationSummary | null
  rating: CodeRating
}

export interface CodeQualityView {
  available: boolean
  reason?: string
  report?: CodeQualityReport
}

export interface ProjectIssueCounts {
  total: number
  byKind: Record<string, number>
  bySeverity: Record<string, number>
  byStatus: Record<string, number>
}

export interface ProjectGateCondition {
  condition: { metric: string; op: string; threshold: number }
  actual: number
  passed: boolean
}

export interface ProjectGateResult {
  passed: boolean
  results: ProjectGateCondition[]
}

export interface ProjectGateInfo {
  key: string
  name: string
  source: 'managed' | 'repository' | 'default' | ''
}

export interface ProjectAnalysis {
  id: string
  createdAt: string
  sourceRef: string
  sourceCommit: string
  gate: ProjectGateResult
  gateInfo: ProjectGateInfo
  issues: ProjectIssueCounts
  newCode: { previousId: string; counts: ProjectIssueCounts; rating: { security: Grade; reliability: Grade; maintainability: Grade | null } }
  delta: { issues: ProjectIssueCounts; measures: Record<string, number>; ratings: Record<string, number> } | null
  measures: Record<string, number>
  coverage: { coveredLines: number; totalLines: number } | null
  duplication?: DuplicationSummary | null
  rating: CodeRating
}

export interface ProjectAnalysisCursor {
  beforeCreatedAt: string
  beforeId: string
}

export interface ProjectAnalysisPage {
  items: ProjectAnalysis[]
  next: ProjectAnalysisCursor | null
}

export interface LatestProjectAnalysis {
  analysis: ProjectAnalysis
  result: ScanResult
}

// --- Rules API ---

export type RuleType =
  | 'bug'
  | 'vulnerability'
  | 'code_smell'
  | 'security_hotspot'

export type RuleQuality =
  | 'security'
  | 'reliability'
  | 'maintainability'

export type RuleSeverity =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type RuleDetection =
  | 'ast'
  | 'pattern'
  | 'metric'

export interface RuleSummary {
  key: string
  name: string
  language: string
  type: RuleType
  qualities: RuleQuality[]
  defaultSeverity: RuleSeverity
  tags: string[]
  cwe: string[]
  owasp: string[]
  description: string
  remediationEffort: number
  detection: RuleDetection
}

export interface RuleDetail extends RuleSummary {
  rationale: string
  remediation: string
  compliantExample: string
  noncompliantExample: string
}

export interface RuleListFilters {
  query: string
  languages: string[]
  types: RuleType[]
  severities: RuleSeverity[]
  tags: string[]
  cwe: string[]
}

export interface RuleFacets {
  languages: string[]
  types: RuleType[]
  severities: RuleSeverity[]
  tags: string[]
  cwe: string[]
}

// --- Security Hotspots ---

export type HotspotStatus = 'to_review' | 'acknowledged' | 'fixed' | 'safe'

export interface Hotspot {
  id: string
  ruleKey: string
  ruleName: string
  title: string
  description: string
  severity: Severity
  kind: string
  cwe: string
  location: string
  status: HotspotStatus
  version: number
  firstSeenAnalysisId: string
  lastSeenAnalysisId: string
  firstSeenAt: string
  lastSeenAt: string
}

export interface HotspotListFilter {
  lens?: 'overall' | 'new-code'
  status?: HotspotStatus
  rule?: string
  severity?: Severity
  search?: string
  limit?: number
  before_last_seen_at?: string
  before_id?: string
}

export interface HotspotPage {
  items: Hotspot[]
  next: { beforeLastSeenAt: string; beforeId: string } | null
  facets: {
    statuses: Record<string, number>
    ruleKeys: Record<string, number>
    severities: Record<string, number>
  }
  summary: HotspotSummary
}

export function CanTransitionTo(from: HotspotStatus, to: HotspotStatus): boolean {
  if (from === to) return false;
  switch (from) {
    case 'to_review':
      return to === 'acknowledged' || to === 'fixed' || to === 'safe';
    case 'acknowledged':
      return to === 'fixed' || to === 'safe' || to === 'to_review';
    case 'fixed':
      return to === 'to_review';
    case 'safe':
      return to === 'to_review';
  }
  return false;
}

export interface HotspotSummary {
  total: number
  reviewed: number
  reviewedPct: number
  grade: Grade
}

export interface HotspotReviewEvent {
  actor: string
  status: HotspotStatus
  rationale: string
  version: number
  at: string
}

// --- Project Issues (code-quality triage) ---

export type IssueStatus = 'open' | 'accepted' | 'false_positive' | 'wont_fix'

export interface ProjectIssue {
  id: string
  ruleKey: string
  ruleName: string
  type: RuleType
  title: string
  description: string
  severity: Severity
  findingKind: string
  cwe: string
  language: string
  file: string
  location: string
  status: IssueStatus
  version: number
  isNew: boolean
  firstSeenAnalysisId: string
  lastSeenAnalysisId: string
  firstSeenAt: string
  lastSeenAt: string
}

export interface IssueListFilter {
  lens?: 'overall' | 'new-code'
  status?: IssueStatus
  type?: RuleType
  severity?: Severity
  rule?: string
  language?: string
  path?: string
  newCode?: boolean
  search?: string
  limit?: number
  before_last_seen_at?: string
  before_id?: string
}

export interface IssueFacets {
  types: Record<string, number>
  statuses: Record<string, number>
  severities: Record<string, number>
  ruleKeys: Record<string, number>
  languages: Record<string, number>
}

export interface IssueSummary {
  total: number
  open: number
  resolved: number
}

export interface IssuePage {
  items: ProjectIssue[]
  next: { beforeLastSeenAt: string; beforeId: string } | null
  facets: IssueFacets
  summary: IssueSummary
}

export interface IssueReviewEvent {
  from: IssueStatus
  to: IssueStatus
  actor: string
  rationale: string
  version: number
  createdAt: string
}

export const ISSUE_STATUSES: IssueStatus[] = ['open', 'accepted', 'false_positive', 'wont_fix']

// canTransitionIssue mirrors the server lifecycle graph (domain/issue/review.go).
export function canTransitionIssue(from: IssueStatus, to: IssueStatus): boolean {
  if (from === to) return false
  const resolved = (s: IssueStatus) => s === 'accepted' || s === 'false_positive' || s === 'wont_fix'
  if (from === 'open') return resolved(to)
  return to === 'open' || resolved(to)
}

export function issueStatusLabel(s: IssueStatus): string {
  switch (s) {
    case 'open': return 'Open'
    case 'accepted': return 'Accepted'
    case 'false_positive': return 'False positive'
    case 'wont_fix': return "Won't fix"
  }
}
