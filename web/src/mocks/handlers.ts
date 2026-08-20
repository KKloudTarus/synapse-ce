import { http, HttpResponse } from 'msw'

// ============================================================================
// MOCK DATA — Rich data for full UI coverage
// ============================================================================

const NOW = new Date().toISOString()
const HOUR_AGO = new Date(Date.now() - 3600_000).toISOString()
const DAY_AGO = new Date(Date.now() - 86400_000).toISOString()
const WEEK_AGO = new Date(Date.now() - 7 * 86400_000).toISOString()

// --- AI Triage Reviews (Review Queue) ---
const REVIEWS = [
  {
    id: 'rev-001', tenant_id: 't1', engagement_id: 'eng-1', project_id: 'proj-gin',
    finding_id: 'f-101', dedup_key: 'cq:sast:sql-injection:handlers/user.go:42',
    title: 'Potential SQL injection in user query handler', severity: 'high', cwe: 'CWE-89',
    owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized',
    confidence: 87, suspected_fp: true,
    proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google',
    verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia',
    independence_policy: 'model_family', prompt_version: 'v3.2', verified: true,
    verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 82,
    policy_version: '2026.08', policy_reason: 'both_models_agree_refuted',
    shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true,
    evidence_ref: 'ev-001', decided_by: '', decision_rationale: '',
    created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1,
  },
  {
    id: 'rev-002', tenant_id: 't1', engagement_id: 'eng-1', project_id: 'proj-gin',
    finding_id: 'f-102', dedup_key: 'cq:sast:path-traversal:middleware/static.go:88',
    title: 'Path traversal in static file middleware', severity: 'critical', cwe: 'CWE-22',
    owner: '', state: 'pending', verdict: 'refuted', driver: 'constant_or_literal',
    confidence: 91, suspected_fp: true,
    proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google',
    verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia',
    independence_policy: 'model_family', prompt_version: 'v3.2', verified: true,
    verifier_verdict: 'refuted', verifier_driver: 'constant_or_literal', verifier_confidence: 89,
    policy_version: '2026.08', policy_reason: 'both_models_agree_refuted',
    shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true,
    evidence_ref: 'ev-002', decided_by: '', decision_rationale: '',
    created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1,
  },
  {
    id: 'rev-003', tenant_id: 't1', engagement_id: 'eng-1', project_id: 'proj-gin',
    finding_id: 'f-103', dedup_key: 'cq:sast:xss:render/template.go:155',
    title: 'Cross-site scripting in template rendering', severity: 'medium', cwe: 'CWE-79',
    owner: 'alice', state: 'accepted', verdict: 'refuted', driver: 'test_or_example_code',
    confidence: 95, suspected_fp: true,
    proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google',
    verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia',
    independence_policy: 'model_family', prompt_version: 'v3.2', verified: true,
    verifier_verdict: 'refuted', verifier_driver: 'test_or_example_code', verifier_confidence: 93,
    policy_version: '2026.08', policy_reason: 'test_fixture',
    shadow: false, would_gate_exempt: true, gate_exempt: true, review_required: true,
    evidence_ref: 'ev-003', decided_by: 'admin', decision_rationale: 'Confirmed: test fixture code',
    created_at: DAY_AGO, updated_at: HOUR_AGO, decided_at: HOUR_AGO, version: 2,
  },
  {
    id: 'rev-004', tenant_id: 't1', engagement_id: 'eng-1', project_id: 'proj-gin',
    finding_id: 'f-104', dedup_key: 'cq:sast:hardcoded-secret:config/dev.go:12',
    title: 'Hardcoded credential in development config', severity: 'high', cwe: 'CWE-798',
    owner: '', state: 'rejected', verdict: 'refuted', driver: 'constant_or_literal',
    confidence: 78, suspected_fp: true,
    proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google',
    verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia',
    independence_policy: 'model_family', prompt_version: 'v3.2', verified: true,
    verifier_verdict: 'sound', verifier_driver: '', verifier_confidence: 85,
    policy_version: '2026.08', policy_reason: 'verifier_disagrees',
    shadow: false, would_gate_exempt: false, gate_exempt: false, review_required: true,
    evidence_ref: 'ev-004', decided_by: 'admin', decision_rationale: 'Real credential, not a FP',
    created_at: DAY_AGO, updated_at: DAY_AGO, decided_at: DAY_AGO, version: 2,
  },
  {
    id: 'rev-005', tenant_id: 't1', engagement_id: 'eng-1', project_id: 'proj-gin',
    finding_id: 'f-105', dedup_key: 'cq:sast:open-redirect:handlers/auth.go:201',
    title: 'Open redirect in OAuth callback handler', severity: 'medium', cwe: 'CWE-601',
    owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized',
    confidence: 84, suspected_fp: true,
    proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google',
    verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia',
    independence_policy: 'model_family', prompt_version: 'v3.2', verified: true,
    verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 80,
    policy_version: '2026.08', policy_reason: 'both_models_agree_refuted',
    shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true,
    evidence_ref: 'ev-005', decided_by: '', decision_rationale: '',
    created_at: NOW, updated_at: NOW, decided_at: null, version: 1,
  },
]

// --- AI Triage Observability ---
const OBSERVABILITY = {
  generated_at: NOW,
  totals: {
    value: 'all', request_count: 247, average_latency_millis: 1834,
    timeout_count: 3, parse_failure_count: 2, provider_failure_count: 1,
    circuit_open_count: 0, total_tokens: 485920, estimated_cost_micro_usd: 0,
    comparisons: 124, disagreements: 8, gate_exemptions: 12, findings: 258,
  },
  by_model: [
    { value: 'google/gemma-4-26b-a4b-it:free', request_count: 132, average_latency_millis: 1650, timeout_count: 1, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 265000, estimated_cost_micro_usd: 0, comparisons: 0, disagreements: 0, gate_exemptions: 0, findings: 0 },
    { value: 'nvidia/nemotron-3.5-lightning:free', request_count: 115, average_latency_millis: 2045, timeout_count: 2, parse_failure_count: 1, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 220920, estimated_cost_micro_usd: 0, comparisons: 0, disagreements: 0, gate_exemptions: 0, findings: 0 },
  ],
  by_prompt_version: [
    { value: 'v3.2', request_count: 247, average_latency_millis: 1834, timeout_count: 3, parse_failure_count: 2, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 485920, estimated_cost_micro_usd: 0, comparisons: 124, disagreements: 8, gate_exemptions: 12, findings: 258 },
  ],
  by_cwe: [
    { value: 'CWE-89', request_count: 45, average_latency_millis: 1920, timeout_count: 0, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 89000, estimated_cost_micro_usd: 0, comparisons: 23, disagreements: 2, gate_exemptions: 3, findings: 45 },
    { value: 'CWE-79', request_count: 38, average_latency_millis: 1750, timeout_count: 1, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 72000, estimated_cost_micro_usd: 0, comparisons: 19, disagreements: 1, gate_exemptions: 4, findings: 38 },
    { value: 'CWE-22', request_count: 28, average_latency_millis: 1680, timeout_count: 0, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 54000, estimated_cost_micro_usd: 0, comparisons: 14, disagreements: 2, gate_exemptions: 2, findings: 28 },
    { value: 'CWE-798', request_count: 22, average_latency_millis: 1550, timeout_count: 0, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 41000, estimated_cost_micro_usd: 0, comparisons: 11, disagreements: 1, gate_exemptions: 1, findings: 22 },
  ],
  by_project: [
    { value: 'gin-gonic/gin', request_count: 158, average_latency_millis: 1790, timeout_count: 2, parse_failure_count: 1, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 312000, estimated_cost_micro_usd: 0, comparisons: 79, disagreements: 5, gate_exemptions: 8, findings: 158 },
    { value: 'synapse-ce', request_count: 89, average_latency_millis: 1920, timeout_count: 1, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 173920, estimated_cost_micro_usd: 0, comparisons: 45, disagreements: 3, gate_exemptions: 4, findings: 100 },
  ],
  distribution: { schema_version: '1', sample_size: 258, language_basis_points: { go: 6200, javascript: 2800, typescript: 1000 }, cwe_basis_points: { 'CWE-89': 1744, 'CWE-79': 1473, 'CWE-22': 1085, 'CWE-798': 853 }, project_basis_points: { 'gin-gonic/gin': 6124, 'synapse-ce': 3876 } },
  alerts: [
    { project_id: 'proj-gin', project_name: 'gin-gonic/gin', alert: { metric: 'disagreement_rate', observed_basis_points: 632, baseline_basis_points: 400, deviation_basis_points: 232, sample_size: 79, message: 'Disagreement rate elevated above baseline' } },
  ],
}

// --- Remediation SLA ---
const SLA_ITEMS = [
  {
    assessment: { tenant_id: 't1', id: 'sla-001', engagement_id: 'eng-1', finding_id: 'f-201', source_risk_assessment_id: 'ra-1', inputs: { severity: 'critical', cvss_score: 9.8, kev: true, epss: 0.92, public_poc: true, active_exploitation: true, criticality: 'high', exposure: 'external', feasibility: 'patch_available' }, result: { tier: 'emergency', score: 98, breakdown: { severity: 30, exploitability: 25, threat_intel: 20, exposure: 10, criticality: 8, feasibility: 5, overrides: ['kev_active'] }, mitigate_by: new Date(Date.now() + 24 * 3600_000).toISOString(), remediate_by: new Date(Date.now() + 3 * 86400_000).toISOString(), reason: 'Active exploitation + KEV + external exposure', computed_at: HOUR_AGO, config_version: '2026.08' }, input_hash: 'abc123', config_hash: 'cfg456', previous_assessment_id: '', deadline_anchor_at: DAY_AGO, assessed_at: HOUR_AGO, created_at: DAY_AGO },
    lifecycle: { tenant_id: 't1', engagement_id: 'eng-1', finding_id: 'f-201', assessment_id: 'sla-001', status: 'open', version: 1, reason: '', compensating_control: '', accepted_by: '', accepted_at: null, acceptance_expires_at: null, updated_by: 'system', updated_at: HOUR_AGO },
    effective_state: 'open', overdue: false, acceptance_expired: false,
  },
  {
    assessment: { tenant_id: 't1', id: 'sla-002', engagement_id: 'eng-1', finding_id: 'f-202', source_risk_assessment_id: 'ra-2', inputs: { severity: 'high', cvss_score: 7.5, kev: false, epss: 0.45, public_poc: true, active_exploitation: false, criticality: 'medium', exposure: 'external', feasibility: 'patch_available' }, result: { tier: 'critical', score: 72, breakdown: { severity: 25, exploitability: 18, threat_intel: 12, exposure: 8, criticality: 5, feasibility: 4, overrides: [] }, mitigate_by: new Date(Date.now() + 7 * 86400_000).toISOString(), remediate_by: new Date(Date.now() + 14 * 86400_000).toISOString(), reason: 'High severity + public PoC + external', computed_at: HOUR_AGO, config_version: '2026.08' }, input_hash: 'def456', config_hash: 'cfg456', previous_assessment_id: '', deadline_anchor_at: WEEK_AGO, assessed_at: HOUR_AGO, created_at: WEEK_AGO },
    lifecycle: { tenant_id: 't1', engagement_id: 'eng-1', finding_id: 'f-202', assessment_id: 'sla-002', status: 'mitigating', version: 2, reason: 'WAF rule deployed', compensating_control: 'WAF block rule #4521', accepted_by: '', accepted_at: null, acceptance_expires_at: null, updated_by: 'alice', updated_at: DAY_AGO },
    effective_state: 'mitigating', overdue: false, acceptance_expired: false,
  },
  {
    assessment: { tenant_id: 't1', id: 'sla-003', engagement_id: 'eng-1', finding_id: 'f-203', source_risk_assessment_id: 'ra-3', inputs: { severity: 'critical', cvss_score: 9.1, kev: true, epss: 0.88, public_poc: true, active_exploitation: true, criticality: 'high', exposure: 'external', feasibility: 'no_patch' }, result: { tier: 'emergency', score: 95, breakdown: { severity: 28, exploitability: 24, threat_intel: 20, exposure: 10, criticality: 8, feasibility: 5, overrides: ['no_vendor_patch'] }, mitigate_by: new Date(Date.now() - 2 * 86400_000).toISOString(), remediate_by: new Date(Date.now() - 86400_000).toISOString(), reason: 'KEV + no vendor patch', computed_at: WEEK_AGO, config_version: '2026.08' }, input_hash: 'ghi789', config_hash: 'cfg456', previous_assessment_id: '', deadline_anchor_at: new Date(Date.now() - 10 * 86400_000).toISOString(), assessed_at: WEEK_AGO, created_at: new Date(Date.now() - 10 * 86400_000).toISOString() },
    lifecycle: { tenant_id: 't1', engagement_id: 'eng-1', finding_id: 'f-203', assessment_id: 'sla-003', status: 'accepted_risk', version: 3, reason: 'Vendor has no patch, compensating control in place', compensating_control: 'Network segmentation + IDS monitoring', accepted_by: 'ciso', accepted_at: DAY_AGO, acceptance_expires_at: new Date(Date.now() + 30 * 86400_000).toISOString(), updated_by: 'ciso', updated_at: DAY_AGO },
    effective_state: 'accepted_risk', overdue: true, acceptance_expired: false,
  },
]

// --- Fleet Agents ---
const FLEET_AGENTS = [
  { id: 'agent-001', name: 'prod-scanner-01', platform: 'linux/amd64', agent_version: '0.9.4', state: 'healthy', last_seen: NOW, capabilities: ['scan.host', 'scan.container', 'detect.runtime'], current_work: 2 },
  { id: 'agent-002', name: 'staging-scanner', platform: 'linux/arm64', agent_version: '0.9.3', state: 'healthy', last_seen: HOUR_AGO, capabilities: ['scan.host', 'detect.runtime'], current_work: 0 },
  { id: 'agent-003', name: 'dev-workstation', platform: 'darwin/arm64', agent_version: '0.9.4', state: 'stale', last_seen: DAY_AGO, capabilities: ['scan.host'], current_work: 0 },
  { id: 'agent-004', name: 'ci-runner-pool-1', platform: 'linux/amd64', agent_version: '0.9.2', state: 'healthy', last_seen: NOW, capabilities: ['scan.host', 'scan.container', 'scan.iac'], current_work: 1 },
]

const FLEET_COVERAGE = [
  { asset_id: 'asset-web-prod', capability: 'scan.host', verdict: 'covered', detail: 'Last scan 2h ago', last_run: HOUR_AGO, agent_id: 'agent-001' },
  { asset_id: 'asset-web-prod', capability: 'detect.runtime', verdict: 'covered', detail: 'Active monitoring', last_run: NOW, agent_id: 'agent-001' },
  { asset_id: 'asset-api-prod', capability: 'scan.host', verdict: 'covered', detail: 'Last scan 1h ago', last_run: HOUR_AGO, agent_id: 'agent-001' },
  { asset_id: 'asset-api-prod', capability: 'scan.container', verdict: 'stale', detail: 'Last scan 3 days ago', last_run: new Date(Date.now() - 3 * 86400_000).toISOString(), agent_id: 'agent-001' },
  { asset_id: 'asset-db-prod', capability: 'scan.host', verdict: 'agent_missing', detail: 'No agent assigned', last_run: '', agent_id: '' },
  { asset_id: 'asset-staging', capability: 'scan.host', verdict: 'covered', detail: 'Last scan 6h ago', last_run: new Date(Date.now() - 6 * 3600_000).toISOString(), agent_id: 'agent-002' },
]

// --- Dashboard ---
const DASHBOARD = {
  range_days: 30, generated_at: NOW,
  asset_posture: { scanned: 12, unscanned: 3, stale: 2 },
  assets_by_criticality: { high: 4, medium: 6, low: 5 },
  active_findings_by_severity: { critical: 3, high: 18, medium: 45, low: 89, info: 103 },
  findings_over_time: Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.now() - (29 - i) * 86400_000).toISOString().split('T')[0],
    counts: { critical: Math.max(0, 5 - Math.floor(i / 8)), high: 15 + Math.floor(Math.random() * 6), medium: 40 + Math.floor(Math.random() * 10), low: 80 + Math.floor(Math.random() * 15) },
  })),
  findings_without_timestamp: 12, external_findings_included: true,
}

// --- Audit Log ---
const AUDIT_LOG = Array.from({ length: 20 }, (_, i) => ({
  id: `audit-${String(i + 1).padStart(3, '0')}`,
  tenant_id: 't1',
  actor: ['admin', 'alice', 'system', 'bob'][i % 4],
  action: ['engagement.create', 'scan.start', 'finding.triage', 'engagement.transition', 'team.invite', 'scan.complete', 'sla.assess', 'agent.enroll'][i % 8],
  resource_type: ['engagement', 'scan', 'finding', 'engagement', 'team', 'scan', 'sla', 'agent'][i % 8],
  resource_id: `res-${String(i + 1).padStart(3, '0')}`,
  detail: JSON.stringify({ status: 'success' }),
  ip: '10.0.1.' + (100 + i),
  user_agent: 'Synapse-Web/1.0',
  created_at: new Date(Date.now() - i * 3600_000).toISOString(),
}))

// ============================================================================
// HANDLERS — intercept only endpoints that need mock data
// ============================================================================

export const handlers = [
  // --- Auth: AUP check (bypass token requirement for local dev) ---
  http.get('/api/v1/aup', () => {
    return HttpResponse.json({ version: '1.0', accepted: true, accepted_at: NOW })
  }),

  http.post('/api/v1/aup/accept', () => {
    return HttpResponse.json({ ok: true })
  }),

  // --- AI Triage Reviews (Review Queue) ---
  http.get('/api/v1/ai-triage/reviews', () => {
    return HttpResponse.json(REVIEWS)
  }),

  http.get('/api/v1/ai-triage/reviews/:id', ({ params }) => {
    const review = REVIEWS.find(r => r.id === params.id)
    return review ? HttpResponse.json(review) : new HttpResponse(null, { status: 404 })
  }),

  // --- AI Triage Observability ---
  http.get('/api/v1/ai-triage/observability', () => {
    return HttpResponse.json(OBSERVABILITY)
  }),

  // --- Remediation SLA ---
  http.get('/api/v1/engagements/:id/slas', () => {
    return HttpResponse.json({ items: SLA_ITEMS, next: null })
  }),

  http.get('/api/v1/engagements/:id/slas/:fid', () => {
    return HttpResponse.json(SLA_ITEMS[0])
  }),

  // --- Fleet Agents ---
  http.get('/api/v1/fleet/agents', () => {
    return HttpResponse.json(FLEET_AGENTS)
  }),

  http.get('/api/v1/fleet/agents/:id', ({ params }) => {
    const agent = FLEET_AGENTS.find(a => a.id === params.id)
    if (!agent) return new HttpResponse(null, { status: 404 })
    return HttpResponse.json({
      agent,
      recent_work: [
        { id: 'wo-1', capability: 'scan.host', asset_id: 'asset-web-prod', state: 'succeeded', updated_at: HOUR_AGO },
        { id: 'wo-2', capability: 'detect.runtime', asset_id: 'asset-api-prod', state: 'running', updated_at: NOW },
      ],
    })
  }),

  // --- Fleet Coverage ---
  http.get('/api/v1/fleet/coverage', () => {
    return HttpResponse.json(FLEET_COVERAGE)
  }),

  // --- Dashboard ---
  http.get('/api/v1/dashboard/security-operations', () => {
    return HttpResponse.json(DASHBOARD)
  }),

  // --- Audit Log ---
  http.get('/api/v1/audit', () => {
    return HttpResponse.json(AUDIT_LOG)
  }),

  http.get('/api/v1/audit/verify', () => {
    return HttpResponse.json({ integrity: 'verified', entries: 20, gaps: 0, verified_at: NOW })
  }),

  // --- Threat Model (engagement-level) ---
  http.get('/api/v1/engagements/:id/threat-model', () => {
    return HttpResponse.json({
      engagement_id: 'eng-1',
      components: [
        { id: 'comp-1', name: 'Web Frontend', type: 'web_app', trust_zone: 'public' },
        { id: 'comp-2', name: 'API Server', type: 'service', trust_zone: 'dmz' },
        { id: 'comp-3', name: 'Database', type: 'datastore', trust_zone: 'internal' },
        { id: 'comp-4', name: 'Cache (Redis)', type: 'datastore', trust_zone: 'internal' },
        { id: 'comp-5', name: 'Object Storage', type: 'datastore', trust_zone: 'cloud' },
      ],
      flows: [
        { id: 'fl-1', from: 'comp-1', to: 'comp-2', protocol: 'HTTPS', data: 'User requests', authenticated: true },
        { id: 'fl-2', from: 'comp-2', to: 'comp-3', protocol: 'TLS/PostgreSQL', data: 'Queries + mutations', authenticated: true },
        { id: 'fl-3', from: 'comp-2', to: 'comp-4', protocol: 'TLS/Redis', data: 'Session + cache', authenticated: true },
        { id: 'fl-4', from: 'comp-2', to: 'comp-5', protocol: 'HTTPS/S3', data: 'Evidence artifacts', authenticated: true },
      ],
      trust_boundaries: [
        { id: 'tb-1', name: 'Internet boundary', components: ['comp-1'] },
        { id: 'tb-2', name: 'DMZ', components: ['comp-2'] },
        { id: 'tb-3', name: 'Internal network', components: ['comp-3', 'comp-4', 'comp-5'] },
      ],
      assets: [
        { id: 'ta-1', name: 'User credentials', sensitivity: 'high', location: 'comp-3' },
        { id: 'ta-2', name: 'Scan findings', sensitivity: 'medium', location: 'comp-3' },
        { id: 'ta-3', name: 'Evidence files', sensitivity: 'medium', location: 'comp-5' },
      ],
      created_at: WEEK_AGO,
    })
  }),

  // --- Code Quality Project Overview (fix empty rule key issue) ---
  http.get('/api/v1/projects/:key/overview', () => {
    return HttpResponse.json({
      state: 'analyzed',
      analysis: {
        id: 'analysis-001', created_at: HOUR_AGO, source_commit: 'a1b2c3d4e5f6',
        gate: { passed: false, results: [{ metric: 'new_critical_issues', condition: '= 0', actual: '2', passed: false }, { metric: 'coverage', condition: '>= 80%', actual: '72.4%', passed: false }] },
        gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' },
        rating: { security: 'B', reliability: 'A', maintainability: 'C' },
        issues: { total: 47, by_severity: { critical: 2, high: 8, medium: 19, low: 18 } },
        new_code: { counts: { total: 5, critical: 1, high: 2, medium: 2, low: 0 }, period: 'previous_version' },
      },
    })
  }),

  // Fallback: return empty JSON for any unhandled API call (prevents 502 from missing backend)
  http.get('/api/v1/*', () => {
    return HttpResponse.json([])
  }),
  http.post('/api/v1/*', () => {
    return HttpResponse.json({ ok: true })
  }),
  http.patch('/api/v1/*', () => {
    return HttpResponse.json({ ok: true })
  }),
  http.delete('/api/v1/*', () => {
    return HttpResponse.json({ ok: true })
  }),
  http.put('/api/v1/*', () => {
    return HttpResponse.json({ ok: true })
  }),
]
