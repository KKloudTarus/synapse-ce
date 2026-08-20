import { http, HttpResponse } from 'msw'

// ============================================================================
// TIMESTAMPS
// ============================================================================
const NOW = new Date().toISOString()
const HOUR_AGO = new Date(Date.now() - 3600_000).toISOString()
const DAY_AGO = new Date(Date.now() - 86400_000).toISOString()
const WEEK_AGO = new Date(Date.now() - 7 * 86400_000).toISOString()
const MONTH_AGO = new Date(Date.now() - 30 * 86400_000).toISOString()

// ============================================================================
// MOCK DATA
// ============================================================================

// --- Engagements ---
const ENGAGEMENTS = [
  { id: 'eng-001', name: 'synapse-ce-audit', status: 'active', client: 'Internal', business_asset_id: 'ba-001', in_scope: [{ kind: 'repo', value: 'https://github.com/KKloudTarus/synapse-ce.git' }], out_of_scope: [], authorized_from: MONTH_AGO, authorized_to: null, timezone: 'Asia/Ho_Chi_Minh', created_at: MONTH_AGO, updated_at: NOW },
  { id: 'eng-002', name: 'gin-framework-scan', status: 'completed', client: 'OSS Review', business_asset_id: '', in_scope: [{ kind: 'repo', value: 'https://github.com/gin-gonic/gin.git' }], out_of_scope: [], authorized_from: WEEK_AGO, authorized_to: null, timezone: 'Asia/Ho_Chi_Minh', created_at: WEEK_AGO, updated_at: DAY_AGO },
  { id: 'eng-003', name: 'api-pentest-q3', status: 'active', client: 'Acme Corp', business_asset_id: 'ba-002', in_scope: [{ kind: 'domain', value: 'api.acme.io' }, { kind: 'url', value: 'https://api.acme.io/v2' }], out_of_scope: [{ kind: 'host', value: '10.0.0.0/8' }], authorized_from: WEEK_AGO, authorized_to: new Date(Date.now() + 30 * 86400_000).toISOString(), timezone: 'Asia/Ho_Chi_Minh', created_at: WEEK_AGO, updated_at: HOUR_AGO },
  { id: 'eng-004', name: 'legacy-infra-review', status: 'draft', client: '', business_asset_id: '', in_scope: [{ kind: 'cidr', value: '172.16.0.0/12' }], out_of_scope: [], authorized_from: null, authorized_to: null, timezone: '', created_at: DAY_AGO, updated_at: DAY_AGO },
]

// --- Findings (for engagement detail) ---
const FINDINGS = Array.from({ length: 45 }, (_, i) => ({
  id: `finding-${String(i + 1).padStart(3, '0')}`,
  engagement_id: 'eng-001',
  title: ['SQL Injection in user input', 'Cross-site scripting (reflected)', 'Insecure deserialization', 'Server-side request forgery', 'Path traversal in file upload', 'Hardcoded API key', 'Missing rate limiting', 'Weak TLS configuration', 'Open redirect', 'Information disclosure via error'][i % 10],
  severity: (['critical', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'low', 'low', 'info'] as const)[i % 10],
  status: (['open', 'open', 'open', 'triaged', 'triaged', 'resolved', 'open', 'open', 'false_positive', 'open'] as const)[i % 10],
  cwe: `CWE-${[89, 79, 502, 918, 22, 798, 770, 326, 601, 209][i % 10]}`,
  kind: i % 3 === 0 ? 'vulnerability' : i % 3 === 1 ? 'license' : 'code_quality',
  component: `pkg:npm/${['express', 'lodash', 'axios', 'jsonwebtoken', 'helmet'][i % 5]}@${['4.18.2', '4.17.21', '1.6.7', '9.0.0', '7.1.0'][i % 5]}`,
  location: `src/${['handlers', 'middleware', 'utils', 'config', 'auth'][i % 5]}/${['user', 'session', 'file', 'api', 'token'][i % 5]}.go:${10 + i * 7}`,
  created_at: new Date(Date.now() - i * 3600_000).toISOString(),
  updated_at: new Date(Date.now() - i * 1800_000).toISOString(),
}))

// --- Scan Result ---
const SCAN_RESULT = {
  engagement_id: 'eng-001',
  scan_mode: 'full',
  components: Array.from({ length: 52 }, (_, i) => ({
    id: `comp-${i}`, name: ['express', 'lodash', 'axios', 'jsonwebtoken', 'helmet', 'cors', 'morgan', 'dotenv', 'pg', 'redis', 'typescript', 'vite'][i % 12], version: `${Math.floor(i / 4)}.${i % 10}.${i % 3}`, type: 'npm', purl: `pkg:npm/${['express', 'lodash', 'axios'][i % 3]}@${i}.0.0`, licenses: [['MIT'], ['Apache-2.0'], ['BSD-3-Clause'], ['ISC']][i % 4],
  })),
  vulnerabilities: Array.from({ length: 18 }, (_, i) => ({
    id: `vuln-${i}`, advisory_id: `GHSA-${String.fromCharCode(97 + i)}${String.fromCharCode(98 + i)}cd-${1234 + i}`, title: ['Prototype pollution', 'ReDoS in validator', 'SSRF via redirect', 'XSS in template', 'Auth bypass', 'Memory leak'][i % 6], severity: (['critical', 'high', 'high', 'medium', 'medium', 'low'] as const)[i % 6], cvss: [9.8, 8.1, 7.5, 6.3, 5.4, 3.2][i % 6], component_id: `comp-${i % 12}`, fixed_version: i % 3 === 0 ? `${i + 1}.0.0` : '',
  })),
  findings: FINDINGS.slice(0, 35),
  licenses: [
    { id: 'lic-1', spdx_id: 'MIT', component_count: 28, verdict: 'allow' },
    { id: 'lic-2', spdx_id: 'Apache-2.0', component_count: 15, verdict: 'allow' },
    { id: 'lic-3', spdx_id: 'GPL-3.0-only', component_count: 3, verdict: 'deny' },
    { id: 'lic-4', spdx_id: 'BSD-3-Clause', component_count: 6, verdict: 'allow' },
  ],
  dependencies: Array.from({ length: 40 }, (_, i) => ({ from: `comp-${i % 12}`, to: `comp-${(i + 3) % 52}` })),
  completeness: { warning: '' },
}

// --- Business Assets ---
const BUSINESS_ASSETS = [
  { id: 'ba-001', key: 'synapse-platform', name: 'Synapse Security Platform', description: 'Core SCA/SAST platform', lifecycle: 'active', criticality: 'high', owner: 'security-engineering', created_at: MONTH_AGO, updated_at: NOW },
  { id: 'ba-002', key: 'acme-api', name: 'Acme Public API', description: 'Customer-facing REST API', lifecycle: 'active', criticality: 'high', owner: 'platform-team', created_at: MONTH_AGO, updated_at: WEEK_AGO },
  { id: 'ba-003', key: 'internal-tools', name: 'Internal Tooling', description: 'Developer productivity tools', lifecycle: 'active', criticality: 'medium', owner: 'devops', created_at: MONTH_AGO, updated_at: DAY_AGO },
]

// --- AI Triage Reviews (Review Queue) ---
const REVIEWS = [
  { id: 'rev-001', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-synapse', finding_id: 'finding-001', dedup_key: 'cq:sast:sql-injection:handlers/user.go:42', title: 'Potential SQL injection in user query handler', severity: 'high', cwe: 'CWE-89', owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized', confidence: 87, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 82, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-001', decided_by: '', decision_rationale: '', created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1 },
  { id: 'rev-002', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-synapse', finding_id: 'finding-005', dedup_key: 'cq:sast:path-traversal:middleware/static.go:88', title: 'Path traversal in static file middleware', severity: 'critical', cwe: 'CWE-22', owner: '', state: 'pending', verdict: 'refuted', driver: 'constant_or_literal', confidence: 91, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'constant_or_literal', verifier_confidence: 89, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-002', decided_by: '', decision_rationale: '', created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1 },
  { id: 'rev-003', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-synapse', finding_id: 'finding-008', dedup_key: 'cq:sast:xss:render/template.go:155', title: 'Cross-site scripting in template rendering', severity: 'medium', cwe: 'CWE-79', owner: 'alice', state: 'accepted', verdict: 'refuted', driver: 'test_or_example_code', confidence: 95, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'test_or_example_code', verifier_confidence: 93, policy_version: '2026.08', policy_reason: 'test_fixture', shadow: false, would_gate_exempt: true, gate_exempt: true, review_required: true, evidence_ref: 'ev-003', decided_by: 'admin', decision_rationale: 'Confirmed: test fixture code', created_at: DAY_AGO, updated_at: HOUR_AGO, decided_at: HOUR_AGO, version: 2 },
  { id: 'rev-004', tenant_id: 't1', engagement_id: 'eng-003', project_id: 'proj-acme', finding_id: 'finding-012', dedup_key: 'cq:sast:hardcoded-secret:config/dev.go:12', title: 'Hardcoded credential in development config', severity: 'high', cwe: 'CWE-798', owner: '', state: 'rejected', verdict: 'refuted', driver: 'constant_or_literal', confidence: 78, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'sound', verifier_driver: '', verifier_confidence: 85, policy_version: '2026.08', policy_reason: 'verifier_disagrees', shadow: false, would_gate_exempt: false, gate_exempt: false, review_required: true, evidence_ref: 'ev-004', decided_by: 'admin', decision_rationale: 'Real credential, not a FP', created_at: DAY_AGO, updated_at: DAY_AGO, decided_at: DAY_AGO, version: 2 },
  { id: 'rev-005', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-synapse', finding_id: 'finding-015', dedup_key: 'cq:sast:open-redirect:handlers/auth.go:201', title: 'Open redirect in OAuth callback handler', severity: 'medium', cwe: 'CWE-601', owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized', confidence: 84, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 80, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-005', decided_by: '', decision_rationale: '', created_at: NOW, updated_at: NOW, decided_at: null, version: 1 },
]

// --- AI Triage Observability ---
const OBSERVABILITY = {
  generated_at: NOW,
  totals: { value: 'all', request_count: 347, average_latency_millis: 1834, timeout_count: 5, parse_failure_count: 3, provider_failure_count: 2, circuit_open_count: 0, total_tokens: 685920, estimated_cost_micro_usd: 0, comparisons: 174, disagreements: 12, gate_exemptions: 18, findings: 458 },
  by_model: [
    { value: 'google/gemma-4-26b-a4b-it:free', request_count: 185, average_latency_millis: 1650, timeout_count: 2, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 365000, estimated_cost_micro_usd: 0, comparisons: 0, disagreements: 0, gate_exemptions: 0, findings: 0 },
    { value: 'nvidia/nemotron-3.5-lightning:free', request_count: 162, average_latency_millis: 2045, timeout_count: 3, parse_failure_count: 2, provider_failure_count: 2, circuit_open_count: 0, total_tokens: 320920, estimated_cost_micro_usd: 0, comparisons: 0, disagreements: 0, gate_exemptions: 0, findings: 0 },
  ],
  by_prompt_version: [{ value: 'v3.2', request_count: 347, average_latency_millis: 1834, timeout_count: 5, parse_failure_count: 3, provider_failure_count: 2, circuit_open_count: 0, total_tokens: 685920, estimated_cost_micro_usd: 0, comparisons: 174, disagreements: 12, gate_exemptions: 18, findings: 458 }],
  by_cwe: [
    { value: 'CWE-89', request_count: 65, average_latency_millis: 1920, timeout_count: 1, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 129000, estimated_cost_micro_usd: 0, comparisons: 33, disagreements: 3, gate_exemptions: 5, findings: 65 },
    { value: 'CWE-79', request_count: 52, average_latency_millis: 1750, timeout_count: 1, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 98000, estimated_cost_micro_usd: 0, comparisons: 26, disagreements: 2, gate_exemptions: 4, findings: 52 },
    { value: 'CWE-22', request_count: 38, average_latency_millis: 1680, timeout_count: 0, parse_failure_count: 1, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 74000, estimated_cost_micro_usd: 0, comparisons: 19, disagreements: 3, gate_exemptions: 3, findings: 38 },
    { value: 'CWE-798', request_count: 28, average_latency_millis: 1550, timeout_count: 0, parse_failure_count: 0, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 52000, estimated_cost_micro_usd: 0, comparisons: 14, disagreements: 2, gate_exemptions: 2, findings: 28 },
    { value: 'CWE-918', request_count: 22, average_latency_millis: 2100, timeout_count: 1, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 44000, estimated_cost_micro_usd: 0, comparisons: 11, disagreements: 1, gate_exemptions: 1, findings: 22 },
  ],
  by_project: [
    { value: 'synapse-ce', request_count: 198, average_latency_millis: 1790, timeout_count: 3, parse_failure_count: 2, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 392000, estimated_cost_micro_usd: 0, comparisons: 99, disagreements: 7, gate_exemptions: 11, findings: 258 },
    { value: 'gin-gonic/gin', request_count: 149, average_latency_millis: 1900, timeout_count: 2, parse_failure_count: 1, provider_failure_count: 1, circuit_open_count: 0, total_tokens: 293920, estimated_cost_micro_usd: 0, comparisons: 75, disagreements: 5, gate_exemptions: 7, findings: 200 },
  ],
  distribution: { schema_version: '1', sample_size: 458, language_basis_points: { go: 5800, javascript: 2400, typescript: 1200, python: 600 }, cwe_basis_points: { 'CWE-89': 1420, 'CWE-79': 1135, 'CWE-22': 830, 'CWE-798': 612, 'CWE-918': 480 }, project_basis_points: { 'synapse-ce': 5633, 'gin-gonic/gin': 4367 } },
  alerts: [{ project_id: 'proj-synapse', project_name: 'synapse-ce', alert: { metric: 'disagreement_rate', observed_basis_points: 707, baseline_basis_points: 400, deviation_basis_points: 307, sample_size: 99, message: 'Disagreement rate elevated above baseline for synapse-ce' } }],
}

// --- Remediation SLA ---
const SLA_ITEMS = [
  { assessment: { tenant_id: 't1', id: 'sla-001', engagement_id: 'eng-001', finding_id: 'finding-001', source_risk_assessment_id: 'ra-1', inputs: { severity: 'critical', cvss_score: 9.8, kev: true, epss: 0.92, public_poc: true, active_exploitation: true, criticality: 'high', exposure: 'external', feasibility: 'patch_available' }, result: { tier: 'emergency', score: 98, breakdown: { severity: 30, exploitability: 25, threat_intel: 20, exposure: 10, criticality: 8, feasibility: 5, overrides: ['kev_active'] }, mitigate_by: new Date(Date.now() + 86400_000).toISOString(), remediate_by: new Date(Date.now() + 3 * 86400_000).toISOString(), reason: 'Active exploitation + KEV + external', computed_at: HOUR_AGO, config_version: '2026.08' }, input_hash: 'abc', config_hash: 'cfg', previous_assessment_id: '', deadline_anchor_at: DAY_AGO, assessed_at: HOUR_AGO, created_at: DAY_AGO }, lifecycle: { tenant_id: 't1', engagement_id: 'eng-001', finding_id: 'finding-001', assessment_id: 'sla-001', status: 'open', version: 1, reason: '', compensating_control: '', accepted_by: '', accepted_at: null, acceptance_expires_at: null, updated_by: 'system', updated_at: HOUR_AGO }, effective_state: 'open', overdue: false, acceptance_expired: false },
  { assessment: { tenant_id: 't1', id: 'sla-002', engagement_id: 'eng-001', finding_id: 'finding-003', source_risk_assessment_id: 'ra-2', inputs: { severity: 'high', cvss_score: 7.5, kev: false, epss: 0.45, public_poc: true, active_exploitation: false, criticality: 'medium', exposure: 'external', feasibility: 'patch_available' }, result: { tier: 'critical', score: 72, breakdown: { severity: 25, exploitability: 18, threat_intel: 12, exposure: 8, criticality: 5, feasibility: 4, overrides: [] }, mitigate_by: new Date(Date.now() + 7 * 86400_000).toISOString(), remediate_by: new Date(Date.now() + 14 * 86400_000).toISOString(), reason: 'High + public PoC + external', computed_at: HOUR_AGO, config_version: '2026.08' }, input_hash: 'def', config_hash: 'cfg', previous_assessment_id: '', deadline_anchor_at: WEEK_AGO, assessed_at: HOUR_AGO, created_at: WEEK_AGO }, lifecycle: { tenant_id: 't1', engagement_id: 'eng-001', finding_id: 'finding-003', assessment_id: 'sla-002', status: 'mitigating', version: 2, reason: 'WAF rule deployed', compensating_control: 'WAF block rule #4521', accepted_by: '', accepted_at: null, acceptance_expires_at: null, updated_by: 'alice', updated_at: DAY_AGO }, effective_state: 'mitigating', overdue: false, acceptance_expired: false },
  { assessment: { tenant_id: 't1', id: 'sla-003', engagement_id: 'eng-001', finding_id: 'finding-005', source_risk_assessment_id: 'ra-3', inputs: { severity: 'critical', cvss_score: 9.1, kev: true, epss: 0.88, public_poc: true, active_exploitation: true, criticality: 'high', exposure: 'external', feasibility: 'no_patch' }, result: { tier: 'emergency', score: 95, breakdown: { severity: 28, exploitability: 24, threat_intel: 20, exposure: 10, criticality: 8, feasibility: 5, overrides: ['no_vendor_patch'] }, mitigate_by: new Date(Date.now() - 2 * 86400_000).toISOString(), remediate_by: new Date(Date.now() - 86400_000).toISOString(), reason: 'KEV + no vendor patch', computed_at: WEEK_AGO, config_version: '2026.08' }, input_hash: 'ghi', config_hash: 'cfg', previous_assessment_id: '', deadline_anchor_at: new Date(Date.now() - 10 * 86400_000).toISOString(), assessed_at: WEEK_AGO, created_at: new Date(Date.now() - 10 * 86400_000).toISOString() }, lifecycle: { tenant_id: 't1', engagement_id: 'eng-001', finding_id: 'finding-005', assessment_id: 'sla-003', status: 'accepted_risk', version: 3, reason: 'No patch available', compensating_control: 'Network segmentation + IDS', accepted_by: 'ciso', accepted_at: DAY_AGO, acceptance_expires_at: new Date(Date.now() + 30 * 86400_000).toISOString(), updated_by: 'ciso', updated_at: DAY_AGO }, effective_state: 'accepted_risk', overdue: true, acceptance_expired: false },
]

// --- Fleet ---
const FLEET_AGENTS = [
  { id: 'agent-001', name: 'prod-scanner-01', platform: 'linux/amd64', agent_version: '0.9.4', state: 'healthy', last_seen: NOW, capabilities: ['scan.host', 'scan.container', 'detect.runtime'], current_work: 2 },
  { id: 'agent-002', name: 'staging-scanner', platform: 'linux/arm64', agent_version: '0.9.3', state: 'healthy', last_seen: HOUR_AGO, capabilities: ['scan.host', 'detect.runtime'], current_work: 0 },
  { id: 'agent-003', name: 'dev-workstation', platform: 'darwin/arm64', agent_version: '0.9.4', state: 'stale', last_seen: DAY_AGO, capabilities: ['scan.host'], current_work: 0 },
  { id: 'agent-004', name: 'ci-runner-pool-1', platform: 'linux/amd64', agent_version: '0.9.2', state: 'healthy', last_seen: NOW, capabilities: ['scan.host', 'scan.container', 'scan.iac'], current_work: 1 },
  { id: 'agent-005', name: 'k8s-node-scanner', platform: 'linux/amd64', agent_version: '0.9.4', state: 'healthy', last_seen: NOW, capabilities: ['scan.host', 'scan.container', 'detect.runtime', 'scan.k8s'], current_work: 3 },
]

const FLEET_COVERAGE = [
  { asset_id: 'ba-001', capability: 'scan.host', verdict: 'covered', detail: 'Last scan 2h ago', last_run: HOUR_AGO, agent_id: 'agent-001' },
  { asset_id: 'ba-001', capability: 'detect.runtime', verdict: 'covered', detail: 'Active monitoring', last_run: NOW, agent_id: 'agent-001' },
  { asset_id: 'ba-001', capability: 'scan.container', verdict: 'covered', detail: 'Last scan 1h ago', last_run: HOUR_AGO, agent_id: 'agent-001' },
  { asset_id: 'ba-002', capability: 'scan.host', verdict: 'stale', detail: 'Last scan 3 days ago', last_run: new Date(Date.now() - 3 * 86400_000).toISOString(), agent_id: 'agent-002' },
  { asset_id: 'ba-002', capability: 'detect.runtime', verdict: 'partial', detail: 'Agent outdated', last_run: DAY_AGO, agent_id: 'agent-002' },
  { asset_id: 'ba-003', capability: 'scan.host', verdict: 'agent_missing', detail: 'No agent assigned', last_run: '', agent_id: '' },
  { asset_id: 'ba-003', capability: 'scan.iac', verdict: 'covered', detail: 'CI pipeline scan', last_run: HOUR_AGO, agent_id: 'agent-004' },
]

// --- Dashboard ---
const DASHBOARD = {
  range_days: 30, generated_at: NOW,
  asset_posture: { scanned: 14, unscanned: 3, stale: 2 },
  assets_by_criticality: { high: 5, medium: 7, low: 5 },
  active_findings_by_severity: { critical: 4, high: 22, medium: 58, low: 112, info: 89 },
  findings_over_time: Array.from({ length: 30 }, (_, i) => ({ date: new Date(Date.now() - (29 - i) * 86400_000).toISOString().split('T')[0], counts: { critical: Math.max(0, 6 - Math.floor(i / 6)), high: 18 + Math.floor(Math.random() * 8), medium: 50 + Math.floor(Math.random() * 15), low: 100 + Math.floor(Math.random() * 20) } })),
  findings_without_timestamp: 8, external_findings_included: true,
}

// --- Code Quality Projects ---
const PROJECTS = [
  { id: 'proj-001', name: 'Synapse CE', key: 'synapse-ce', source_binding: { kind: 'git', value: 'https://github.com/KKloudTarus/synapse-ce.git', ref: 'main' }, default_profile_by_lang: { go: 'default', typescript: 'default' }, gate_id: 'default', audit: { created_at: MONTH_AGO }, latest_analysis: { id: 'an-001', gate: { passed: false, results: [{ metric: 'new_critical_issues', condition: '= 0', actual: '2', passed: false }] }, gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' }, created_at: HOUR_AGO, source_commit: 'a1b2c3d', rating: { security: 'B', reliability: 'A', maintainability: 'C' }, issues: { total: 47, by_severity: { critical: 2, high: 8, medium: 19, low: 18 } }, new_code: { counts: { total: 5, critical: 1, high: 2, medium: 2, low: 0 }, period: 'previous_version' } }, latest_job: { id: 'job-001', status: 'succeeded' } },
  { id: 'proj-002', name: 'Gin Framework', key: 'gin-gonic', source_binding: { kind: 'git', value: 'https://github.com/gin-gonic/gin.git', ref: 'master' }, default_profile_by_lang: { go: 'default' }, gate_id: 'default', audit: { created_at: WEEK_AGO }, latest_analysis: { id: 'an-002', gate: { passed: true, results: [{ metric: 'new_critical_issues', condition: '= 0', actual: '0', passed: true }] }, gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' }, created_at: DAY_AGO, source_commit: 'f4e5d6c', rating: { security: 'A', reliability: 'A', maintainability: 'B' }, issues: { total: 12, by_severity: { critical: 0, high: 2, medium: 5, low: 5 } }, new_code: { counts: { total: 1, critical: 0, high: 0, medium: 1, low: 0 }, period: 'previous_version' } }, latest_job: { id: 'job-002', status: 'succeeded' } },
]

// --- Rules ---
const RULES = Array.from({ length: 25 }, (_, i) => ({
  key: `go:S${1000 + i}`, name: ['SQL injection', 'XSS prevention', 'Path traversal', 'CSRF protection', 'Auth bypass', 'Insecure random', 'Hardcoded secret', 'Weak hash', 'Open redirect', 'SSRF'][i % 10], language: i < 15 ? 'go' : 'typescript', type: ['vulnerability', 'bug', 'code_smell'][i % 3], severity: (['critical', 'high', 'medium', 'low', 'info'] as const)[i % 5], tags: [['owasp-top10', 'injection'], ['owasp-top10', 'xss'], ['path-traversal'], ['csrf'], ['auth']][i % 5], cwe: [`CWE-${[89, 79, 22, 352, 287, 330, 798, 328, 601, 918][i % 10]}`],
}))

// --- Quality Gates ---
const QUALITY_GATES = [
  { key: 'default', name: 'Synapse Way', built_in: true, conditions: [{ metric: 'new_critical_issues', op: '=', value: '0' }, { metric: 'coverage', op: '>=', value: '80' }] },
  { key: 'relaxed', name: 'Relaxed', built_in: false, conditions: [{ metric: 'new_critical_issues', op: '=', value: '0' }] },
]

// --- Quality Profiles ---
const QUALITY_PROFILES = [
  { key: 'go-default', name: 'Default (Go)', language: 'go', is_default: true, rule_count: 142, built_in: true },
  { key: 'ts-default', name: 'Default (TypeScript)', language: 'typescript', is_default: true, rule_count: 98, built_in: true },
  { key: 'go-strict', name: 'Strict (Go)', language: 'go', is_default: false, rule_count: 198, built_in: false },
]

// --- Vulnerability Intelligence ---
const VULN_INTEL = {
  advisories: Array.from({ length: 15 }, (_, i) => ({ id: `GHSA-${String.fromCharCode(97 + i)}bcd-${1000 + i}`, source: 'osv', status: 'active', severity: (['critical', 'high', 'high', 'medium', 'low'] as const)[i % 5], title: ['Remote code execution in serializer', 'Authentication bypass via token reuse', 'Memory corruption in parser', 'Information disclosure in error handler', 'Denial of service via regex'][i % 5], published_at: new Date(Date.now() - i * 86400_000 * 3).toISOString(), updated_at: new Date(Date.now() - i * 86400_000).toISOString(), affected_count: 3 + i, occurrence_count: 1 + (i % 4) })),
  sources: [{ adapter: 'osv', enabled: true, last_sync: HOUR_AGO, state: 'succeeded' }, { adapter: 'nvd', enabled: true, last_sync: DAY_AGO, state: 'succeeded' }, { adapter: 'cisa_kev', enabled: true, last_sync: HOUR_AGO, state: 'succeeded' }],
}

// --- Audit Log ---
const AUDIT_LOG = Array.from({ length: 25 }, (_, i) => ({
  id: `audit-${String(i + 1).padStart(3, '0')}`, tenant_id: 't1', actor: ['admin', 'alice', 'system', 'bob', 'scanner'][i % 5], action: ['engagement.create', 'scan.start', 'finding.triage', 'engagement.transition', 'team.invite', 'scan.complete', 'sla.assess', 'agent.enroll', 'review.decide', 'project.analyze'][i % 10], resource_type: ['engagement', 'scan', 'finding', 'engagement', 'team', 'scan', 'sla', 'agent', 'review', 'project'][i % 10], resource_id: `res-${String(i + 1).padStart(3, '0')}`, detail: JSON.stringify({ status: 'success' }), ip: '10.0.1.' + (100 + i), user_agent: 'Synapse-Web/1.0', created_at: new Date(Date.now() - i * 2700_000).toISOString(),
}))

// --- Team ---
const TEAM_MEMBERS = [
  { id: 'user-001', username: 'admin', display_name: 'Admin User', email: 'admin@synapse.local', role: 'owner', last_active: NOW },
  { id: 'user-002', username: 'alice', display_name: 'Alice Security', email: 'alice@synapse.local', role: 'operator', last_active: HOUR_AGO },
  { id: 'user-003', username: 'bob', display_name: 'Bob DevOps', email: 'bob@synapse.local', role: 'viewer', last_active: DAY_AGO },
]

// ============================================================================
// HANDLERS
// ============================================================================

export const handlers = [
  // --- Auth ---
  http.get('/api/v1/aup', () => HttpResponse.json({ version: '1.0', accepted: true, accepted_at: NOW })),
  http.post('/api/v1/aup/accept', () => HttpResponse.json({ ok: true })),

  // --- Dashboard ---
  http.get('/api/v1/dashboard/security-operations', () => HttpResponse.json(DASHBOARD)),

  // --- Engagements ---
  http.get('/api/v1/engagements', () => HttpResponse.json(ENGAGEMENTS)),
  http.get('/api/v1/engagements/:id', ({ params }) => {
    const eng = ENGAGEMENTS.find(e => e.id === params.id) ?? ENGAGEMENTS[0]
    return HttpResponse.json(eng)
  }),
  http.post('/api/v1/engagements', () => HttpResponse.json(ENGAGEMENTS[0])),
  http.patch('/api/v1/engagements/:id', ({ params }) => {
    const eng = ENGAGEMENTS.find(e => e.id === params.id) ?? ENGAGEMENTS[0]
    return HttpResponse.json(eng)
  }),

  // --- Engagement Findings ---
  http.get('/api/v1/engagements/:id/findings', () => HttpResponse.json({ items: FINDINGS, next: null })),

  // --- Engagement Scan ---
  http.get('/api/v1/engagements/:id/scan-status', () => HttpResponse.json(null)),
  http.get('/api/v1/engagements/:id/scan/latest', () => HttpResponse.json(SCAN_RESULT)),
  http.post('/api/v1/engagements/:id/scan', () => HttpResponse.json({ id: 'job-mock', engagement_id: 'eng-001', target: '', kind: 'git', status: 'running', stage: 'acquiring', progress: 10, error: '', started_at: NOW, finished_at: null, debug_events: [] })),

  // --- Engagement SLA ---
  http.get('/api/v1/engagements/:id/slas', () => HttpResponse.json({ items: SLA_ITEMS, next: null })),
  http.get('/api/v1/engagements/:id/slas/:fid', () => HttpResponse.json(SLA_ITEMS[0])),

  // --- Engagement Threat Model ---
  http.get('/api/v1/engagements/:id/threat-model', () => HttpResponse.json({
    engagement_id: 'eng-001',
    components: [
      { id: 'c1', name: 'Web Frontend', type: 'web_app', trust_zone: 'public' },
      { id: 'c2', name: 'API Gateway', type: 'service', trust_zone: 'dmz' },
      { id: 'c3', name: 'Auth Service', type: 'service', trust_zone: 'internal' },
      { id: 'c4', name: 'PostgreSQL', type: 'datastore', trust_zone: 'internal' },
      { id: 'c5', name: 'Redis Cache', type: 'datastore', trust_zone: 'internal' },
      { id: 'c6', name: 'S3 Evidence', type: 'datastore', trust_zone: 'cloud' },
    ],
    flows: [
      { id: 'f1', from: 'c1', to: 'c2', protocol: 'HTTPS', data: 'User requests', authenticated: true },
      { id: 'f2', from: 'c2', to: 'c3', protocol: 'gRPC/TLS', data: 'Auth tokens', authenticated: true },
      { id: 'f3', from: 'c2', to: 'c4', protocol: 'TLS/PostgreSQL', data: 'Queries', authenticated: true },
      { id: 'f4', from: 'c2', to: 'c5', protocol: 'TLS/Redis', data: 'Sessions', authenticated: true },
      { id: 'f5', from: 'c2', to: 'c6', protocol: 'HTTPS/S3', data: 'Evidence files', authenticated: true },
    ],
    trust_boundaries: [
      { id: 'tb1', name: 'Internet', components: ['c1'] },
      { id: 'tb2', name: 'DMZ', components: ['c2'] },
      { id: 'tb3', name: 'Internal', components: ['c3', 'c4', 'c5', 'c6'] },
    ],
    assets: [
      { id: 'a1', name: 'User credentials', sensitivity: 'high', location: 'c4' },
      { id: 'a2', name: 'API tokens', sensitivity: 'high', location: 'c3' },
      { id: 'a3', name: 'Scan evidence', sensitivity: 'medium', location: 'c6' },
    ],
    created_at: WEEK_AGO,
  })),

  // --- AI Triage Reviews ---
  http.get('/api/v1/ai-triage/reviews', () => HttpResponse.json(REVIEWS)),
  http.get('/api/v1/ai-triage/reviews/:id', ({ params }) => {
    const r = REVIEWS.find(rv => rv.id === params.id) ?? REVIEWS[0]
    return HttpResponse.json(r)
  }),

  // --- AI Triage Observability ---
  http.get('/api/v1/ai-triage/observability', () => HttpResponse.json(OBSERVABILITY)),

  // --- Assets ---
  http.get('/api/v1/assets', () => HttpResponse.json(BUSINESS_ASSETS.map(a => ({ ...a, type: 'host', tags: ['production'], finding_count: 12, last_scanned: HOUR_AGO })))),
  http.get('/api/v1/assets/:id', ({ params }) => {
    const a = BUSINESS_ASSETS.find(x => x.id === params.id) ?? BUSINESS_ASSETS[0]
    return HttpResponse.json({ ...a, type: 'host', tags: ['production'], finding_count: 12, last_scanned: HOUR_AGO, engagements: ENGAGEMENTS.slice(0, 2) })
  }),
  http.get('/api/v1/appsec/assets', () => HttpResponse.json({ items: BUSINESS_ASSETS, total: 3, limit: 50, offset: 0 })),

  // --- Vulnerability Intelligence ---
  http.get('/api/v1/vulnerability/advisories', () => HttpResponse.json({ items: VULN_INTEL.advisories, next: null })),
  http.get('/api/v1/vulnerability/sources', () => HttpResponse.json(VULN_INTEL.sources)),

  // --- Fleet ---
  http.get('/api/v1/fleet/agents', () => HttpResponse.json(FLEET_AGENTS)),
  http.get('/api/v1/fleet/agents/:id', ({ params }) => {
    const agent = FLEET_AGENTS.find(a => a.id === params.id) ?? FLEET_AGENTS[0]
    return HttpResponse.json({ agent, recent_work: [{ id: 'wo-1', capability: 'scan.host', asset_id: 'ba-001', state: 'succeeded', updated_at: HOUR_AGO }, { id: 'wo-2', capability: 'detect.runtime', asset_id: 'ba-001', state: 'running', updated_at: NOW }] })
  }),
  http.get('/api/v1/fleet/coverage', () => HttpResponse.json(FLEET_COVERAGE)),

  // --- Code Quality Projects ---
  http.get('/api/v1/projects', () => HttpResponse.json(PROJECTS)),
  http.get('/api/v1/projects/:key', ({ params }) => {
    const p = PROJECTS.find(pr => pr.key === params.key) ?? PROJECTS[0]
    return HttpResponse.json(p)
  }),
  http.get('/api/v1/projects/:key/overview', () => HttpResponse.json({
    state: 'analyzed', analysis: PROJECTS[0].latest_analysis,
  })),
  http.get('/api/v1/projects/:key/analyses', () => HttpResponse.json({ items: [PROJECTS[0].latest_analysis], next: null })),
  http.get('/api/v1/projects/:key/analysis-status', () => HttpResponse.json(null)),
  http.get('/api/v1/projects/:key/measures', () => HttpResponse.json({
    state: 'analyzed', metrics: { lines: 48520, statements: 12450, functions: 1820, classes: 145, files: 312, complexity: 2840, cognitive_complexity: 1950, coverage: 72.4, duplicated_lines_density: 3.2, duplicated_blocks: 18 },
  })),

  // --- Rules ---
  http.get('/api/v1/rules', () => HttpResponse.json(RULES)),
  http.get('/api/v1/rules/:key', ({ params }) => {
    const r = RULES.find(rl => rl.key === params.key) ?? RULES[0]
    return HttpResponse.json({ ...r, description: 'This rule detects potential security vulnerabilities in source code.', html_description: '<p>Detects potential security issues.</p>', examples: { compliant: '// safe code', non_compliant: '// unsafe code' } })
  }),

  // --- Quality Gates & Profiles ---
  http.get('/api/v1/quality-gates', () => HttpResponse.json(QUALITY_GATES)),
  http.get('/api/v1/quality-profiles', () => HttpResponse.json(QUALITY_PROFILES)),

  // --- Audit ---
  http.get('/api/v1/audit', () => HttpResponse.json(AUDIT_LOG)),
  http.get('/api/v1/audit/verify', () => HttpResponse.json({ integrity: 'verified', entries: 25, gaps: 0, verified_at: NOW })),

  // --- Team ---
  http.get('/api/v1/team', () => HttpResponse.json(TEAM_MEMBERS)),

  // --- Catch-all fallback ---
  http.get('/api/v1/*', () => HttpResponse.json([])),
  http.post('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.patch('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.delete('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.put('/api/v1/*', () => HttpResponse.json({ ok: true })),
]
