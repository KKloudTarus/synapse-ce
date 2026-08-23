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
  { ID: 'eng-001', Name: 'synapse-ce-audit', Status: 'active', Client: 'Internal', BusinessAssetID: 'ba-001', Scope: { InScope: [{ Kind: 'repo', Value: 'https://github.com/KKloudTarus/synapse-ce.git' }], OutOfScope: [] }, AuthorizedFrom: MONTH_AGO, AuthorizedTo: null, LiveReconEnabled: false, RoE: { allowed_tool_classes: [], blackouts: [] }, Audit: { CreatedAt: MONTH_AGO } },
  { ID: 'eng-002', Name: 'gin-framework-scan', Status: 'completed', Client: 'OSS Review', BusinessAssetID: '', Scope: { InScope: [{ Kind: 'repo', Value: 'https://github.com/gin-gonic/gin.git' }], OutOfScope: [] }, AuthorizedFrom: WEEK_AGO, AuthorizedTo: null, LiveReconEnabled: false, RoE: { allowed_tool_classes: [], blackouts: [] }, Audit: { CreatedAt: WEEK_AGO } },
  { ID: 'eng-003', Name: 'api-pentest-q3', Status: 'active', Client: 'Acme Corp', BusinessAssetID: 'ba-002', Scope: { InScope: [{ Kind: 'domain', Value: 'api.acme.io' }, { Kind: 'url', Value: 'https://api.acme.io/v2' }], OutOfScope: [{ Kind: 'host', Value: '10.0.0.0/8' }] }, AuthorizedFrom: WEEK_AGO, AuthorizedTo: new Date(Date.now() + 30 * 86400_000).toISOString(), LiveReconEnabled: true, RoE: { allowed_tool_classes: ['scanner', 'fuzzer'], blackouts: [] }, Audit: { CreatedAt: WEEK_AGO } },
  { ID: 'eng-004', Name: 'payment-gateway-review', Status: 'active', Client: 'Payments', BusinessAssetID: 'ba-004', Scope: { InScope: [{ Kind: 'repo', Value: 'https://github.com/internal/payment-service.git' }], OutOfScope: [] }, AuthorizedFrom: DAY_AGO, AuthorizedTo: null, LiveReconEnabled: false, RoE: { allowed_tool_classes: [], blackouts: [] }, Audit: { CreatedAt: DAY_AGO } },
  { ID: 'eng-005', Name: 'auth-hardening', Status: 'draft', Client: '', BusinessAssetID: 'ba-005', Scope: { InScope: [{ Kind: 'repo', Value: 'https://github.com/internal/auth-service.git' }], OutOfScope: [] }, AuthorizedFrom: null, AuthorizedTo: null, LiveReconEnabled: false, RoE: { allowed_tool_classes: [], blackouts: [] }, Audit: { CreatedAt: DAY_AGO } },
  { ID: 'eng-006', Name: 'mobile-app-scan', Status: 'draft', Client: '', BusinessAssetID: '', Scope: { InScope: [{ Kind: 'repo', Value: 'https://github.com/internal/mobile-app.git' }], OutOfScope: [] }, AuthorizedFrom: null, AuthorizedTo: null, LiveReconEnabled: false, RoE: { allowed_tool_classes: [], blackouts: [] }, Audit: { CreatedAt: NOW } },
]

// --- Findings (for engagement detail) -- PascalCase matching Go API output ---
const FINDINGS = Array.from({ length: 45 }, (_, i) => ({
  ID: `finding-${String(i + 1).padStart(3, '0')}`,
  EngagementID: 'eng-001',
  Title: ['SQL Injection in user input', 'Cross-site scripting (reflected)', 'Insecure deserialization', 'Server-side request forgery', 'Path traversal in file upload', 'Hardcoded API key', 'Missing rate limiting', 'Weak TLS configuration', 'Open redirect', 'Information disclosure via error'][i % 10],
  Description: ['User input concatenated in SQL query without parameterization', 'Reflected user input in HTML response without encoding', 'Untrusted data deserialized via Java ObjectInputStream', 'Server follows user-supplied URLs to internal services', 'File path constructed from user input without sanitization', 'AWS secret key hardcoded in source', 'No rate limit on authentication endpoint', 'TLS 1.0 still enabled on production endpoint', 'Redirect URL not validated against allowlist', 'Stack trace exposed in error response'][i % 10],
  Severity: (['critical', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'low', 'low', 'info'])[i % 10],
  CVSSVector: ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'][i % 10],
  CWE: `CWE-${[89, 79, 502, 918, 22, 798, 770, 326, 601, 209][i % 10]}`,
  Status: (['open', 'open', 'open', 'triaged', 'triaged', 'resolved', 'open', 'open', 'false_positive', 'open'])[i % 10],
  DedupKey: `sca:vuln:${['express', 'lodash', 'axios', 'jsonwebtoken', 'helmet'][i % 5]}:CVE-2026-${1000 + i}`,
  KEV: i % 10 === 0,
  RiskScore: [98, 82, 75, 62, 55, 48, 35, 28, 20, 10][i % 10],
  Class: i % 3 === 0 ? 'third_party' : i % 3 === 1 ? 'first_party' : 'configuration',
  Scope: (['production', 'production', 'production', 'staging', 'development', 'production', 'production', 'staging', 'development', 'production'])[i % 10],
  Reachability: (['reachable', 'reachable', 'unknown', 'reachable', 'unreachable', 'unknown', 'reachable', 'unknown', 'unreachable', 'unknown'])[i % 10],
  Impact: '',
  Priority: [1, 1, 2, 2, 3, 3, 3, 4, 4, 5][i % 10],
  Assignee: i % 5 === 0 ? 'alice' : i % 5 === 1 ? 'bob' : '',
  Version: 1,
  Kind: i % 3 === 0 ? 'vulnerability' : i % 3 === 1 ? 'license' : 'code_quality',
  EvidenceScore: [95, 88, 72, 65, 50, 42, 30, 25, 15, 5][i % 10],
  ProposedBy: '',
  compliance_controls: i % 7 === 0 ? [{ Framework: 'OWASP', ID: 'A03:2021', Title: 'Injection' }] : [],
}))

// --- Scan Result (PascalCase for components, snake_case for other fields) ---
const SCAN_RESULT = {
  target: 'https://github.com/KKloudTarus/synapse-ce.git',
  scan_mode: 'full',
  languages: [
    { Name: 'Go', Percent: 58 },
    { Name: 'TypeScript', Percent: 24 },
    { Name: 'JavaScript', Percent: 12 },
    { Name: 'Shell', Percent: 4 },
    { Name: 'Dockerfile', Percent: 2 },
  ],
  sbom: {
    Components: Array.from({ length: 52 }, (_, i) => ({
      Name: ['express', 'lodash', 'axios', 'jsonwebtoken', 'helmet', 'cors', 'morgan', 'dotenv', 'pg', 'redis', 'typescript', 'vite', 'react', 'react-dom', 'tailwindcss', 'vitest', 'msw', 'zod', 'date-fns', 'chart.js'][i % 20],
      Version: `${Math.floor(i / 4)}.${i % 10}.${i % 3}`,
      PURL: `pkg:npm/${['express', 'lodash', 'axios', 'react', 'vite'][i % 5]}@${Math.floor(i / 4)}.${i % 10}.${i % 3}`,
      Licenses: [
        [{ SPDXID: 'MIT', Name: 'MIT License', Category: 'permissive' }],
        [{ SPDXID: 'Apache-2.0', Name: 'Apache License 2.0', Category: 'permissive' }],
        [{ SPDXID: 'BSD-3-Clause', Name: 'BSD 3-Clause', Category: 'permissive' }],
        [{ SPDXID: 'ISC', Name: 'ISC License', Category: 'permissive' }],
        [{ SPDXID: 'GPL-3.0-only', Name: 'GNU GPL v3', Category: 'copyleft' }],
      ][i % 5],
      LicenseSource: ['declared', 'concluded', 'declared', 'declared', 'concluded'][i % 5],
      LicenseConfidence: 'high',
      UnknownReason: '',
      FirstParty: i % 8 === 0,
      Location: `node_modules/${['express', 'lodash', 'axios', 'react', 'vite'][i % 5]}/package.json`,
    })),
    Dependencies: Array.from({ length: 40 }, (_, i) => ({
      Ref: `pkg:npm/${['express', 'lodash', 'axios'][i % 3]}@${i}.0.0`,
      DependsOn: [`pkg:npm/${['lodash', 'axios', 'express'][(i + 1) % 3]}@${i + 1}.0.0`],
    })),
  },
  vulnerabilities: Array.from({ length: 18 }, (_, i) => ({
    ID: `CVE-2026-${1000 + i}`,
    Source: ['osv', 'nvd', 'ghsa'][i % 3],
    Severity: (['critical', 'high', 'high', 'medium', 'medium', 'low'] )[i % 6],
    CVSSVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    CVSSScore: [9.8, 8.1, 7.5, 6.3, 5.4, 3.2][i % 6],
    Component: ['express', 'lodash', 'axios', 'jsonwebtoken', 'helmet', 'cors'][i % 6],
    Version: ['4.18.2', '4.17.21', '1.6.7', '9.0.0', '7.1.0', '2.8.5'][i % 6],
    FixedVersion: i % 3 === 0 ? `${Math.floor(i / 3) + 5}.0.0` : '',
    Description: ['Prototype pollution in object merge', 'ReDoS in email validator regex', 'SSRF via redirect following', 'XSS in template literal injection', 'Authentication bypass via JWT none algo', 'Memory leak in connection pool'][i % 6],
    KEV: i % 6 === 0,
    EPSS: [0.92, 0.67, 0.45, 0.23, 0.12, 0.05][i % 6],
    Path: i % 3 === 0 ? ['express', 'body-parser', 'qs'] : [],
    Direct: i % 2 === 0,
    Sources: [['osv', 'nvd'], ['nvd'], ['ghsa', 'osv']][i % 3],
    Confidence: ['high', 'high', 'medium', 'medium', 'low', 'high'][i % 6],
    Detections: [{ Source: 'osv', AdvisoryID: `GHSA-${String.fromCharCode(97 + i)}bcd-${1234 + i}`, Severity: (['critical', 'high', 'high', 'medium', 'medium', 'low'] )[i % 6], FixedVersion: i % 3 === 0 ? `${Math.floor(i / 3) + 5}.0.0` : '' }],
    FirstParty: false,
    Unversioned: false,
  })),
  licenses: [
    { license: 'MIT', category: 'permissive', verdict: 'allow', components: Array.from({ length: 28 }, (_, i) => `comp-${i}`) },
    { license: 'Apache-2.0', category: 'permissive', verdict: 'allow', components: Array.from({ length: 15 }, (_, i) => `comp-${i + 28}`) },
    { license: 'GPL-3.0-only', category: 'copyleft', verdict: 'deny', components: ['comp-4', 'comp-9', 'comp-14'] },
    { license: 'BSD-3-Clause', category: 'permissive', verdict: 'allow', components: ['comp-2', 'comp-7', 'comp-12', 'comp-17', 'comp-22', 'comp-27'] },
    { license: 'ISC', category: 'permissive', verdict: 'allow', components: ['comp-3', 'comp-8', 'comp-13'] },
    { license: 'UNKNOWN', category: 'unknown', verdict: 'warn', components: ['comp-50', 'comp-51'] },
  ],
  findings: FINDINGS.slice(0, 35),
  slas: [],
  ai_triage: [
    { finding_id: 'finding-001', dedup_key: 'sca:vuln:express:CVE-2026-1000', verdict: 'refuted', driver: 'input_sanitized', confidence: 87, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, verified: true, verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 82 },
    { finding_id: 'finding-005', dedup_key: 'sca:vuln:helmet:CVE-2026-1004', verdict: 'sound', driver: '', confidence: 92, suspected_fp: false, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', policy_version: '2026.08', policy_reason: 'both_models_agree_sound', shadow: false, would_gate_exempt: false, gate_exempt: false, review_required: false, verified: true, verifier_verdict: 'sound', verifier_driver: '', verifier_confidence: 90 },
  ],
  tool_versions: { syft: '1.18.1', grype: '0.87.0', 'synapse-callgraph': '0.4.2' },
  vuln_db_snapshot: '2026-08-22T00:00:00Z',
  completeness: { lockfiles: ['package-lock.json', 'go.sum'], components_total: 52, components_resolved: 52, confident: true, warning: '' },
  license_coverage: { total: 52, detected: 50, unknown: 2, pct: 96.2 },
  finding_quality: { raw_findings: 45, actionable: 28, background: 5, production: 35, development: 10, example_test: 3, third_party: 30, first_party_historical: 2, version_coverage_pct: 94, path_coverage_pct: 88, confidence: 'high', by_priority: { '1': 5, '2': 12, '3': 18, '4': 7, '5': 3 } },
  manifest: { tool_versions: { syft: '1.18.1', grype: '0.87.0' }, vuln_db_snapshot: '2026-08-22T00:00:00Z', grype_db_version: '5', correlation_version: 2, sbom_sha256: 'abc123def456', repro_score: 100, pinned_inputs: ['syft@1.18.1', 'grype@0.87.0'], unpinned_inputs: [] },
  code_quality: {
    inventory: { languages: [{ language: 'Go', files: 245, code_lines: 38200, comment_lines: 4800, blank_lines: 6100, functions: 1420, functions_known: true }, { language: 'TypeScript', files: 156, code_lines: 22400, comment_lines: 1200, blank_lines: 3400, functions: 890, functions_known: true }] },
    findings: FINDINGS.slice(30, 45),
    duplication: { blocks: [{ tokens: 120, occurrences: [{ file: 'src/handlers/user.go', start_line: 45, end_line: 58 }, { file: 'src/handlers/admin.go', start_line: 22, end_line: 35 }] }], duplicated_lines: 340, total_lines: 60600, files: 8 },
    rating: { security: 'B', reliability: 'A', maintainability: 'B', tech_debt_minutes: 2840, debt_ratio_pct: 3.2, lines_of_code: 60600 },
  },
  debug_events: [
    { stage: 'acquire', step: 'git_clone', status: 'done', message: 'Cloned synapse-ce.git', tool: 'git', counts: {}, started_at: new Date(Date.now() - 300000).toISOString(), finished_at: new Date(Date.now() - 280000).toISOString(), duration_ms: 20000, error: '' },
    { stage: 'sbom', step: 'syft_scan', status: 'done', message: '52 components identified', tool: 'syft', counts: { components: 52 }, started_at: new Date(Date.now() - 280000).toISOString(), finished_at: new Date(Date.now() - 250000).toISOString(), duration_ms: 30000, error: '' },
    { stage: 'vuln', step: 'grype_match', status: 'done', message: '18 vulnerabilities matched', tool: 'grype', counts: { vulnerabilities: 18 }, started_at: new Date(Date.now() - 250000).toISOString(), finished_at: new Date(Date.now() - 220000).toISOString(), duration_ms: 30000, error: '' },
    { stage: 'license', step: 'classify', status: 'done', message: '50/52 licenses resolved', tool: 'synapse', counts: { resolved: 50, unknown: 2 }, started_at: new Date(Date.now() - 220000).toISOString(), finished_at: new Date(Date.now() - 200000).toISOString(), duration_ms: 20000, error: '' },
    { stage: 'quality', step: 'sast_scan', status: 'done', message: '15 code quality findings', tool: 'synapse-ast', counts: { findings: 15 }, started_at: new Date(Date.now() - 200000).toISOString(), finished_at: new Date(Date.now() - 150000).toISOString(), duration_ms: 50000, error: '' },
    { stage: 'correlate', step: 'dedup', status: 'done', message: 'Deduplicated findings', tool: 'synapse', counts: { raw: 63, deduped: 45 }, started_at: new Date(Date.now() - 150000).toISOString(), finished_at: new Date(Date.now() - 140000).toISOString(), duration_ms: 10000, error: '' },
  ],
}

// --- Business Assets ---
const BUSINESS_ASSETS = [
  { ID: 'ba-001', Key: 'synapse-platform', Name: 'Synapse Security Platform', Description: 'Core SCA/SAST platform', Lifecycle: 'active', Criticality: 'high', Owner: 'security-engineering', Type: 'application', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: NOW }, posture: 'critical', posture_explanation: '' },
  { ID: 'ba-002', Key: 'acme-api', Name: 'Acme Public API', Description: 'Customer-facing REST API', Lifecycle: 'active', Criticality: 'high', Owner: 'platform-team', Type: 'application', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: WEEK_AGO }, posture: 'high_risk', posture_explanation: '' },
  { ID: 'ba-003', Key: 'internal-tools', Name: 'Internal Tooling', Description: 'Developer productivity tools', Lifecycle: 'active', Criticality: 'medium', Owner: 'devops', Type: 'system', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: DAY_AGO }, posture: 'attention', posture_explanation: '' },
  { ID: 'ba-004', Key: 'payment-service', Name: 'Payment Gateway', Description: 'Stripe integration microservice', Lifecycle: 'active', Criticality: 'critical', Owner: 'payments-team', Type: 'business_service', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: DAY_AGO }, posture: 'high_risk', posture_explanation: '' },
  { ID: 'ba-005', Key: 'auth-service', Name: 'Auth & Identity Service', Description: 'OAuth2/OIDC provider', Lifecycle: 'active', Criticality: 'critical', Owner: 'security-engineering', Type: 'application', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: WEEK_AGO }, posture: 'attention', posture_explanation: '' },
  { ID: 'ba-006', Key: 'data-pipeline', Name: 'Data Pipeline', Description: 'ETL and analytics pipeline', Lifecycle: 'active', Criticality: 'medium', Owner: 'data-team', Type: 'system', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: DAY_AGO }, posture: 'good', posture_explanation: '' },
  { ID: 'ba-007', Key: 'mobile-app', Name: 'Mobile App (iOS/Android)', Description: 'Customer mobile application', Lifecycle: 'active', Criticality: 'high', Owner: 'mobile-team', Type: 'product', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: WEEK_AGO }, posture: 'unknown', posture_explanation: '' },
  { ID: 'ba-008', Key: 'cdn-edge', Name: 'CDN Edge Layer', Description: 'CloudFront + Lambda@Edge', Lifecycle: 'active', Criticality: 'medium', Owner: 'platform-team', Type: 'system', Metadata: {}, Version: 1, Audit: { CreatedAt: MONTH_AGO, UpdatedAt: NOW }, posture: 'good', posture_explanation: '' },
]

// --- AI Triage Reviews (Review Queue) ---
const REVIEWS = [
  { id: 'rev-001', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-001', finding_id: 'finding-001', dedup_key: 'cq:sast:sql-injection:handlers/user.go:42', title: 'Potential SQL injection in user query handler', severity: 'high', cwe: 'CWE-89', owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized', confidence: 87, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 82, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-001', decided_by: '', decision_rationale: '', created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1 },
  { id: 'rev-002', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-001', finding_id: 'finding-005', dedup_key: 'cq:sast:path-traversal:middleware/static.go:88', title: 'Path traversal in static file middleware', severity: 'critical', cwe: 'CWE-22', owner: '', state: 'pending', verdict: 'refuted', driver: 'constant_or_literal', confidence: 91, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'constant_or_literal', verifier_confidence: 89, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-002', decided_by: '', decision_rationale: '', created_at: HOUR_AGO, updated_at: HOUR_AGO, decided_at: null, version: 1 },
  { id: 'rev-003', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-001', finding_id: 'finding-008', dedup_key: 'cq:sast:xss:render/template.go:155', title: 'Cross-site scripting in template rendering', severity: 'medium', cwe: 'CWE-79', owner: 'alice', state: 'accepted', verdict: 'refuted', driver: 'test_or_example_code', confidence: 95, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'test_or_example_code', verifier_confidence: 93, policy_version: '2026.08', policy_reason: 'test_fixture', shadow: false, would_gate_exempt: true, gate_exempt: true, review_required: true, evidence_ref: 'ev-003', decided_by: 'admin', decision_rationale: 'Confirmed: test fixture code', created_at: DAY_AGO, updated_at: HOUR_AGO, decided_at: HOUR_AGO, version: 2 },
  { id: 'rev-004', tenant_id: 't1', engagement_id: 'eng-003', project_id: 'proj-002', finding_id: 'finding-012', dedup_key: 'cq:sast:hardcoded-secret:config/dev.go:12', title: 'Hardcoded credential in development config', severity: 'high', cwe: 'CWE-798', owner: '', state: 'rejected', verdict: 'refuted', driver: 'constant_or_literal', confidence: 78, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'sound', verifier_driver: '', verifier_confidence: 85, policy_version: '2026.08', policy_reason: 'verifier_disagrees', shadow: false, would_gate_exempt: false, gate_exempt: false, review_required: true, evidence_ref: 'ev-004', decided_by: 'admin', decision_rationale: 'Real credential, not a FP', created_at: DAY_AGO, updated_at: DAY_AGO, decided_at: DAY_AGO, version: 2 },
  { id: 'rev-005', tenant_id: 't1', engagement_id: 'eng-001', project_id: 'proj-001', finding_id: 'finding-015', dedup_key: 'cq:sast:open-redirect:handlers/auth.go:201', title: 'Open redirect in OAuth callback handler', severity: 'medium', cwe: 'CWE-601', owner: '', state: 'pending', verdict: 'refuted', driver: 'input_sanitized', confidence: 84, suspected_fp: true, proposer_model: 'google/gemma-4-26b-a4b-it:free', proposer_provider: 'openrouter', proposer_model_family: 'google', verifier_model: 'nvidia/nemotron-3.5-lightning:free', verifier_provider: 'openrouter', verifier_model_family: 'nvidia', independence_policy: 'model_family', prompt_version: 'v3.2', verified: true, verifier_verdict: 'refuted', verifier_driver: 'input_sanitized', verifier_confidence: 80, policy_version: '2026.08', policy_reason: 'both_models_agree_refuted', shadow: false, would_gate_exempt: true, gate_exempt: false, review_required: true, evidence_ref: 'ev-005', decided_by: '', decision_rationale: '', created_at: NOW, updated_at: NOW, decided_at: null, version: 1 },
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
  asset_posture: { critical: 2, high_risk: 5, attention: 8, unknown: 3, good: 14 },
  assets_by_criticality: { critical: 3, high: 5, medium: 7, low: 5 },
  active_findings_by_severity: { critical: 4, high: 22, medium: 58, low: 112, info: 89, unknown: 3 },
  findings_over_time: Array.from({ length: 30 }, (_, i) => ({ date: new Date(Date.now() - (29 - i) * 86400_000).toISOString().split('T')[0], counts: { critical: Math.max(0, 6 - Math.floor(i / 6)), high: 18 + Math.floor(Math.random() * 8), medium: 50 + Math.floor(Math.random() * 15), low: 100 + Math.floor(Math.random() * 20) } })),
  findings_without_timestamp: 8, external_findings_included: true,
}

// --- Code Quality Projects ---
const PROJECTS = [
  { ID: 'proj-001', Name: 'Synapse CE', Key: 'synapse-ce', SourceBinding: { kind: 'git', value: 'https://github.com/KKloudTarus/synapse-ce.git', ref: 'main' }, DefaultProfileByLang: { go: 'default', typescript: 'default' }, GateID: 'default', Audit: { CreatedAt: MONTH_AGO }, latest_analysis: { id: 'an-001', gate: { passed: false, results: [{ metric: 'new_critical_issues', condition: '= 0', actual: 2, passed: false }] }, gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' }, created_at: HOUR_AGO, source_commit: 'a1b2c3d', rating: { security: 'B', reliability: 'A', maintainability: 'C' }, issues: { total: 47, by_severity: { critical: 2, high: 8, medium: 19, low: 18 } }, new_code: { counts: { total: 5, critical: 1, high: 2, medium: 2, low: 0 }, period: 'previous_version' } }, latest_job: { id: 'job-001', status: 'succeeded' } },
  { ID: 'proj-002', Name: 'Gin Framework', Key: 'gin-gonic', SourceBinding: { kind: 'git', value: 'https://github.com/gin-gonic/gin.git', ref: 'master' }, DefaultProfileByLang: { go: 'default' }, GateID: 'default', Audit: { CreatedAt: WEEK_AGO }, latest_analysis: { id: 'an-002', gate: { passed: true, results: [{ metric: 'new_critical_issues', condition: '= 0', actual: 0, passed: true }] }, gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' }, created_at: DAY_AGO, source_commit: 'f4e5d6c', rating: { security: 'A', reliability: 'A', maintainability: 'B' }, issues: { total: 12, by_severity: { critical: 0, high: 2, medium: 5, low: 5 } }, new_code: { counts: { total: 1, critical: 0, high: 0, medium: 1, low: 0 }, period: 'previous_version' } }, latest_job: { id: 'job-002', status: 'succeeded' } },
]

// --- Rules ---
const RULES = Array.from({ length: 25 }, (_, i) => ({
  key: `go:S${1000 + i}`, name: ['SQL injection', 'XSS prevention', 'Path traversal', 'CSRF protection', 'Auth bypass', 'Insecure random', 'Hardcoded secret', 'Weak hash', 'Open redirect', 'SSRF'][i % 10], language: i < 15 ? 'go' : 'typescript', type: ['vulnerability', 'bug', 'code_smell'][i % 3], severity: (['critical', 'high', 'medium', 'low', 'info'] )[i % 5], tags: [['owasp-top10', 'injection'], ['owasp-top10', 'xss'], ['path-traversal'], ['csrf'], ['auth']][i % 5], cwe: [`CWE-${[89, 79, 22, 352, 287, 330, 798, 328, 601, 918][i % 10]}`],
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
const VULN_INTEL_TITLES = ['Remote code execution in serializer', 'Authentication bypass via token reuse', 'Memory corruption in parser', 'Information disclosure in error handler', 'Denial of service via regex', 'SQL injection in ORM query builder', 'Prototype pollution in merge utility', 'SSRF via URL parsing bypass', 'Insecure deserialization in message handler', 'Open redirect in OAuth callback', 'XML external entity injection', 'Path traversal in file upload', 'Weak cryptographic hash function', 'Cleartext transmission of credentials', 'Improper certificate validation']
const VULN_INTEL = {
  advisories: Array.from({ length: 15 }, (_, i) => ({
    canonical: {
      Advisory: {
        ID: `GHSA-${String.fromCharCode(97 + i)}bcd-${1000 + i}`,
        Aliases: [`CVE-2024-${4000 + i}`],
        Summary: VULN_INTEL_TITLES[i],
        CVSSVector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
        CVSSScore: [9.8, 8.6, 8.1, 6.5, 4.3, 9.1, 7.5, 8.8, 9.0, 5.4, 7.8, 7.2, 5.9, 6.1, 4.8][i],
      },
      Status: (['active', 'active', 'active', 'active', 'resolved'])[i % 5],
      KEV: i < 3,
      EPSS: [0.92, 0.78, 0.65, 0.45, 0.12, 0.88, 0.55, 0.71, 0.83, 0.33, 0.61, 0.48, 0.22, 0.31, 0.08][i],
      PublicExploit: i < 5,
      ActiveExploitation: i < 2,
      Sources: ['osv', 'nvd'].slice(0, 1 + (i % 2)),
    },
    revision: 1 + (i % 3),
    changed_fields: ['severity', 'affected'],
    sync_run_ids: [`run-${i + 1}`],
    changed_at: new Date(Date.now() - i * 86400_000).toISOString(),
    active_affected_count: [5, 3, 4, 2, 1, 6, 2, 3, 4, 1, 2, 3, 1, 2, 0][i],
    affected_asset_count: [3, 2, 2, 1, 1, 3, 1, 2, 2, 1, 1, 2, 1, 1, 0][i],
    affected_component_count: [8, 5, 6, 3, 2, 9, 4, 5, 7, 2, 3, 4, 2, 3, 0][i],
    risk_priority: [1, 1, 2, 2, 3, 1, 2, 1, 1, 3, 2, 2, 3, 3, 4][i],
    previous_risk_priority: [1, 2, 2, 3, 3, 1, 3, 2, 1, 3, 2, 3, 3, 4, 4][i],
    risk_trend: (['rising', 'stable', 'stable', 'falling', 'stable'])[i % 5],
    risk_score: [95, 82, 78, 55, 30, 91, 68, 80, 88, 40, 65, 52, 28, 35, 15][i],
    risk_score_change: [5, 0, -3, -8, 0, 2, -5, 0, 3, 0, -2, -4, 0, -1, 0][i],
    detection_states: ['detected'],
    action_states: i < 5 ? ['open'] : ['resolved'],
    last_evaluation: new Date(Date.now() - i * 3600_000).toISOString(),
  })),
  sources: [{ adapter: 'osv', enabled: true, last_sync: HOUR_AGO, state: 'succeeded' }, { adapter: 'nvd', enabled: true, last_sync: DAY_AGO, state: 'succeeded' }, { adapter: 'cisa_kev', enabled: true, last_sync: HOUR_AGO, state: 'succeeded' }],
}

// --- Audit Log ---
const AUDIT_LOG = Array.from({ length: 25 }, (_, i) => ({
  id: `audit-${String(i + 1).padStart(3, '0')}`,
  actor: ['admin', 'alice', 'system', 'bob', 'scanner'][i % 5],
  action: ['engagement.create', 'scan.start', 'finding.triage', 'engagement.transition', 'team.invite', 'scan.complete', 'sla.assess', 'agent.enroll', 'review.decide', 'project.analyze'][i % 10],
  target: ['eng-001', 'scan-042', 'finding-118', 'eng-002', 'user-003', 'scan-043', 'sla-policy-1', 'agent-001', 'review-77', 'proj-synapse'][i % 10],
  metadata: [
    { engagement: 'synapse-ce-audit', status: 'created' },
    { engine: 'grype', scope: 'repo' },
    { verdict: 'false_positive', confidence: '0.92' },
    { from: 'active', to: 'completed' },
    { email: 'bob@synapse.local', role: 'viewer' },
    { duration_ms: '45200', findings: '18' },
    { policy: 'default-30d', result: 'pass' },
    { version: '0.9.4', platform: 'linux/amd64' },
    { decision: 'retain', reason: 'confirmed vulnerability' },
    { language: 'go', issues: '12', hotspots: '3' },
  ][i % 10] as Record<string, string>,
  at: new Date(Date.now() - i * 2700_000).toISOString(),
  hash: `sha256:${Math.random().toString(36).slice(2, 14)}`,
  previous_hash: i === 0 ? undefined : `sha256:${Math.random().toString(36).slice(2, 14)}`,
}))

// --- Team ---
const TEAM_MEMBERS = [
  { id: 'user-001', name: 'Admin User', role: 'admin', disabled: false, createdAt: MONTH_AGO },
  { id: 'user-002', name: 'Alice Security', role: 'admin', disabled: false, createdAt: MONTH_AGO },
  { id: 'user-003', name: 'Bob DevOps', role: 'member', disabled: false, createdAt: WEEK_AGO },
  { id: 'user-004', name: 'Charlie Analyst', role: 'member', disabled: false, createdAt: WEEK_AGO },
  { id: 'user-005', name: 'Diana Pentester', role: 'member', disabled: false, createdAt: DAY_AGO },
  { id: 'user-006', name: 'Eve Auditor', role: 'member', disabled: true, createdAt: MONTH_AGO },
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
    const eng = ENGAGEMENTS.find(e => e.ID === params.id) ?? ENGAGEMENTS[0]
    return HttpResponse.json(eng)
  }),
  http.post('/api/v1/engagements', () => HttpResponse.json(ENGAGEMENTS[0])),
  http.patch('/api/v1/engagements/:id', ({ params }) => {
    const eng = ENGAGEMENTS.find(e => e.ID === params.id) ?? ENGAGEMENTS[0]
    return HttpResponse.json(eng)
  }),

  // --- Engagement Findings (raw PascalCase array -- mapFinding expects this) ---
  http.get('/api/v1/engagements/:id/findings', () => HttpResponse.json(FINDINGS)),

  // --- Engagement Scan ---
  http.get('/api/v1/engagements/:id/sbom', () => new HttpResponse(null, { status: 404 })),
  http.get('/api/v1/engagements/:id/scan-status', () => HttpResponse.json(null)),
  http.get('/api/v1/engagements/:id/scan', () => HttpResponse.json(SCAN_RESULT)),
  http.post('/api/v1/sca/scans', () => HttpResponse.json({ id: 'job-mock', engagement_id: 'eng-001', target: 'https://github.com/KKloudTarus/synapse-ce.git', kind: 'git', status: 'complete', stage: 'done', progress: 100, error: '', started_at: new Date(Date.now() - 300000).toISOString(), finished_at: NOW, debug_events: SCAN_RESULT.debug_events })),

  // --- Engagement SLA (returns { slas: [...] }) ---
  http.get('/api/v1/engagements/:id/slas', () => HttpResponse.json({ slas: SLA_ITEMS })),
  http.get('/api/v1/engagements/:id/slas/:fid', () => HttpResponse.json(SLA_ITEMS[0])),
  http.get('/api/v1/engagements/:id/slas/:fid/assessments', () => HttpResponse.json({ assessments: [SLA_ITEMS[0].assessment] })),
  http.get('/api/v1/engagements/:id/slas/:fid/events', () => HttpResponse.json({ events: [
    { tenant_id: 't1', id: 'ev-1', engagement_id: 'eng-001', finding_id: 'finding-001', assessment_id: 'sla-001', from: 'open', to: 'mitigating', reason: 'WAF rule deployed', compensating_control: 'WAF block rule', acceptance_expires_at: null, actor: 'alice', before_version: 1, after_version: 2, at: HOUR_AGO },
  ] })),

  // --- Engagement Evidence ---
  http.get('/api/v1/engagements/:id/evidence', () => HttpResponse.json({
    items: [
      { ID: 'ev-001', Kind: 'scan_result', Content: '', Hash: 'sha256:a1b2c3d4e5f6', PreviousHash: '', StorageRef: 's3://evidence/eng-001/scan-001.json', CreatedBy: 'system', CreatedAt: HOUR_AGO },
      { ID: 'ev-002', Kind: 'finding_triage', Content: '', Hash: 'sha256:f6e5d4c3b2a1', PreviousHash: 'sha256:a1b2c3d4e5f6', StorageRef: 's3://evidence/eng-001/triage-001.json', CreatedBy: 'ai-triage', CreatedAt: HOUR_AGO },
      { ID: 'ev-003', Kind: 'recon_output', Content: '', Hash: 'sha256:112233445566', PreviousHash: 'sha256:f6e5d4c3b2a1', StorageRef: 's3://evidence/eng-001/recon-nmap-001.txt', CreatedBy: 'recon-agent', CreatedAt: DAY_AGO },
      { ID: 'ev-004', Kind: 'manual_capture', Content: '', Hash: 'sha256:aabbccddeeff', PreviousHash: 'sha256:112233445566', StorageRef: 's3://evidence/eng-001/screenshot-001.png', CreatedBy: 'admin', CreatedAt: DAY_AGO },
      { ID: 'ev-005', Kind: 'report_generated', Content: '', Hash: 'sha256:998877665544', PreviousHash: 'sha256:aabbccddeeff', StorageRef: 's3://evidence/eng-001/report-v1.pdf', CreatedBy: 'system', CreatedAt: WEEK_AGO },
    ],
    intact: true,
    head: 'sha256:998877665544',
    verified: 5,
    error: '',
    attestation: { key_id: 'arn:aws:kms:us-east-1:123456789:key/mrk-abc', algorithm: 'ECDSA_SHA_384' },
  })),

  // --- Engagement Recon ---
  http.get('/api/v1/recon/tools', () => HttpResponse.json([
    { id: 'nmap', name: 'Nmap', description: 'Network port scanner', category: 'network', capabilities: ['port_scan', 'service_detection', 'os_fingerprint'] },
    { id: 'subfinder', name: 'Subfinder', description: 'Subdomain discovery', category: 'dns', capabilities: ['subdomain_enum'] },
    { id: 'nuclei', name: 'Nuclei', description: 'Template-based vulnerability scanner', category: 'vuln_scan', capabilities: ['cve_check', 'misconfig'] },
    { id: 'httpx', name: 'httpx', description: 'HTTP probe and tech fingerprint', category: 'web', capabilities: ['tech_detect', 'status_check'] },
    { id: 'ffuf', name: 'ffuf', description: 'Web fuzzer for content discovery', category: 'web', capabilities: ['dir_brute', 'vhost_brute'] },
  ])),
  http.get('/api/v1/engagements/:id/recon/runs', () => HttpResponse.json([
    { id: 'run-001', engagement_id: 'eng-001', tool: 'nmap', target: 'api.acme.io', status: 'complete', started_at: DAY_AGO, finished_at: DAY_AGO, output_lines: 42, findings_count: 3 },
    { id: 'run-002', engagement_id: 'eng-001', tool: 'subfinder', target: 'acme.io', status: 'complete', started_at: DAY_AGO, finished_at: DAY_AGO, output_lines: 18, findings_count: 8 },
    { id: 'run-003', engagement_id: 'eng-001', tool: 'nuclei', target: 'api.acme.io', status: 'running', started_at: HOUR_AGO, finished_at: null, output_lines: 120, findings_count: 0 },
  ])),

  // --- Engagement Agent Sessions ---
  http.get('/api/v1/engagements/:id/agent-sessions', () => HttpResponse.json([
    { id: 'sess-001', engagement_id: 'eng-001', status: 'complete', objective: 'Enumerate attack surface for api.acme.io', started_at: DAY_AGO, finished_at: DAY_AGO, steps: 8, findings_generated: 2 },
    { id: 'sess-002', engagement_id: 'eng-001', status: 'running', objective: 'Exploit identified SSRF vulnerability', started_at: HOUR_AGO, finished_at: null, steps: 3, findings_generated: 0 },
  ])),
  http.get('/api/v1/engagements/:id/agent-approvals', () => HttpResponse.json([
    { id: 'appr-001', session_id: 'sess-002', tool: 'curl', target: 'http://169.254.169.254/latest/meta-data/', rationale: 'Verify SSRF reaches IMDS', status: 'pending', requested_at: HOUR_AGO },
  ])),
  http.get('/api/v1/engagements/:id/agent-readiness', () => HttpResponse.json({ ready: true, reason: '', sandbox_healthy: true, tools_available: ['nmap', 'curl', 'nuclei', 'ffuf', 'subfinder'] })),
  http.get('/api/v1/engagements/:id/agent-sessions/:sid', () => HttpResponse.json({
    id: 'sess-001', engagement_id: 'eng-001', status: 'complete', objective: 'Enumerate attack surface',
    transcript: [
      { role: 'system', content: 'Agent initialized. Objective: enumerate attack surface for api.acme.io', timestamp: DAY_AGO },
      { role: 'agent', content: 'Running subfinder for subdomain enumeration...', timestamp: DAY_AGO },
      { role: 'tool', content: 'subfinder found 8 subdomains: api.acme.io, admin.acme.io, staging.acme.io...', timestamp: DAY_AGO },
      { role: 'agent', content: 'Running nmap port scan on discovered hosts...', timestamp: DAY_AGO },
      { role: 'tool', content: 'nmap: 3 hosts up, 12 open ports total. Notable: admin.acme.io:8080 (no TLS)', timestamp: DAY_AGO },
      { role: 'agent', content: 'Finding: admin panel exposed without TLS on port 8080. Generating finding...', timestamp: DAY_AGO },
    ],
    started_at: DAY_AGO, finished_at: DAY_AGO, steps: 8, findings_generated: 2,
  })),
  http.get('/api/v1/engagements/:id/agent-sessions/:sid/plan', () => HttpResponse.json({
    steps: [
      { id: 1, action: 'subdomain_enum', target: 'acme.io', status: 'complete', tool: 'subfinder' },
      { id: 2, action: 'port_scan', target: 'discovered hosts', status: 'complete', tool: 'nmap' },
      { id: 3, action: 'service_fingerprint', target: 'open ports', status: 'complete', tool: 'httpx' },
      { id: 4, action: 'vuln_scan', target: 'web services', status: 'pending', tool: 'nuclei' },
    ],
  })),
  http.get('/api/v1/engagements/:id/agent-sessions/:sid/decisions', () => HttpResponse.json([
    { id: 'd-1', session_id: 'sess-001', step: 2, decision: 'proceed', rationale: 'Non-intrusive port scan within RoE', tool: 'nmap', target: 'api.acme.io', decided_at: DAY_AGO },
  ])),

  // --- Engagement Code Quality ---
  http.get('/api/v1/engagements/:id/code-quality', () => HttpResponse.json({
    available: true,
    report: SCAN_RESULT.code_quality,
  })),

  // --- Writeups ---
  http.get('/api/v1/writeups', () => HttpResponse.json([
    { id: 'wu-001', title: 'SQL Injection via unsanitized input', severity: 'critical', cwe: 'CWE-89', body: '## Summary\nUser input concatenated directly into SQL query...', remediation: 'Use parameterized queries', references: ['https://owasp.org/Top10/A03_2021-Injection/'] },
    { id: 'wu-002', title: 'Reflected XSS in search parameter', severity: 'high', cwe: 'CWE-79', body: '## Summary\nUser-supplied search term reflected in response...', remediation: 'Apply output encoding', references: ['https://owasp.org/Top10/A03_2021-Injection/'] },
  ])),

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
  http.get('/api/v1/ai-triage/reviews', ({ request }) => {
    const url = new URL(request.url)
    const severity = url.searchParams.get('severity')
    const cwe = url.searchParams.get('cwe')?.trim().toLowerCase()
    const project = url.searchParams.get('project')
    const state = url.searchParams.get('state')

    let list = [...REVIEWS]
    if (state && state !== 'all') {
      list = list.filter((r) => r.state === state)
    }
    if (severity && severity !== 'all') {
      list = list.filter((r) => r.severity === severity)
    }
    if (cwe) {
      list = list.filter((r) => r.cwe?.toLowerCase().includes(cwe) || r.title?.toLowerCase().includes(cwe))
    }
    if (project && project !== 'all') {
      list = list.filter((r) => r.project_id === project || r.engagement_id === project)
    }
    return HttpResponse.json({ reviews: list })
  }),
  http.get('/api/v1/ai-triage/reviews/:id', ({ params }) => {
    const r = REVIEWS.find(rv => rv.id === params.id) ?? REVIEWS[0]
    return HttpResponse.json(r)
  }),
  http.post('/api/v1/ai-triage/reviews/:id/claim', ({ params }) => {
    const r = REVIEWS.find(rv => rv.id === params.id)
    if (r) {
      r.owner = 'admin'
      r.version += 1
      return HttpResponse.json(r)
    }
    return new HttpResponse('Not found', { status: 404 })
  }),
  http.post('/api/v1/ai-triage/reviews/:id/decision', async ({ params, request }) => {
    const r = REVIEWS.find(rv => rv.id === params.id)
    const body = (await request.json()) as { decision: 'accept' | 'reject'; rationale: string }
    if (r) {
      r.state = body.decision === 'accept' ? 'accepted' : 'rejected'
      r.decided_by = 'admin'
      r.decision_rationale = body.rationale
      r.decided_at = new Date().toISOString()
      r.version += 1
      return HttpResponse.json(r)
    }
    return new HttpResponse('Not found', { status: 404 })
  }),

  // --- AI Triage Observability ---
  http.get('/api/v1/ai-triage/observability', () => HttpResponse.json(OBSERVABILITY)),

  // --- Current User ---
  http.get('/api/v1/me', () => HttpResponse.json({ id: 'user-001', username: 'admin', display_name: 'Admin User', email: 'admin@synapse.local', role: 'owner' })),

  // --- Assets ---
  http.get('/api/v1/assets', () => HttpResponse.json(BUSINESS_ASSETS.map(a => ({ ...a, type: 'host', tags: ['production'], finding_count: 12, last_scanned: HOUR_AGO })))),
  http.get('/api/v1/assets/:id', ({ params }) => {
    const a = BUSINESS_ASSETS.find(x => x.ID === params.id) ?? BUSINESS_ASSETS[0]
    return HttpResponse.json({ ...a, type: 'host', tags: ['production'], finding_count: 12, last_scanned: HOUR_AGO, engagements: ENGAGEMENTS.slice(0, 2) })
  }),
  http.get('/api/v1/appsec/assets', ({ request }) => {
    const url = new URL(request.url)
    const limit = Number(url.searchParams.get('limit')) || 5
    const offset = Number(url.searchParams.get('offset')) || 0
    const q = url.searchParams.get('q')?.toLowerCase().trim()
    const type = url.searchParams.get('type')
    const criticality = url.searchParams.get('criticality')
    const lifecycle = url.searchParams.get('lifecycle')

    let items = [...BUSINESS_ASSETS]
    if (q) {
      items = items.filter(a => a.Name.toLowerCase().includes(q) || a.Key.toLowerCase().includes(q) || a.Owner.toLowerCase().includes(q))
    }
    if (type && type !== 'all') {
      items = items.filter(a => a.Type === type)
    }
    if (criticality && criticality !== 'all') {
      items = items.filter(a => a.Criticality === criticality)
    }
    if (lifecycle && lifecycle !== 'all') {
      items = items.filter(a => a.Lifecycle === lifecycle)
    }

    const total = items.length
    const paged = items.slice(offset, offset + limit)
    return HttpResponse.json({ items: paged, total, limit, offset })
  }),
  http.get('/api/v1/appsec/assets/:key/projects', () => HttpResponse.json([
    { ComponentID: 'proj-001', Role: 'primary', Provenance: 'engagement:eng-001' },
    { ComponentID: 'proj-002', Role: 'supporting', Provenance: 'manual' },
  ])),
  http.get('/api/v1/appsec/assets/:key/technical-assets', () => HttpResponse.json([
    { ID: 'ta-001', Kind: 'repository', Key: 'github.com/KKloudTarus/synapse-ce', Name: 'synapse-ce repo', Attributes: { language: 'Go', stars: 42 } },
    { ID: 'ta-002', Kind: 'container', Key: 'synapse-api:latest', Name: 'synapse-api container', Attributes: { registry: 'ECR', size_mb: 180 } },
    { ID: 'ta-003', Kind: 'endpoint', Key: 'api.synapse.internal', Name: 'API endpoint', Attributes: { protocol: 'HTTPS', port: 443 } },
  ])),
  http.get('/api/v1/appsec/assets/:key/engagements', () => HttpResponse.json(ENGAGEMENTS.slice(0, 3))),
  http.get('/api/v1/appsec/assets/:key/findings', () => HttpResponse.json(
    FINDINGS.slice(0, 8).map((f, i) => ({
      finding: f,
      external: i % 3 === 0,
      can_self_promote: false,
      suppressed_by_tool: false,
      provenance: { ToolName: 'synapse-sast', ToolVersion: '1.4.2', RuleID: (f as any).RuleID ?? `rule-${i}`, SourceDigest: 'sha256:abc123', IngestedBy: 'scanner', IngestedAt: HOUR_AGO },
      reachability: { state: ['reachable', 'unreachable', 'unknown'][i % 3], tier: `tier-${i % 3}`, confidence: 70 + i * 3, path: [], status: '', source: 'callgraph', history: [] },
      engagement_id: ENGAGEMENTS[i % 3]?.ID ?? 'eng-001',
      engagement_name: ENGAGEMENTS[i % 3]?.Name ?? 'synapse-ce-audit',
    }))
  )),
  http.get('/api/v1/appsec/assets/:key/coverage', () => HttpResponse.json({
    rows: [
      { kind: 'sca', component_id: 'proj-001', name: 'SCA Scan', verdict: 'covered', engagement_id: 'eng-001', last_assessed: HOUR_AGO, freshness_target_days: 30 },
      { kind: 'sast', component_id: 'proj-001', name: 'SAST Scan', verdict: 'covered', engagement_id: 'eng-001', last_assessed: DAY_AGO, freshness_target_days: 30 },
      { kind: 'dast', component_id: 'ta-003', name: 'DAST Scan', verdict: 'stale', engagement_id: 'eng-003', last_assessed: MONTH_AGO, freshness_target_days: 14 },
      { kind: 'pentest', component_id: 'ta-001', name: 'Manual Pentest', verdict: 'uncovered', engagement_id: '', last_assessed: null, freshness_target_days: 90 },
    ],
    counts: { covered: 2, stale: 1, uncovered: 1 },
    freshness_target_days: 30,
  })),
  http.get('/api/v1/appsec/assets/:key/posture', () => HttpResponse.json({
    rating: 'attention',
    explanation: '2 high-severity findings open, DAST coverage stale',
    finding_counts: { critical: 1, high: 3, medium: 5, low: 2 },
    coverage_counts: { covered: 2, stale: 1, uncovered: 1 },
  })),
  http.get('/api/v1/appsec/assets/:key/history', () => HttpResponse.json([
    { engagement_id: 'eng-001', name: 'synapse-ce-audit', status: 'active', authorized_from: MONTH_AGO, authorized_to: null, scope_count: 1, finding_count: 45, retest_count: 2, updated_at: HOUR_AGO },
    { engagement_id: 'eng-003', name: 'api-pentest-q3', status: 'active', authorized_from: WEEK_AGO, authorized_to: new Date(Date.now() + 30 * 86400_000).toISOString(), scope_count: 2, finding_count: 12, retest_count: 0, updated_at: DAY_AGO },
  ])),
  http.get('/api/v1/appsec/assets/:key', ({ params }) => {
    const a = BUSINESS_ASSETS.find(x => x.Key === params.key || x.ID === params.key) ?? BUSINESS_ASSETS[0]
    return HttpResponse.json(a)
  }),

  // --- Vulnerability Intelligence ---
  http.get('/api/v1/vulnerability/overview', () => HttpResponse.json({
    enabled_sources: 4, stale_or_failed_sources: 1, last_successful_sync: HOUR_AGO,
    changed_advisories_24_hours: 12, oldest_unevaluated_revision: null,
    open_high_critical_exposure: 7, pending_risk_actions: 3, queue_depth: 0, dead_letters: 0,
  })),
  http.get('/api/v1/vulnerability/advisories', () => HttpResponse.json({ items: VULN_INTEL.advisories, next: '' })),
  http.get('/api/v1/vulnerability/advisories/:id', ({ params }) => {
    const a = VULN_INTEL.advisories.find(x => x.canonical.Advisory.ID === params.id) ?? VULN_INTEL.advisories[0]
    return HttpResponse.json(a)
  }),
  http.get('/api/v1/vulnerability/advisories/:id/revisions', ({ params }) => {
    const a = VULN_INTEL.advisories.find(x => x.canonical.Advisory.ID === params.id) ?? VULN_INTEL.advisories[0]
    return HttpResponse.json({
      items: Array.from({ length: a.revision }, (_, i) => ({
        ...a,
        revision: a.revision - i,
        changed_fields: i === 0 ? ['severity', 'affected'] : ['affected'],
        changed_at: new Date(Date.now() - (i + 1) * 3 * 86400_000).toISOString(),
        sync_run_ids: [`run-rev-${a.revision - i}`],
      })),
      next: 0,
    })
  }),
  http.get('/api/v1/vulnerability/occurrences', ({ request }) => {
    const url = new URL(request.url)
    const advisoryId = url.searchParams.get('advisory_id') ?? ''
    const idx = VULN_INTEL.advisories.findIndex(x => x.canonical.Advisory.ID === advisoryId)
    const count = Math.max(1, (idx >= 0 ? VULN_INTEL.advisories[idx].active_affected_count : 2))
    return HttpResponse.json({
      items: Array.from({ length: count }, (_, i) => ({
        ID: `occ-${advisoryId}-${i + 1}`,
        EngagementID: ENGAGEMENTS[i % ENGAGEMENTS.length].ID,
        AdvisoryID: advisoryId,
        AdvisoryRevision: 1,
        ComponentID: `comp-${i + 1}`,
        ComponentFingerprint: `sha256:${String(i).repeat(8)}`,
        Ecosystem: ['npm', 'go', 'pypi', 'maven', 'cargo'][i % 5],
        Package: ['express', 'golang.org/x/net', 'requests', 'log4j-core', 'serde'][i % 5],
        ComponentVersion: `${1 + i}.${i * 2}.${i}`,
        ComponentCPE: '',
        FixedVersion: `${2 + i}.0.0`,
        MatchMethod: ['exact', 'semver', 'purl'][i % 3],
        Confidence: ['confirmed', 'likely', 'confirmed'][i % 3],
        Scope: ['direct', 'transitive', 'direct'][i % 3],
        Reachability: ['reachable', 'unreachable', 'unknown'][i % 3],
        State: ['detected', 'detected', 'no_longer_detected'][i % 3],
        FirstDetectedAt: new Date(Date.now() - (10 + i) * 86400_000).toISOString(),
        LastDetectedAt: new Date(Date.now() - i * 86400_000).toISOString(),
        LastEvaluatedAt: HOUR_AGO,
        UpdatedAt: HOUR_AGO,
      })),
    })
  }),
  http.get('/api/v1/vulnerability/occurrences/:id/assessments', () => HttpResponse.json({
    items: [
      { ID: 'assess-001', OccurrenceID: '', AdvisoryRevision: 1, Severity: 'critical', CVSSScore: 9.8, KEV: true, EPSS: 0.92, Scope: 'direct', Reachability: 'reachable', Impact: 'Remote code execution', FixedVersion: '2.0.0', OccurrenceState: 'detected', RiskScore: 95, Priority: 1, ReasonCodes: ['kev', 'exploit_public', 'reachable'], AssessedAt: HOUR_AGO },
      { ID: 'assess-002', OccurrenceID: '', AdvisoryRevision: 1, Severity: 'high', CVSSScore: 8.6, KEV: false, EPSS: 0.45, Scope: 'direct', Reachability: 'reachable', Impact: 'Authentication bypass', FixedVersion: '1.5.0', OccurrenceState: 'detected', RiskScore: 72, Priority: 2, ReasonCodes: ['reachable', 'direct_dep'], AssessedAt: DAY_AGO },
    ],
  })),
  http.get('/api/v1/vulnerability/occurrences/:id/transitions', () => HttpResponse.json({
    items: [
      { ID: 'trans-001', OccurrenceID: '', FromState: '', ToState: 'detected', Reason: 'Initial detection during scan', Actor: 'scanner', CreatedAt: new Date(Date.now() - 10 * 86400_000).toISOString() },
      { ID: 'trans-002', OccurrenceID: '', FromState: 'detected', ToState: 'detected', Reason: 'Re-confirmed in latest scan', Actor: 'scanner', CreatedAt: DAY_AGO },
    ],
  })),
  http.get('/api/v1/vulnerability/actions', () => HttpResponse.json({
    items: [
      { id: 'action-001', advisoryId: 'GHSA-abcd-1000', occurrenceId: 'occ-GHSA-abcd-1000-1', kind: 'patch', status: 'open', priority: 1, title: 'Upgrade express to >=2.0.0', assignee: 'alice', createdAt: DAY_AGO, updatedAt: HOUR_AGO },
      { id: 'action-002', advisoryId: 'GHSA-abcd-1000', occurrenceId: 'occ-GHSA-abcd-1000-2', kind: 'mitigate', status: 'open', priority: 2, title: 'Apply WAF rule for serialization endpoint', assignee: '', createdAt: DAY_AGO, updatedAt: DAY_AGO },
      { id: 'action-003', advisoryId: 'GHSA-bcde-1001', occurrenceId: 'occ-GHSA-bcde-1001-1', kind: 'accept_risk', status: 'resolved', priority: 3, title: 'Accept risk: internal-only service', assignee: 'bob', createdAt: WEEK_AGO, updatedAt: DAY_AGO },
    ],
  })),
  http.get('/api/v1/vulnerability/sources', () => HttpResponse.json([
    { id: 'src-001', key: 'osv-github', name: 'OSV (GitHub)', adapter_type: 'osv', endpoint: 'https://api.osv.dev/v1', enabled: true, archived: false, cadence_seconds: 3600, stale_after_seconds: 86400, sync_mode: 'incremental', adapter_config: {}, credential_configured: false, version: 3, created_at: MONTH_AGO, updated_at: HOUR_AGO, health: { state: 'healthy', stale: false, last_successful_at: HOUR_AGO, fresh_until: new Date(Date.now() + 82800_000).toISOString(), latest_run: { id: 'run-101', source_id: 'src-001', mode: 'incremental', state: 'succeeded', started_at: new Date(Date.now() - 1800_000).toISOString(), finished_at: HOUR_AGO, duration_seconds: 45, advisories_created: 3, advisories_updated: 12, advisories_withdrawn: 0, error: '' } } },
    { id: 'src-002', key: 'nvd-nist', name: 'NVD (NIST)', adapter_type: 'nvd', endpoint: 'https://services.nvd.nist.gov/rest/json/cves/2.0', enabled: true, archived: false, cadence_seconds: 7200, stale_after_seconds: 172800, sync_mode: 'incremental', adapter_config: {}, credential_configured: true, version: 5, created_at: MONTH_AGO, updated_at: DAY_AGO, health: { state: 'healthy', stale: false, last_successful_at: DAY_AGO, fresh_until: new Date(Date.now() + 86400_000).toISOString(), latest_run: { id: 'run-102', source_id: 'src-002', mode: 'incremental', state: 'succeeded', started_at: new Date(Date.now() - 86400_000 - 300_000).toISOString(), finished_at: DAY_AGO, duration_seconds: 120, advisories_created: 28, advisories_updated: 45, advisories_withdrawn: 2, error: '' } } },
    { id: 'src-003', key: 'cisa-kev', name: 'CISA KEV', adapter_type: 'cisa_kev', endpoint: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', enabled: true, archived: false, cadence_seconds: 3600, stale_after_seconds: 86400, sync_mode: 'full', adapter_config: {}, credential_configured: false, version: 2, created_at: MONTH_AGO, updated_at: HOUR_AGO, health: { state: 'healthy', stale: false, last_successful_at: HOUR_AGO, fresh_until: new Date(Date.now() + 82800_000).toISOString(), latest_run: { id: 'run-103', source_id: 'src-003', mode: 'full', state: 'succeeded', started_at: new Date(Date.now() - 2400_000).toISOString(), finished_at: HOUR_AGO, duration_seconds: 18, advisories_created: 0, advisories_updated: 5, advisories_withdrawn: 0, error: '' } } },
    { id: 'src-004', key: 'first-epss', name: 'FIRST EPSS', adapter_type: 'first_epss', endpoint: 'https://epss.cyentia.com/epss_scores-current.csv.gz', enabled: true, archived: false, cadence_seconds: 86400, stale_after_seconds: 259200, sync_mode: 'full', adapter_config: {}, credential_configured: false, version: 1, created_at: MONTH_AGO, updated_at: new Date(Date.now() - 4 * 86400_000).toISOString(), health: { state: 'stale', stale: true, last_successful_at: new Date(Date.now() - 4 * 86400_000).toISOString(), fresh_until: new Date(Date.now() - 86400_000).toISOString(), latest_run: { id: 'run-104', source_id: 'src-004', mode: 'full', state: 'failed', started_at: new Date(Date.now() - 2 * 86400_000).toISOString(), finished_at: new Date(Date.now() - 2 * 86400_000 + 30_000).toISOString(), duration_seconds: 30, advisories_created: 0, advisories_updated: 0, advisories_withdrawn: 0, error: 'connection timeout: epss.cyentia.com' } } },
  ])),
  http.get('/api/v1/vulnerability/sources/types', () => HttpResponse.json([
    { type: 'osv', implemented: true, supports_test: true, supports_credentials: false },
    { type: 'nvd', implemented: true, supports_test: true, supports_credentials: true },
    { type: 'cisa_kev', implemented: true, supports_test: true, supports_credentials: false },
    { type: 'first_epss', implemented: true, supports_test: false, supports_credentials: false },
    { type: 'csaf', implemented: true, supports_test: true, supports_credentials: true },
    { type: 'public_exploit', implemented: true, supports_test: false, supports_credentials: false },
  ])),
  http.get('/api/v1/vulnerability/sync-runs', () => HttpResponse.json({ items: [
    {
      id: 'run-001', source_id: 'src-001', adapter_type: 'osv', mode: 'incremental', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-901',
      attempts: 1, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'GHSA-abcd-1000', revision: 3, changed_at: HOUR_AGO }],
      affected_revisions_truncated: false, checkpoint: { cursor: '2026-08-23T12:00:00Z', page: 4 },
      counts: { processed: 45, inserted: 3, updated: 8, unchanged: 34, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 1800_000).toISOString(),
      started_at: new Date(Date.now() - 1795_000).toISOString(),
      finished_at: new Date(Date.now() - 1750_000).toISOString(),
    },
    {
      id: 'run-002', source_id: 'src-002', adapter_type: 'nvd', mode: 'incremental', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-902',
      attempts: 1, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'CVE-2026-1234', revision: 2, changed_at: new Date(Date.now() - 3600_000 * 2).toISOString() }],
      affected_revisions_truncated: false, checkpoint: { last_mod_start: '2026-08-22T00:00:00Z', offset: 120 },
      counts: { processed: 120, inserted: 5, updated: 15, unchanged: 100, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 3600_000 * 2).toISOString(),
      started_at: new Date(Date.now() - 3600_000 * 2 + 5_000).toISOString(),
      finished_at: new Date(Date.now() - 3600_000 * 2 + 125_000).toISOString(),
    },
    {
      id: 'run-003', source_id: 'src-003', adapter_type: 'cisa_kev', mode: 'full', trigger: 'manual', actor: 'admin', durable_job_id: 'job-903',
      attempts: 1, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'CVE-2026-1234', revision: 1, changed_at: new Date(Date.now() - 3600_000 * 4).toISOString() }],
      affected_revisions_truncated: false, checkpoint: { total_records: 1145 },
      counts: { processed: 1145, inserted: 2, updated: 0, unchanged: 1143, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 3600_000 * 4).toISOString(),
      started_at: new Date(Date.now() - 3600_000 * 4 + 2_000).toISOString(),
      finished_at: new Date(Date.now() - 3600_000 * 4 + 20_000).toISOString(),
    },
    {
      id: 'run-004', source_id: 'src-004', adapter_type: 'first_epss', mode: 'full', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-904',
      attempts: 3, dead_lettered: true,
      affected_revisions: [],
      affected_revisions_truncated: false, checkpoint: { chunk: 1, line: 0 },
      counts: { processed: 0, inserted: 0, updated: 0, unchanged: 0, skipped: 0, quarantined: 0 },
      error_samples: ['connection timeout: epss.cyentia.com:443 after 30s'], state: 'failed',
      created_at: new Date(Date.now() - 3600_000 * 8).toISOString(),
      started_at: new Date(Date.now() - 3600_000 * 8 + 3_000).toISOString(),
      finished_at: new Date(Date.now() - 3600_000 * 8 + 93_000).toISOString(),
    },
    {
      id: 'run-005', source_id: 'src-001', adapter_type: 'osv', mode: 'incremental', trigger: 'manual', actor: 'alice', durable_job_id: 'job-905',
      attempts: 1, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'GHSA-bcde-1001', revision: 2, changed_at: new Date(Date.now() - 3600_000 * 12).toISOString() }],
      affected_revisions_truncated: false, checkpoint: { cursor: '2026-08-22T18:00:00Z', page: 2 },
      counts: { processed: 62, inserted: 1, updated: 4, unchanged: 57, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 3600_000 * 12).toISOString(),
      started_at: new Date(Date.now() - 3600_000 * 12 + 1_000).toISOString(),
      finished_at: new Date(Date.now() - 3600_000 * 12 + 36_000).toISOString(),
    },
    {
      id: 'run-006', source_id: 'src-002', adapter_type: 'nvd', mode: 'full', trigger: 'manual', actor: 'admin', durable_job_id: 'job-906',
      attempts: 1, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'CVE-2026-9999', revision: 1, changed_at: new Date(Date.now() - 86400_000).toISOString() }],
      affected_revisions_truncated: false, checkpoint: { start_index: 2000, total: 250000 },
      counts: { processed: 2500, inserted: 12, updated: 88, unchanged: 2400, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 86400_000).toISOString(),
      started_at: new Date(Date.now() - 86400_000 + 4_000).toISOString(),
      finished_at: new Date(Date.now() - 86400_000 + 244_000).toISOString(),
    },
    {
      id: 'run-007', source_id: 'src-001', adapter_type: 'osv', mode: 'incremental', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-907',
      attempts: 1, dead_lettered: false,
      affected_revisions: [],
      affected_revisions_truncated: false, checkpoint: { cursor: '2026-08-21T06:00:00Z', page: 1 },
      counts: { processed: 20, inserted: 0, updated: 1, unchanged: 19, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 86400_000 * 2).toISOString(),
      started_at: new Date(Date.now() - 86400_000 * 2 + 1_000).toISOString(),
      finished_at: new Date(Date.now() - 86400_000 * 2 + 15_000).toISOString(),
    },
    {
      id: 'run-008', source_id: 'src-003', adapter_type: 'cisa_kev', mode: 'full', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-908',
      attempts: 1, dead_lettered: false,
      affected_revisions: [],
      affected_revisions_truncated: false, checkpoint: { total_records: 1140 },
      counts: { processed: 1140, inserted: 0, updated: 0, unchanged: 1140, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 86400_000 * 3).toISOString(),
      started_at: new Date(Date.now() - 86400_000 * 3 + 2_000).toISOString(),
      finished_at: new Date(Date.now() - 86400_000 * 3 + 19_000).toISOString(),
    },
    {
      id: 'run-009', source_id: 'src-002', adapter_type: 'nvd', mode: 'incremental', trigger: 'scheduled', actor: 'system:scheduler', durable_job_id: 'job-909',
      attempts: 2, dead_lettered: false,
      affected_revisions: [{ advisory_id: 'CVE-2026-5555', revision: 1, changed_at: new Date(Date.now() - 86400_000 * 4).toISOString() }],
      affected_revisions_truncated: false, checkpoint: { offset: 40 },
      counts: { processed: 40, inserted: 1, updated: 3, unchanged: 36, skipped: 0, quarantined: 0 },
      error_samples: ['HTTP 429 Rate limited, backed off for 30s'], state: 'partial',
      created_at: new Date(Date.now() - 86400_000 * 4).toISOString(),
      started_at: new Date(Date.now() - 86400_000 * 4 + 5_000).toISOString(),
      finished_at: new Date(Date.now() - 86400_000 * 4 + 75_000).toISOString(),
    },
    {
      id: 'run-010', source_id: 'src-001', adapter_type: 'osv', mode: 'incremental', trigger: 'manual', actor: 'alice', durable_job_id: 'job-910',
      attempts: 1, dead_lettered: false,
      affected_revisions: [],
      affected_revisions_truncated: false, checkpoint: { cursor: '2026-08-19T00:00:00Z', page: 1 },
      counts: { processed: 15, inserted: 0, updated: 0, unchanged: 15, skipped: 0, quarantined: 0 },
      error_samples: [], state: 'succeeded',
      created_at: new Date(Date.now() - 86400_000 * 5).toISOString(),
      started_at: new Date(Date.now() - 86400_000 * 5 + 1_000).toISOString(),
      finished_at: new Date(Date.now() - 86400_000 * 5 + 12_000).toISOString(),
    },
  ], next: '' })),

  // --- Fleet ---
  http.get('/api/v1/fleet/coverage/summary', () => HttpResponse.json({
    agents_by_state: { healthy: 4, stale: 1, revoked: 0 },
    rows_by_verdict: { covered: 4, stale: 1, partial: 1, agent_missing: 1 },
    oldest_per_capability: { 'scan.host': new Date(Date.now() - 3 * 86400_000).toISOString(), 'detect.runtime': DAY_AGO, 'scan.container': HOUR_AGO },
    assets_without_agent: 1,
  })),
  http.get('/api/v1/fleet/agents', () => HttpResponse.json(FLEET_AGENTS)),
  http.get('/api/v1/fleet/agents/:id', ({ params }) => {
    const agent = FLEET_AGENTS.find(a => a.id === params.id) ?? FLEET_AGENTS[0]
    return HttpResponse.json({ agent, recent_work: [{ id: 'wo-1', capability: 'scan.host', asset_id: 'ba-001', state: 'succeeded', updated_at: HOUR_AGO }, { id: 'wo-2', capability: 'detect.runtime', asset_id: 'ba-001', state: 'running', updated_at: NOW }] })
  }),
  http.get('/api/v1/fleet/coverage', () => HttpResponse.json(FLEET_COVERAGE)),

  // --- Code Quality Projects ---
  http.get('/api/v1/projects', () => HttpResponse.json(PROJECTS)),
  http.get('/api/v1/projects/:key', ({ params }) => {
    const p = PROJECTS.find(pr => pr.Key === params.key) ?? PROJECTS[0]
    return HttpResponse.json(p)
  }),
  http.get('/api/v1/projects/:key/overview', ({ params }) => {
    const p = PROJECTS.find(pr => pr.Key === params.key) ?? PROJECTS[0]
    const analysis = p.latest_analysis
    const gatePassed = analysis.gate.passed
    return HttpResponse.json({
      state: 'analyzed',
      project: { key: p.Key, name: p.Name },
      latest_analysis: {
        id: analysis.id,
        created_at: analysis.created_at,
        source_ref: 'refs/heads/main',
        source_commit: analysis.source_commit,
        new_code: { first_analysis: false, has_baseline: true, baseline_analysis_id: 'an-000' },
      },
      gate: {
        status: gatePassed ? 'passed' : 'failed',
        key: 'default',
        name: 'Synapse Way',
        source: 'managed',
        failed_conditions: gatePassed ? [] : [{ metric: 'new_critical', operator: '<=', threshold: 0, actual: 2 }],
      },
      issue_summary: {
        new_code_total: { availability: 'available', value: analysis.new_code?.counts?.total ?? 5, unavailable_reason: null },
        accepted_overall_total: { availability: 'available', value: analysis.issues.total, unavailable_reason: null },
      },
      lenses: {
        overall: {
          security: { availability: 'available', grade: analysis.rating.security, unavailable_reason: null },
          reliability: { availability: 'available', grade: analysis.rating.reliability, unavailable_reason: null },
          maintainability: { availability: 'available', grade: analysis.rating.maintainability, unavailable_reason: null },
          security_hotspots_reviewed: { availability: 'available', value: 50, unavailable_reason: null },
          coverage: { availability: 'available', value: 72.4, unavailable_reason: null },
          duplications: { availability: 'available', value: 3.2, unavailable_reason: null },
        },
        new_code: {
          security: { availability: 'available', grade: 'B', unavailable_reason: null },
          reliability: { availability: 'available', grade: 'A', unavailable_reason: null },
          maintainability: { availability: 'available', grade: 'B', unavailable_reason: null },
          security_hotspots_reviewed: { availability: 'available', value: 100, unavailable_reason: null },
          coverage: { availability: 'available', value: 68.1, unavailable_reason: null },
          duplications: { availability: 'available', value: 1.5, unavailable_reason: null },
        },
      },
    })
  }),
  http.get('/api/v1/projects/:key/analyses', () => HttpResponse.json({
    items: Array.from({ length: 8 }, (_, i) => ({
      id: `an-${String(8 - i).padStart(3, '0')}`,
      created_at: new Date(Date.now() - i * 3 * 86400_000).toISOString(),
      source_ref: 'refs/heads/main',
      source_commit: `${String.fromCharCode(97 + i)}1b2c3${i}`,
      gate: { passed: i > 2, results: i <= 2 ? [{ metric: 'new_critical_issues', condition: '= 0', actual: 2 - i, passed: i > 2 }] : [] },
      gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' },
      issues: { total: 47 - i * 4, by_severity: { critical: Math.max(0, 2 - i), high: 8 - i, medium: 19 - i, low: 18 - i * 2 } },
      new_code: { counts: { total: Math.max(0, 5 - i), critical: Math.max(0, 1 - i), high: Math.max(0, 2 - i), medium: 2, low: 0 }, period: 'previous_version' },
      rating: { security: i < 2 ? 'B' : 'A', reliability: 'A', maintainability: i < 3 ? 'C' : 'B' },
      measures: { lines: 48520 - i * 500, ncloc: 38200 - i * 400, coverage: 72.4 + i * 1.2, duplicated_lines_density: 3.2 - i * 0.3 },
    })),
    next: null,
  })),
  http.get('/api/v1/projects/:key/analysis', ({ params }) => {
    const p = PROJECTS.find(pr => pr.Key === params.key) ?? PROJECTS[0]
    const a = p.latest_analysis
    return HttpResponse.json({
      analysis: {
        id: a.id,
        created_at: a.created_at,
        source_ref: 'refs/heads/main',
        source_commit: a.source_commit,
        gate: { passed: a.gate.passed, results: a.gate.results.map((r: any) => ({ metric: r.metric, op: r.condition?.includes('=') ? '<=' : '>=', threshold: 0, actual: parseInt(r.actual) || 0, passed: r.passed })) },
        gate_info: a.gate_info,
        issues: a.issues,
        new_code: { previous_id: 'an-000', counts: a.new_code?.counts ?? { total: 0 }, rating: { security: 'B', reliability: 'A', maintainability: 'B' } },
        measures: { lines: 48520, ncloc: 38200, coverage: 72.4, duplicated_lines_density: 3.2 },
        coverage: { covered_lines: 27650, total_lines: 38200 },
        duplication: { duplicated_lines: 1550, total_lines: 48520, files: 5 },
        rating: a.rating,
      },
      result: {
        target: 'https://github.com/KKloudTarus/synapse-ce.git',
        scan_mode: 'full',
        languages: [{ Name: 'Go', Percent: 58 }, { Name: 'TypeScript', Percent: 24 }, { Name: 'JavaScript', Percent: 12 }, { Name: 'Other', Percent: 6 }],
        sbom: { Components: [] },
        code_quality: { available: true, files_analyzed: 312, rules_evaluated: 142, issues_found: a.issues.total },
      },
    })
  }),
  http.get('/api/v1/projects/:key/analysis-status', () => new HttpResponse(null, { status: 404 })),
  http.get('/api/v1/projects/:key/measures', ({ params, request }) => {
    const p = PROJECTS.find(pr => pr.Key === params.key) ?? PROJECTS[0]
    const url = new URL(request.url)
    const path = url.searchParams.get('path') ?? ''
    const av = (value: number) => ({ availability: 'available', value, unavailable_reason: null })
    const ag = (grade: string) => ({ availability: 'available', grade, unavailable_reason: null })
    const makeNode = (path: string, name: string, kind: string, files: number, ncloc: number, fns: number, cyclo: number, cog: number, cov: number, dupLines: number) => ({
      path, name, kind, language: 'go',
      size: { files: av(files), ncloc: av(ncloc), comment_lines: av(Math.round(ncloc * 0.12)), blank_lines: av(Math.round(ncloc * 0.15)), functions: av(fns), comment_density: av(12.4) },
      complexity: { cyclomatic: av(cyclo), cognitive: av(cog) },
      coverage: { covered_lines: av(Math.round(ncloc * cov / 100)), coverable_lines: av(ncloc), coverage: av(cov), new_code_coverage: av(Math.max(0, cov - 5)) },
      duplication: { duplicated_lines: av(dupLines), duplication_blocks: av(Math.max(1, Math.round(dupLines / 80))), duplication_density: av(+(dupLines / Math.max(1, ncloc) * 100).toFixed(1)) },
      issues: { by_type: { vulnerability: av(3), bug: av(2), code_smell: av(8) }, by_severity: { critical: av(1), high: av(3), medium: av(5), low: av(4) } },
      debt: { remediation_effort_minutes: av(cyclo * 2) },
      ratings: { security: ag('B'), reliability: ag('A'), maintainability: ag('C') },
    })
    const base = { state: 'analyzed' as const, project: { key: p.Key, name: p.Name }, analysis: { id: p.latest_analysis.id, created_at: p.latest_analysis.created_at, source_ref: 'refs/heads/main', source_commit: p.latest_analysis.source_commit }, included_domains: ['size', 'complexity', 'coverage', 'duplication', 'issues', 'debt', 'ratings'] }
    if (path) {
      // Drill-down: return files inside the directory
      const dirName = path.split('/').pop() ?? path
      const fileNames = ['main.go', 'handler.go', 'service.go', 'repository.go', 'types.go']
      return HttpResponse.json({ ...base, path, node: makeNode(path, dirName, 'directory', 5, 2400, 85, 180, 120, 74.0, 45), children: { items: fileNames.map((f, i) => makeNode(`${path}/${f}`, f, 'file', 1, 280 + i * 60, 12 + i * 3, 25 + i * 5, 18 + i * 3, 60 + i * 8, i * 3)), next_cursor: null } })
    }
    return HttpResponse.json({ ...base,
      path: '',
      node: makeNode('', p.Name, 'project', 312, 38200, 1820, 2840, 1950, 72.4, 1550),
      children: { items: [
        makeNode('internal/handlers', 'handlers', 'directory', 45, 9800, 420, 820, 580, 68.5, 205),
        makeNode('internal/usecase', 'usecase', 'directory', 32, 6500, 310, 540, 380, 81.2, 98),
        makeNode('internal/adapter', 'adapter', 'directory', 28, 5400, 240, 380, 260, 76.0, 259),
        makeNode('internal/domain', 'domain', 'directory', 22, 3400, 180, 220, 150, 88.5, 27),
        makeNode('cmd', 'cmd', 'directory', 8, 950, 35, 45, 30, 42.0, 0),
      ], next_cursor: null },
    })
  }),
  http.get('/api/v1/projects/:key/hotspots', () => HttpResponse.json({
    items: Array.from({ length: 8 }, (_, i) => ({
      id: `hs-${String(i + 1).padStart(3, '0')}`,
      rule_key: RULES[i % RULES.length].key,
      rule_name: RULES[i % RULES.length].name,
      title: `Potential ${RULES[i % RULES.length].name.toLowerCase()} detected in this code block`,
      description: `Review this code for potential ${RULES[i % RULES.length].name.toLowerCase()} vulnerability. Ensure proper input validation and sanitization.`,
      severity: (['critical', 'high', 'medium', 'low'])[i % 4],
      finding_kind: 'security_hotspot',
      cwe: RULES[i % RULES.length].cwe,
      location: `internal/handlers/${['user', 'auth', 'scan', 'report', 'asset', 'finding', 'agent', 'rule'][i]}.go:${42 + i * 17}`,
      status: (['to_review', 'acknowledged', 'fixed', 'safe'])[i % 4],
      version: 1,
      first_seen_analysis_id: 'an-001',
      last_seen_analysis_id: 'an-001',
      first_seen_at: new Date(Date.now() - i * 86400_000).toISOString(),
      last_seen_at: new Date(Date.now() - i * 3600_000).toISOString(),
    })),
    next: null,
    facets: { statuses: { to_review: 4, acknowledged: 2, fixed: 1, safe: 1 }, rule_keys: {}, severities: { critical: 2, high: 2, medium: 2, low: 2 } },
    summary: { total: 8, reviewed: 4, reviewed_pct: 50, grade: 'C' },
  })),
  http.get('/api/v1/projects/:key/hotspots/:hotspotId', ({ params }) => {
    const id = params.hotspotId as string
    return HttpResponse.json({
      id,
      rule_key: 'go:S1000',
      rule_name: 'SQL injection',
      title: 'Potential SQL injection detected in query builder',
      description: 'This code constructs a SQL query using string concatenation with user input. Use parameterized queries or prepared statements to prevent SQL injection attacks.',
      severity: 'critical',
      finding_kind: 'security_hotspot',
      cwe: 'CWE-89',
      location: 'internal/handlers/user.go:42',
      status: 'to_review',
      version: 1,
      first_seen_analysis_id: 'an-001',
      last_seen_analysis_id: 'an-001',
      first_seen_at: new Date(Date.now() - 5 * 86400_000).toISOString(),
      last_seen_at: HOUR_AGO,
    })
  }),
  http.get('/api/v1/projects/:key/hotspots/:hotspotId/history', () => HttpResponse.json([
    { actor: 'scanner', status: 'to_review', rationale: 'Detected during initial analysis', version: 1, created_at: new Date(Date.now() - 5 * 86400_000).toISOString() },
  ])),
  http.post('/api/v1/projects/:key/hotspots/:hotspotId/transitions', async ({ request, params }) => {
    const body = await request.json() as { to: string; rationale: string; expected_version: number }
    return HttpResponse.json({
      hotspot: {
        id: params.hotspotId,
        rule_key: 'go:S1000',
        rule_name: 'SQL injection',
        title: 'Potential SQL injection detected in query builder',
        description: 'This code constructs a SQL query using string concatenation with user input.',
        severity: 'critical',
        finding_kind: 'security_hotspot',
        cwe: 'CWE-89',
        location: 'internal/handlers/user.go:42',
        status: body.to,
        version: body.expected_version + 1,
        first_seen_analysis_id: 'an-001',
        last_seen_analysis_id: 'an-001',
        first_seen_at: new Date(Date.now() - 5 * 86400_000).toISOString(),
        last_seen_at: HOUR_AGO,
      },
      event: { actor: 'admin', status: body.to, rationale: body.rationale, version: body.expected_version + 1, created_at: NOW },
    })
  }),
  http.get('/api/v1/projects/:key/issues', () => HttpResponse.json({
    items: Array.from({ length: 12 }, (_, i) => {
      const file = `internal/${['handlers', 'usecase', 'adapter', 'domain'][i % 4]}/${['user', 'scan', 'report', 'finding'][i % 4]}.go`
      const line = 15 + i * 23
      return {
        id: `iss-${String(i + 1).padStart(3, '0')}`,
        rule_key: RULES[i % RULES.length].key,
        rule_name: RULES[i % RULES.length].name,
        type: (['vulnerability', 'bug', 'code_smell'])[i % 3],
        title: `${RULES[i % RULES.length].name} found in ${file.split('/').pop()}`,
        description: `This code may be vulnerable to ${RULES[i % RULES.length].name.toLowerCase()}. Review and apply proper mitigations.`,
        severity: (['critical', 'high', 'medium', 'low', 'info'])[i % 5],
        finding_kind: (['vulnerability', 'bug', 'code_smell'])[i % 3],
        cwe: RULES[i % RULES.length].cwe,
        language: i < 9 ? 'go' : 'typescript',
        file,
        location: `${file}:${line}`,
        status: (['open', 'confirmed', 'resolved', 'reopened', 'accepted'])[i % 5],
        version: 1,
        is_new: i < 5,
        first_seen_analysis_id: 'an-001',
        last_seen_analysis_id: 'an-001',
        first_seen_at: new Date(Date.now() - i * 2 * 86400_000).toISOString(),
        last_seen_at: new Date(Date.now() - i * 3600_000).toISOString(),
      }
    }),
    next: null,
    facets: { statuses: { open: 5, confirmed: 3, resolved: 2, reopened: 1, accepted: 1 }, types: { vulnerability: 4, bug: 4, code_smell: 4 }, severities: { critical: 3, high: 3, medium: 2, low: 2, info: 2 }, languages: { go: 9, typescript: 3 } },
    summary: { total: 12, open: 7, resolved: 2 },
  })),
  http.get('/api/v1/projects/:key/analyses/:analysisId/code/files', () => HttpResponse.json({
    analysis_id: 'an-001',
    head: { ref: 'refs/heads/main', commit: 'a1b2c3d', artifact_digest: 'sha256:abc123' },
    base: null,
    capabilities: { source: true, unified_diff: true, split_diff: false, line_coverage: true },
    files: [
      { path: 'internal/handlers/user.go', status: 'unchanged', language: 'go', lines: 342 },
      { path: 'internal/handlers/auth.go', status: 'unchanged', language: 'go', lines: 285 },
      { path: 'internal/handlers/scan.go', status: 'addition', language: 'go', lines: 156 },
      { path: 'internal/handlers/report.go', status: 'unchanged', language: 'go', lines: 198 },
      { path: 'internal/usecase/sca.go', status: 'unchanged', language: 'go', lines: 412 },
      { path: 'internal/usecase/sast.go', status: 'modification', language: 'go', lines: 523 },
      { path: 'internal/usecase/reachability.go', status: 'unchanged', language: 'go', lines: 267 },
      { path: 'internal/adapter/postgres.go', status: 'unchanged', language: 'go', lines: 380 },
      { path: 'internal/adapter/redis.go', status: 'unchanged', language: 'go', lines: 145 },
      { path: 'internal/adapter/s3.go', status: 'modification', language: 'go', lines: 92 },
      { path: 'cmd/synapse-api/main.go', status: 'unchanged', language: 'go', lines: 78 },
    ],
  })),
  http.get('/api/v1/projects/:key/analyses/:analysisId/code/file', () => HttpResponse.json({
    analysis_id: 'an-001',
    head: { ref: 'refs/heads/main', commit: 'a1b2c3d', artifact_digest: 'sha256:abc123' },
    base: null,
    file: { path: 'internal/handlers/user.go', status: 'unchanged', language: 'go', lines: 342 },
    from_line: 1,
    to_line: 50,
    total_lines: 342,
    lines: Array.from({ length: 50 }, (_, i) => ({
      number: i + 1,
      content: i === 0 ? 'package handlers' : i === 1 ? '' : i === 2 ? 'import (' : i === 3 ? '\t"context"' : i === 4 ? '\t"net/http"' : i === 5 ? ')' : i === 6 ? '' : `// Line ${i + 1}: handler implementation`,
      change: 'unchanged',
      duplicated: false,
      coverage: i > 10 && i < 40 ? 'covered' : i >= 40 ? 'uncovered' : null,
    })),
    findings: [
      { id: 'iss-001', kind: 'issue', rule_key: 'go:S1001', rule_name: 'SQL injection', type: 'vulnerability', severity: 'critical', detection_status: 'open', current_status: null, message: 'Potential SQL injection in query builder', location: { file: 'internal/handlers/user.go', start_line: 42, end_line: 42, start_column: 12, end_column: 45 }, new: true },
    ],
    capabilities: { source: true, unified_diff: true, split_diff: false, line_coverage: true },
  })),
  http.get('/api/v1/projects/:key/analyses/:analysisId/code/diff', () => HttpResponse.json({
    analysis_id: 'an-001',
    head: { ref: 'refs/heads/main', commit: 'a1b2c3d', artifact_digest: 'sha256:abc123' },
    base: { ref: 'refs/heads/main', commit: 'prev123', artifact_digest: 'sha256:def456' },
    file: { path: 'internal/usecase/sast.go', old_path: null, status: 'modification', language: 'go', lines: 523 },
    diff: {
      hunks: [{ old_start: 45, old_lines: 5, new_start: 45, new_lines: 8, header: '@@ -45,5 +45,8 @@', lines: [
        { type: 'context', content: 'func analyzeSAST(ctx context.Context, target string) error {', old_number: 45, new_number: 45 },
        { type: 'deletion', content: '\tresult, err := runScanner(target)', old_number: 46, new_number: null },
        { type: 'addition', content: '\tresult, err := runScannerWithTimeout(ctx, target, 5*time.Minute)', old_number: null, new_number: 46 },
        { type: 'addition', content: '\tif errors.Is(err, context.DeadlineExceeded) {', old_number: null, new_number: 47 },
        { type: 'addition', content: '\t\treturn fmt.Errorf("SAST scan timed out for %s: %w", target, err)', old_number: null, new_number: 48 },
        { type: 'addition', content: '\t}', old_number: null, new_number: 49 },
        { type: 'context', content: '\tif err != nil {', old_number: 47, new_number: 50 },
        { type: 'context', content: '\t\treturn err', old_number: 48, new_number: 51 },
      ] }],
    },
    capabilities: { source: { available: true, reason: null }, comparison: { available: true, reason: null }, unified_diff: { available: true, reason: null }, split_diff: { available: false, reason: 'not supported' }, highlighting: { available: true, reason: null } },
  })),

  // --- Rules ---
  http.get('/api/v1/rules', () => HttpResponse.json(RULES)),
  http.get('/api/v1/rules/:key', ({ params }) => {
    const r = RULES.find(rl => rl.key === params.key) ?? RULES[0]
    return HttpResponse.json({
      ...r,
      description: 'This rule detects potential security vulnerabilities in source code. It analyzes data flow paths to identify tainted inputs reaching sensitive sinks without proper sanitization.',
      rationale: 'Unsanitized user input flowing into security-sensitive operations can lead to injection attacks, data leaks, and unauthorized access.',
      html_description: '<p>Detects potential security issues by tracing data flow from sources to sinks.</p>',
      compliant_example: `// Compliant: parameterized query\nrows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)`,
      noncompliant_example: `// Non-compliant: string concatenation in query\nrows, err := db.Query("SELECT * FROM users WHERE id = " + userID)`,
    })
  }),

  // --- Quality Gates & Profiles ---
  http.get('/api/v1/quality-gates', () => HttpResponse.json(QUALITY_GATES)),
  http.get('/api/v1/quality-profiles', () => HttpResponse.json(QUALITY_PROFILES)),

  // --- Audit ---
  http.get('/api/v1/audit', () => HttpResponse.json(AUDIT_LOG)),
  http.get('/api/v1/audit/verify', () => HttpResponse.json({ intact: true, verified: 25, unchained: 0, head: 'sha256:a4f8c2e91b3d7056ef12dc89ab34fe67cd890123', attestation: { algorithm: 'ed25519', key_id: 'prod-signing-key-01' } })),

  // --- Team ---
  http.get('/api/v1/users', () => HttpResponse.json(TEAM_MEMBERS)),
  http.post('/api/v1/users', async ({ request }) => {
    const body = await request.json() as { name: string; role: string }
    const newUser = { id: `user-${String(TEAM_MEMBERS.length + 1).padStart(3, '0')}`, name: body.name, role: body.role, disabled: false, createdAt: NOW }
    TEAM_MEMBERS.push(newUser as any)
    return HttpResponse.json({ user: newUser, apiKey: `syn_${Math.random().toString(36).slice(2, 18)}_${Math.random().toString(36).slice(2, 10)}` })
  }),

  // --- Catch-all fallback ---
  http.get('/api/v1/*', ({ request }) => {
    console.warn('[MSW] Unhandled GET:', new URL(request.url).pathname)
    return HttpResponse.json({ error: 'Not mocked' }, { status: 404 })
  }),
  http.post('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.patch('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.delete('/api/v1/*', () => HttpResponse.json({ ok: true })),
  http.put('/api/v1/*', () => HttpResponse.json({ ok: true })),
]
