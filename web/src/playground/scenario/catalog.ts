// Synthetic training records. No real advisory, credential or exploit payload is included.
export const DEMO_PACKAGES = [
  { name: 'checkout-parser', ecosystem: 'npm', location: 'package-lock.json', version: '1.0.0', fixed: '1.1.0', license: 'MIT', dependencies: ['checkout-path', 'checkout-archive'] },
  { name: 'checkout-serializer', ecosystem: 'npm', location: 'package-lock.json', version: '1.0.0', fixed: '1.1.0', license: 'Apache-2.0', dependencies: ['checkout-template'] },
  { name: 'checkout-template', ecosystem: 'npm', location: 'package-lock.json', version: '1.0.0', fixed: '1.1.0', license: 'MIT', dependencies: [] },
  { name: 'checkout-token', ecosystem: 'npm', location: 'package-lock.json', version: '2.0.0', fixed: '2.0.0', license: 'MIT', dependencies: [] },
  { name: 'checkout-http', ecosystem: 'pypi', location: 'services/worker/poetry.lock', version: '3.0.0', fixed: '3.0.2', license: 'Apache-2.0', dependencies: ['checkout-logging'] },
  { name: 'checkout-path', ecosystem: 'npm', location: 'package-lock.json', version: '2.1.0', fixed: '2.1.1', license: 'BSD-3-Clause', dependencies: [] },
  { name: 'checkout-archive', ecosystem: 'npm', location: 'package-lock.json', version: '4.0.0', fixed: '4.2.0', license: 'MIT', dependencies: [] },
  { name: 'checkout-session', ecosystem: 'golang', location: 'services/session/go.sum', version: '1.4.0', fixed: '1.4.3', license: 'BSD-3-Clause', dependencies: [] },
  { name: 'checkout-logging', ecosystem: 'pypi', location: 'services/worker/poetry.lock', version: '2.0.0', fixed: '2.0.1', license: 'MIT', dependencies: [] },
  { name: 'checkout-metrics', ecosystem: 'maven', location: 'services/payment/pom.xml', version: '1.2.0', fixed: '1.2.0', license: 'Apache-2.0', dependencies: [] },
  { name: 'checkout-export', ecosystem: 'npm', location: 'package-lock.json', version: '1.0.0', fixed: '1.1.0', license: 'GPL-3.0-only', dependencies: [] },
  { name: 'checkout-helper', ecosystem: 'npm', location: 'package-lock.json', version: '0.9.0', fixed: '1.0.0', license: '', dependencies: [] },
]
export interface DemoIssue {
  title: string; kind: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; cwe?: string
  location: string; remediation: string; packageIndex?: number; advisory?: string; direct?: boolean
}
const dependency = (packageIndex: number, advisory: string, title: string, severity: DemoIssue['severity'], cwe: string, direct = true): DemoIssue => ({
  packageIndex, advisory, title, severity, cwe, direct, kind: 'vulnerability', location: DEMO_PACKAGES[packageIndex].location,
  remediation: `Upgrade ${DEMO_PACKAGES[packageIndex].name} to ${DEMO_PACKAGES[packageIndex].fixed} and verify the same dependency path in the Re-test.`,
})
export const DEMO_ISSUES: DemoIssue[] = [
  dependency(0, 'DEMO-CHECKOUT-001', 'simulated vulnerable dependency', 'critical', 'CWE-502'),
  dependency(1, 'DEMO-CHECKOUT-002', 'unsafe object merging', 'high', 'CWE-1321'),
  dependency(2, 'DEMO-CHECKOUT-003', 'unescaped template output', 'medium', 'CWE-79'),
  dependency(4, 'DEMO-CHECKOUT-005', 'redirect validation weakness', 'high', 'CWE-918'),
  dependency(5, 'DEMO-CHECKOUT-006', 'path normalization weakness', 'high', 'CWE-22', false),
  dependency(6, 'DEMO-CHECKOUT-007', 'archive extraction boundary missing', 'high', 'CWE-22', false),
  dependency(7, 'DEMO-CHECKOUT-008', 'session lifetime validation missing', 'medium', 'CWE-613'),
  dependency(8, 'DEMO-CHECKOUT-009', 'sensitive fields included in logs', 'low', 'CWE-532', false),
  { title: 'SQL query assembled from request data', kind: 'sast', severity: 'critical', cwe: 'CWE-89', location: 'src/orders/repository.ts:42', remediation: 'Use parameterized queries and validate the expected input shape.' },
  { title: 'Unescaped HTML in receipt rendering', kind: 'sast', severity: 'high', cwe: 'CWE-79', location: 'services/payment/ReceiptRenderer.java:67', remediation: 'Use contextual output encoding and a template engine with automatic escaping.' },
  { title: 'File lookup lacks a directory boundary', kind: 'sast', severity: 'high', cwe: 'CWE-22', location: 'services/session/download.go:31', remediation: 'Resolve paths against an approved root and enforce that boundary.' },
  { title: 'Outbound URL lacks destination validation', kind: 'sast', severity: 'medium', cwe: 'CWE-918', location: 'services/worker/webhooks.py:58', remediation: 'Allow approved destinations and reject private network addresses.' },
  { title: 'Credential-like value in application configuration', kind: 'secret', severity: 'critical', cwe: 'CWE-798', location: 'config/checkout.env:12', remediation: 'Remove the redacted training placeholder and load credentials from the secret manager. Revoke and rotate a real exposed credential.' },
  { title: 'Credential-like value in a test fixture', kind: 'secret', severity: 'medium', cwe: 'CWE-798', location: 'tests/fixtures/service-account.json:8', remediation: 'Replace the redacted training placeholder with an explicit non-secret fixture.' },
  { title: 'Storage policy permits public reads', kind: 'misconfig', severity: 'high', cwe: 'CWE-732', location: 'infra/storage.tf:24', remediation: 'Restrict storage access to the application identity and enable public access blocking.' },
  { title: 'Container enables privileged execution', kind: 'misconfig', severity: 'high', cwe: 'CWE-250', location: 'deploy/checkout.yaml:36', remediation: 'Disable privileged mode and restrict the container security context.' },
  { title: 'Copyleft dependency needs policy review', kind: 'license', severity: 'medium', packageIndex: 10, location: 'package-lock.json', remediation: 'Review distribution obligations with the owner. This demo replaces the dependency with an approved MIT-licensed version.' },
  { title: 'Dependency license metadata is missing', kind: 'license', severity: 'info', packageIndex: 11, location: 'package-lock.json', remediation: 'Obtain license provenance before approving the dependency. The Re-test records an approved MIT license.' },
]
export const CORE_PHASES = [
  { stage: 'acquiring target', title: 'Acquire the source revision', engine: 'inventory', why: 'The authorized Git revision defines the source boundary. The demo materializes a simulated revision without cloning a repository.' },
  { stage: 'detecting languages', title: 'Detect languages and manifests', engine: 'inventory', why: 'Language and manifest detection identifies TypeScript, JavaScript, Python, Go and Java source, plus Terraform and Kubernetes configuration.' },
  { stage: 'generating SBOM', title: 'Resolve the dependency inventory', engine: 'dependency_resolution', why: 'Lockfiles pin package versions and dependency edges. The SBOM supplies stable package identities for later matching and monitoring.' },
  { stage: 'scanning vulnerabilities', title: 'Match dependency advisories', engine: 'sca', why: 'SCA matches package identities and versions to eight synthetic advisories, including direct and transitive dependencies.' },
  { stage: 'analyzing source', title: 'Analyze source code', engine: 'sast', why: 'SAST identifies four source issues with file locations and CWE classifications. A source finding needs its own review, separate from a package advisory.' },
  { stage: 'scanning secrets', title: 'Inspect credential exposure', engine: 'secrets', why: 'Secret scanning identifies two credential-like placeholders. The demo displays only redacted descriptions and never includes usable credentials.' },
  { stage: 'scanning configuration', title: 'Evaluate infrastructure configuration', engine: 'iac', why: 'IaC analysis identifies public storage access and privileged container execution in the recorded configuration.' },
  { stage: 'scanning licenses', title: 'Evaluate license policy', engine: 'licenses', why: 'License analysis distinguishes approved permissive licenses, a copyleft review and missing metadata. License policy is independent of vulnerability severity.' },
  { stage: 'prioritizing risk', title: 'Prioritize and correlate findings', engine: '', why: 'Correlation retains issue identity, severity, source and evidence. Priorities help the reviewer decide what to investigate first; they do not prove exploitability.' },
  { stage: 'deriving findings', title: 'Finalize findings and provenance', engine: '', why: 'The scan records eighteen findings, engine coverage and evidence. Results become available only after finalization; success alone does not establish complete coverage.' },
]
export const PHASE_DURATION = 1800
export const SCAN_DURATION = CORE_PHASES.length * PHASE_DURATION
export const SEVERITY_RISK = { critical: 9, high: 7, medium: 5, low: 2, info: 1 }
