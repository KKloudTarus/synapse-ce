// Synthetic defensive training cases; all counts are derived from these records.
export const LANGUAGES = [
  { Name: 'TypeScript', Percent: 35 }, { Name: 'Go', Percent: 25 },
  { Name: 'Python', Percent: 20 }, { Name: 'Java', Percent: 10 }, { Name: 'JavaScript', Percent: 10 },
]
export const RUNTIME_PACKAGES = [
  { name: 'openssl', version: '3.0.15', purl: 'pkg:deb/debian/openssl@3.0.15' },
  { name: 'nodejs', version: '22.11.0', purl: 'pkg:generic/nodejs@22.11.0' },
  { name: 'python', version: '3.12.7', purl: 'pkg:generic/python@3.12.7' },
  { name: 'openjdk', version: '21.0.5', purl: 'pkg:generic/openjdk@21.0.5' },
  { name: 'checkout-session', version: '1.4.3', purl: 'pkg:golang/checkout-session@1.4.3' },
  { name: 'ca-certificates', version: '20240203', purl: 'pkg:deb/debian/ca-certificates@20240203' },
]
export const WORKLOADS = ['checkout-api', 'payment-worker', 'session-service'].map((name, i) => ({
  cluster: 'training-cluster', namespace: 'checkout', kind: 'Deployment', name, service_account: name,
  images: [{ ref: `registry.example/${name}:training`, digest: `sha256:${String(i + 1).repeat(64)}` }],
}))
export const DETECTIONS = [
  { rule: 'unexpected_file_access', class: 'file', severity: 'high', title: 'Unexpected configuration file access', count: 3, risk: 72, confidence: 85, evidence: 'Synthetic access to a training configuration file by the checkout workload.' },
  { rule: 'privilege_boundary_change', class: 'privilege', severity: 'critical', title: 'Unexpected privilege boundary change', count: 2, risk: 94, confidence: 96, evidence: 'Synthetic privilege transition outside the recorded workload policy.' },
  { rule: 'unapproved_network_destination', class: 'network', severity: 'medium', title: 'Unapproved outbound destination', count: 4, risk: 48, confidence: 78, evidence: 'Synthetic connection metadata references a destination outside the training allowlist.' },
  { rule: 'unexpected_child_process', class: 'process', severity: 'low', title: 'Unexpected maintenance child process', count: 1, risk: 24, confidence: 68, evidence: 'Synthetic maintenance process requires an analyst to confirm its deployment context.' },
  { rule: 'workload_baseline_change', class: 'process', severity: 'info', title: 'Workload baseline changed', count: 2, risk: 8, confidence: 99, evidence: 'Synthetic informational observation records a new training build identity.' },
]
export const AI_CASES = [
  { title: 'Unsafe query pattern in a TypeScript test fixture', severity: 'medium', cwe: 'CWE-89', language: 'typescript', file: 'tests/fixtures/query.ts:18', confidence: 94, verifierConfidence: 90, agrees: true, driver: 'test_or_example_code', risk: 35, description: 'The query appears only in a fixed-data TypeScript test fixture excluded from production builds. Review that boundary before accepting the false-positive proposal.' },
  { title: 'Unvalidated user lookup in Go production code', severity: 'high', cwe: 'CWE-89', language: 'go', file: 'services/session/lookup.go:42', confidence: 62, verifierConfidence: 93, agrees: false, driver: 'input_sanitized', risk: 75, description: 'The Go production lookup has no recorded validation or parameter binding. The proposer suggests a false positive; the independent verifier disagrees. Retain the finding and assign remediation.' },
  { title: 'Directory boundary missing in a Python export worker', severity: 'critical', cwe: 'CWE-22', language: 'python', file: 'services/worker/export.py:63', confidence: 58, verifierConfidence: 97, agrees: false, driver: 'trusted_input', risk: 92, description: 'The Python worker lacks evidence of an approved directory boundary. The verifier disputes the trusted-input assumption. This proposal remains pending for a separate human review.' },
  { title: 'Legacy digest in a Java cache key', severity: 'low', cwe: 'CWE-327', language: 'java', file: 'services/payment/CacheKey.java:27', confidence: 89, verifierConfidence: 86, agrees: true, driver: 'non_security_context', risk: 20, description: 'The Java digest labels cached public assets. Both models propose a non-security context; a human must verify that context before accepting an exemption.' },
  { title: 'Diagnostic detail in a JavaScript training page', severity: 'info', cwe: 'CWE-209', language: 'javascript', file: 'web/training/diagnostics.js:12', confidence: 97, verifierConfidence: 95, agrees: true, driver: 'test_or_example_code', risk: 5, description: 'The JavaScript diagnostic page is a training-only fixture. The informational finding remains pending until a reviewer verifies its build exclusion.' },
]
export const QUALITY_ISSUES = [
  { title: 'Duplicated checkout validation', type: 'code_smell', severity: 'medium', language: 'typescript', file: 'src/checkout.ts', line: 24, cwe: '', description: 'Consolidate duplicated input validation and add regression tests.' },
  { title: 'Unvalidated query parameters', type: 'vulnerability', severity: 'critical', language: 'go', file: 'services/session/lookup.go', line: 42, cwe: 'CWE-89', description: 'The production lookup needs parameter binding. Evaluate the fix in a revised analysis.' },
  { title: 'Unhandled payment failure', type: 'bug', severity: 'high', language: 'java', file: 'services/payment/PaymentService.java', line: 64, cwe: '', description: 'Return an explicit payment failure and cover the error path with regression tests.' },
  { title: 'Export path lacks an approved root', type: 'vulnerability', severity: 'critical', language: 'python', file: 'services/worker/export.py', line: 63, cwe: 'CWE-22', description: 'Resolve export paths against the approved directory and verify the boundary.' },
  { title: 'Receipt output lacks contextual encoding', type: 'vulnerability', severity: 'high', language: 'javascript', file: 'web/receipts/render.js', line: 37, cwe: 'CWE-79', description: 'Encode rendered output for its destination context and add rendering tests.' },
  { title: 'Worker retry can skip cleanup', type: 'bug', severity: 'medium', language: 'python', file: 'services/worker/retry.py', line: 51, cwe: '', description: 'Run cleanup on both successful and failed retry paths.' },
  { title: 'Unnecessary temporary slice allocation', type: 'code_smell', severity: 'low', language: 'go', file: 'services/session/cache.go', line: 28, cwe: '', description: 'Remove the temporary allocation while preserving cache behavior.' },
  { title: 'Unused payment validation branch', type: 'code_smell', severity: 'low', language: 'java', file: 'services/payment/Validator.java', line: 33, cwe: '', description: 'Remove the unreachable branch and document the supported validation path.' },
  { title: 'Redundant checkout type annotation', type: 'code_smell', severity: 'info', language: 'typescript', file: 'src/checkout/types.ts', line: 15, cwe: '', description: 'Use the existing inferred type to reduce duplicate maintenance.' },
  { title: 'Stale diagnostic comment', type: 'code_smell', severity: 'info', language: 'javascript', file: 'web/training/diagnostics.js', line: 10, cwe: '', description: 'Update the comment to describe the current training-only behavior.' },
]
export const QUALITY_HOTSPOTS = [
  { title: 'Review checksum use in asset caching', severity: 'medium', language: 'typescript', file: 'src/cache/checksum.ts', line: 24, cwe: 'CWE-327', description: 'The digest detects changes in cached public assets. It is not used for passwords, signatures or security decisions. Record the reviewed context before marking Safe.' },
  { title: 'Review TLS verification in the session client', severity: 'high', language: 'go', file: 'services/session/client.go', line: 48, cwe: 'CWE-295', description: 'Confirm that the production client verifies certificates. The improved revision removes the training override and records this hotspot as Fixed.' },
  { title: 'Review worker diagnostic logging', severity: 'low', language: 'python', file: 'services/worker/logging.py', line: 29, cwe: 'CWE-532', description: 'Review which request fields can reach diagnostic logs. The improved revision redacts sensitive fields and records this hotspot as Fixed.' },
]
export function counts<T extends object>(rows: T[], key: keyof T) {
  const result: Record<string, number> = {}
  for (const row of rows) { const value = String(row[key]); result[value] = (result[value] ?? 0) + 1 }
  return result
}
