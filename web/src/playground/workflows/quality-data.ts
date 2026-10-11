import { PROJECT_CODE_SOURCE_WINDOW } from '../../lib/projectCodeNavigation'
import { DEMO_ISSUES, DEMO_PACKAGES } from '../scenario/catalog'
import { LANGUAGES, QUALITY_HOTSPOTS, QUALITY_ISSUES, counts } from './catalog'
import { analysis, qualityIssue } from './data'
import { PROJECT_KEY, type QualityAnalysis, type QualityState } from './store'

// Retained training excerpts, not executable copies of a vulnerable repository.
// Unsafe expressions are redacted; revision identity and finding locations stay pinned.
const snippets: Record<string, string[]> = {
  typescript: ['export function validateQuantity(value: number): boolean {', '  return Number.isInteger(value) && value > 0 && value <= 100;', '}'],
  go: ['func ValidQuantity(value int) bool {', '\treturn value > 0 && value <= 100', '}'],
  python: ['def valid_quantity(value: int) -> bool:', '    return isinstance(value, int) and 0 < value <= 100'],
  java: ['static boolean validQuantity(int value) {', '    return value > 0 && value <= 100;', '}'],
  javascript: ['export function validQuantity(value) {', '  return Number.isInteger(value) && value > 0 && value <= 100;', '}'],
}
const reviewSnippets: Record<string, string[]> = {
  'src/checkout.ts': ['export function checkoutQuantity(value: number): number {', '  if (!Number.isInteger(value) || value < 1 || value > 100) {', '    throw new RangeError("Quantity must be between 1 and 100.");', '  }', '  return value;', '}'],
  'services/session/lookup.go': ['func Lookup(ctx context.Context, db *sql.DB, id int64) *sql.Row {', '\treturn db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = $1", id)', '}'],
  'services/payment/PaymentService.java': ['PaymentResult process(PaymentRequest request) {', '    try {', '        return gateway.charge(request);', '    } catch (PaymentDeclinedException error) {', '        return PaymentResult.declined();', '    }', '}'],
  'services/worker/export.py': ['def approved_export_path(root: Path, name: str) -> Path:', '    base = root.resolve()', '    candidate = (base / name).resolve()', '    if not candidate.is_relative_to(base):', '        raise ValueError("Export path is outside the approved root")', '    return candidate'],
  'web/receipts/render.js': ['export function renderReceipt(container, receipt) {', '  const label = document.createElement("span");', '  label.textContent = String(receipt.reference);', '  container.replaceChildren(label);', '}'],
  'services/worker/retry.py': ['def run_with_cleanup(operation, resource):', '    try:', '        return operation(resource)', '    finally:', '        resource.close()'],
  'services/session/cache.go': ['func CopyKeys(destination, keys []string) []string {', '\treturn append(destination, keys...)', '}'],
  'services/payment/Validator.java': ['boolean validAmount(BigDecimal amount) {', '    return amount != null && amount.signum() > 0;', '}'],
  'src/checkout/types.ts': ['export const createCheckout = (quantity: number) => ({ quantity });', 'export type Checkout = ReturnType<typeof createCheckout>;'],
  'web/training/diagnostics.js': ['// Diagnostic output is restricted to the training build.', 'export function showDiagnostics(isTraining, summary) {', '  if (isTraining) console.debug(summary.count);', '}'],
  'src/cache/checksum.ts': ['// The digest identifies public cached content.', 'export function cacheKey(content: string): string {', '  return createHash("sha256").update(content).digest("hex");', '}'],
  'services/session/client.go': ['func SessionClient() *http.Client {', '\treturn &http.Client{', '\t\tTimeout: 10 * time.Second,', '\t\tTransport: &http.Transport{', '\t\t\tTLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},', '\t\t},', '\t}', '}'],
  'services/worker/logging.py': ['def record_export(logger, job):', '    logger.info(', '        "Export completed",', '        extra={"job_id": job.id, "status": job.status},', '    )'],
}
const records = [...QUALITY_ISSUES, ...QUALITY_HOTSPOTS]
const sourceFiles = [
  ...records.map(c => ({ path: c.file, language: c.language, line: c.line, note: c.description })),
  ...records.map((c, i) => ({ path: `tests/${c.language}/case-${i + 1}.${c.file.split('.').at(-1)}`, language: c.language, line: 8, note: `Regression coverage: ${c.title}.` })),
  { path: 'src/quantity.ts', language: 'typescript', line: 8, note: 'Shared quantity validation boundary.' },
  { path: 'web/quantity.js', language: 'javascript', line: 8, note: 'Client quantity validation boundary.' },
]
const comment = (language: string) => language === 'python' ? '#' : '//'
function contents(file: typeof sourceFiles[number], a: QualityAnalysis) {
  const prefix = comment(file.language)
  const lines = [`${prefix} Synapse training excerpt: ${file.path}`, `${prefix} Recorded unsafe expressions are redacted.`, `${prefix} Revision: ${a.ref}`]
  while (lines.length < file.line - 1) lines.push('')
  lines.push(`${prefix} ${a.ref === 'main' ? 'Review boundary' : 'Verified remediation'}: ${file.note}`,
    `${prefix} Defensive reference implementation; findings are recorded simulation data.`, ...(reviewSnippets[file.path] ?? snippets[file.language]))
  return lines
}
const revision = (a: QualityAnalysis) => ({ ref: `refs/heads/${a.ref}`, commit: analysis(a).source_commit, artifact_digest: `demo-source-${a.ref}` })
const capabilities = (a: QualityAnalysis) => ({ source: true, unified_diff: a.ref === 'improved', split_diff: false, line_coverage: true })
function findings(s: QualityState, a: QualityAnalysis, path: string) {
  return records.flatMap((c, index) => {
    const hotspot = index >= QUALITY_ISSUES.length, i = hotspot ? index - QUALITY_ISSUES.length : index
    if (c.file !== path || !hotspot && a.ref === 'improved') return []
    const row = qualityIssue(s, i, hotspot, a)
    return [{ id: row.id, kind: hotspot ? 'hotspot' : 'issue', rule_key: row.rule_key, rule_name: c.title, type: row.type, severity: c.severity,
      detection_status: row.status === 'fixed' ? 'fixed' : 'detected', current_status: row.status, message: c.description,
      location: { file: path, start_line: c.line, end_line: c.line }, new: a.ref === 'main' }]
  })
}
function fileMetadata(s: QualityState, a: QualityAnalysis, file: typeof sourceFiles[number]) {
  return { path: file.path, old_path: null, status: a.ref === 'improved' ? 'modified' : 'unchanged', language: file.language,
    lines: contents(file, a).length, finding_count: findings(s, a, file.path).length, changed_line_count: a.ref === 'improved' ? 2 : 0,
    binary: false, generated: false, source_available: true, source_reason: null }
}
function codeContext(a: QualityAnalysis) {
  return { analysis_id: a.id, head: revision(a), base: a.ref === 'improved' ? { ref: 'refs/heads/main', commit: 'a1b2c3d', artifact_digest: 'demo-source-main' } : null, capabilities: capabilities(a) }
}
export function qualityCodeIndex(s: QualityState, a: QualityAnalysis) {
  return { ...codeContext(a), files: sourceFiles.map(file => fileMetadata(s, a, file)) }
}
export function qualityCodeFile(s: QualityState, a: QualityAnalysis, path: string, from: number) {
  const file = sourceFiles.find(file => file.path === path)
  if (!file) return null
  const lines = contents(file, a), end = Math.min(from + PROJECT_CODE_SOURCE_WINDOW - 1, lines.length)
  return { ...codeContext(a), file: fileMetadata(s, a, file), from_line: from, to_line: end, total_lines: lines.length,
    lines: lines.slice(from - 1, end).map((content, i) => ({ number: from + i, content, change: a.ref === 'improved' && [3, file.line].includes(from + i) ? 'addition' : 'unchanged',
      duplicated: a.ref === 'main' && path === QUALITY_ISSUES[0].file && from + i > file.line, coverage: content && !content.startsWith(comment(file.language)) ? 'covered' : null })),
    findings: findings(s, a, path) }
}
export function qualityCodeDiff(a: QualityAnalysis, path: string) {
  const file = sourceFiles.find(file => file.path === path)
  if (!file || a.ref !== 'improved') return null
  const base = contents(file, { ...a, ref: 'main' }), head = contents(file, a)
  const rows = head.flatMap<{ kind: string; old_line: number | null; new_line: number | null; text: string; no_final_newline: boolean }>((text, i) => base[i] === text
    ? [{ kind: 'context', old_line: i + 1, new_line: i + 1, text, no_final_newline: false }]
    : [{ kind: 'removed', old_line: i + 1, new_line: null, text: base[i], no_final_newline: false }, { kind: 'added', old_line: null, new_line: i + 1, text, no_final_newline: false }])
  const available = { available: true, reason: null }
  return { capabilities: { source: available, comparison: available, unified_diff: available, split_diff: { available: false, reason: 'Split diff is not retained in this training snapshot.' }, highlighting: available },
    diff: { ...codeContext(a), path, view: 'unified', context_truncated: false, change: { old_path: path, new_path: path, status: 'modified', binary: false, mode_old: '100644', mode_new: '100644', hunks: [{ old_start: 1, old_lines: base.length, new_start: 1, new_lines: head.length, rows }] } } }
}

export function qualityDependencyGraph(a: QualityAnalysis) {
  const childNames = new Set(DEMO_PACKAGES.flatMap(p => p.dependencies))
  const nodes = DEMO_PACKAGES.map((p, i) => {
    const vulnerabilities = DEMO_ISSUES.filter(issue => issue.advisory && issue.packageIndex === i).map(issue => ({ id: issue.advisory!, severity: issue.severity, source: 'training', fixed_version: p.fixed }))
    const licenseRisk = !p.license || p.license === 'GPL-3.0-only'
    return { id: `pkg:${p.ecosystem}/${p.name}@${p.version}`, purl: `pkg:${p.ecosystem}/${p.name}@${p.version}`, name: p.name, version: p.version,
      scope: 'required', reachability: 'unknown', direct: !childNames.has(p.name), depth: childNames.has(p.name) ? 1 : 0, synthetic: false,
      licenses: p.license ? [{ id: p.license, name: p.license, category: licenseRisk ? 'strong_copyleft' : 'permissive' }] : [],
      license_risk: licenseRisk, license_verdict: licenseRisk ? 'review' : 'allow', vulnerabilities, vulnerability_count: vulnerabilities.length, worst_severity: vulnerabilities[0]?.severity ?? '' }
  })
  const edges = DEMO_PACKAGES.flatMap((p, i) => p.dependencies.map(name => ({ from: nodes[i].id, to: nodes[DEMO_PACKAGES.findIndex(child => child.name === name)].id })))
  // Quality re-analysis changes source quality; dependency upgrades belong to Code Security.
  return { analysis_id: a.id, roots: nodes.filter(n => n.direct).map(n => n.id), nodes, edges,
    summary: { components: nodes.length, direct: nodes.filter(n => n.direct).length, transitive: nodes.filter(n => !n.direct).length, vulnerable: nodes.filter(n => n.vulnerability_count).length, license_risk: nodes.filter(n => n.license_risk).length, edges: edges.length } }
}
export function qualityDependencyExport(a: QualityAnalysis, root: string) {
  const graph = qualityDependencyGraph(a)
  if (root && !graph.nodes.some(n => n.id === root)) return null
  const retained = new Set(root ? [root] : graph.nodes.map(n => n.id))
  if (root) for (const id of retained) for (const edge of graph.edges) if (edge.from === id) retained.add(edge.to)
  return { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { properties: [{ name: 'synapse:training', value: 'true' }, { name: 'synapse:analysis', value: a.id }] },
    components: graph.nodes.filter(n => retained.has(n.id)).map(n => ({ type: 'library', 'bom-ref': n.id, name: n.name, version: n.version, purl: n.purl, licenses: n.licenses.map(l => ({ license: { id: l.id } })) })),
    dependencies: graph.nodes.filter(n => retained.has(n.id)).map(n => ({ ref: n.id, dependsOn: graph.edges.filter(e => e.from === n.id && retained.has(e.to)).map(e => e.to) })) }
}

const metric = (value: number) => ({ availability: 'available', value, unavailable_reason: null })
const grade = (value: string) => ({ availability: 'available', grade: value, unavailable_reason: null })
function allocate(total: number, weights: number[]) {
  const sum = weights.reduce((n, value) => n + value, 0)
  const values = weights.map(weight => Math.floor(total * weight / sum))
  for (let i = 0, remainder = total - values.reduce((n, value) => n + value, 0); i < remainder; i++) values[i]++
  return values
}
export function qualityMeasures(s: QualityState, a: QualityAnalysis, path = '') {
  const improved = a.ref === 'improved', snapshot = analysis(a)
  const sizes = sourceFiles.map(() => 0)
  for (const language of LANGUAGES) {
    const indices = sourceFiles.flatMap((file, i) => file.language === language.Name.toLowerCase() ? [i] : [])
    const share = allocate(language.Percent * 10, indices.map(() => 1))
    indices.forEach((index, i) => { sizes[index] = share[i] })
  }
  const covered = allocate(snapshot.coverage.covered_lines, sizes), duplicated = allocate(snapshot.duplication.duplicated_lines, sizes)
  const blanks = allocate(snapshot.measures.lines - snapshot.measures.ncloc - sourceFiles.length * 5, sizes)
  const files = sourceFiles.map((file, i) => ({ ...file, ncloc: sizes[i], covered: covered[i], duplicated: duplicated[i], blanks: blanks[i] }))
  const descendants = (p: string) => files.filter(f => !p || f.path === p || f.path.startsWith(`${p}/`))
  const selected = descendants(path)
  if (!selected.length) return null
  function node(p: string) {
    const rows = descendants(p), sum = (key: 'ncloc' | 'covered' | 'duplicated' | 'blanks') => rows.reduce((n, row) => n + row[key], 0)
    const issueRows = improved ? [] : QUALITY_ISSUES.filter(issue => rows.some(row => row.path === issue.file))
    const ncloc = sum('ncloc'), byType = counts(issueRows, 'type'), bySeverity = counts(issueRows, 'severity')
    return { path: p, name: p ? p.split('/').at(-1) : s.project?.name, kind: !p ? 'project' : files.some(file => file.path === p) ? 'file' : 'directory', language: rows.length === 1 ? rows[0].language : '',
      size: { files: metric(rows.length), ncloc: metric(ncloc), comment_lines: metric(rows.length * 5), blank_lines: metric(sum('blanks')), functions: metric(rows.length), comment_density: metric(100 * rows.length * 5 / (ncloc + rows.length * 5)) },
      coverage: { covered_lines: metric(sum('covered')), coverable_lines: metric(ncloc), coverage: metric(100 * sum('covered') / ncloc), new_code_coverage: metric(100 * sum('covered') / ncloc) },
      duplication: { duplicated_lines: metric(sum('duplicated')), duplication_blocks: metric(rows.filter(row => row.duplicated > 0).length), duplication_density: metric(100 * sum('duplicated') / ncloc) },
      issues: { by_type: Object.fromEntries(['vulnerability', 'bug', 'code_smell'].map(key => [key, metric(byType[key] ?? 0)])), by_severity: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map(key => [key, metric(bySeverity[key] ?? 0)])) },
      debt: { remediation_effort_minutes: metric(issueRows.length * 20) }, ratings: { security: grade(issueRows.some(r => r.type === 'vulnerability') ? 'D' : 'A'), reliability: grade(issueRows.some(r => r.type === 'bug') ? 'C' : 'A'), maintainability: grade(issueRows.some(r => r.type === 'code_smell') ? 'C' : 'A') } }
  }
  const children = [...new Set(selected.filter(f => f.path !== path).map(f => {
    const rest = path ? f.path.slice(path.length + 1) : f.path
    return [path, rest.split('/')[0]].filter(Boolean).join('/')
  }))].sort()
  return { state: 'analyzed', project: { key: PROJECT_KEY, name: s.project?.name }, analysis: snapshot, path,
    included_domains: ['size', 'coverage', 'duplication', 'issues', 'debt', 'ratings'], node: node(path), children: { items: children.map(node), next_cursor: null } }
}
export function qualityBehavioralHotspots(s: QualityState, a: QualityAnalysis, path: string) {
  return { project: { key: PROJECT_KEY, name: s.project?.name }, analysis: analysis(a), path, availability: 'unavailable',
    unavailable_reason: 'Git history is not retained in this training snapshot.', items: [] }
}
