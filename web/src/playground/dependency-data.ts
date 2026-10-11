// The graph, summary and exported components are projections of the same small inventory.
export function demoDependencies(analysisId: string) {
  const rows = [
    ['github.com/gin-gonic/gin', '1.9.1', 'golang', 'MIT', 'high'],
    ['golang.org/x/net', '0.17.0', 'golang', 'BSD-3-Clause', 'medium'],
    ['react', '18.2.0', 'npm', 'MIT', ''],
    ['lodash', '4.17.20', 'npm', 'MIT', 'critical'],
    ['PyYAML', '5.3.1', 'pypi', 'MIT', 'high'],
    ['org.slf4j/slf4j-api', '2.0.9', 'maven', 'MIT', ''],
  ]
  const nodes = rows.map(([name, version, ecosystem, license, severity], i) => ({ id: `demo-pkg-${i}`, name, version, purl: `pkg:${ecosystem}/${name}@${version}`, scope: 'runtime', reachability: i === 3 ? 'reachable' : 'unknown', direct: i !== 1, depth: i === 1 ? 1 : 0, synthetic: false, licenses: [{ id: license, name: license, category: 'permissive' }], license_risk: false, license_verdict: 'allowed', vulnerabilities: severity ? [{ id: `DEMO-DEPENDENCY-${i + 1}`, source: 'Synthetic advisory', severity, fixed_version: i === 3 ? '4.17.21' : '' }] : [], vulnerability_count: severity ? 1 : 0, worst_severity: severity }))
  return { analysis_id: analysisId, roots: nodes.filter(n => n.direct).map(n => n.id), nodes, edges: [{ from: 'demo-pkg-0', to: 'demo-pkg-1' }], summary: { components: nodes.length, direct: nodes.filter(n => n.direct).length, transitive: 1, vulnerable: nodes.filter(n => n.vulnerability_count).length, license_risk: 0, edges: 1 } }
}
