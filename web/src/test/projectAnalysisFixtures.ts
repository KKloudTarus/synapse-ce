import type { Finding, LatestProjectAnalysis } from '../lib/types'

export function buildLatestProjectAnalysis(
  options: { id?: string; findings?: Finding[]; sourceRef?: string } = {},
): LatestProjectAnalysis {
  const id = options.id ?? 'analysis-1'
  const findings = options.findings ?? [
    buildFinding('sast-finding', 'SAST security finding', 'sast', 'high'),
    buildFinding('reliability-finding', 'Reliability finding', 'reliability', 'medium'),
    buildFinding('quality-finding', 'Maintainability finding', 'quality', 'low'),
    buildFinding('threat-finding', 'Threat model finding', 'threat', 'critical'),
  ]
  const counts = {
    total: findings.length,
    byKind: Object.fromEntries(findings.map((finding) => [finding.kind, findings.filter((item) => item.kind === finding.kind).length])),
    bySeverity: Object.fromEntries(findings.map((finding) => [finding.severity, findings.filter((item) => item.severity === finding.severity).length])),
    byStatus: { open: findings.length },
  }
  const duplication = {
    duplicatedLines: 20,
    totalLines: 1000,
    files: 2,
    blocks: [{
      tokens: 40,
      occurrences: [
        { file: 'src/a.ts', startLine: 10, endLine: 20 },
        { file: 'src/b.ts', startLine: 30, endLine: 40 },
      ],
    }],
  }

  return {
    analysis: {
      id,
      createdAt: '2026-07-18T00:00:00Z',
      origin: 'server',
      ci: null,
      sourceRef: options.sourceRef ?? 'main',
      sourceCommit: `${id}-abcdef1234567890`,
      gate: { passed: true, results: [] },
      gateInfo: { key: 'synapse-way', name: 'Synapse way', source: 'default' },
      issues: counts,
      newCode: {
        previousId: 'analysis-0',
        counts: { ...counts, total: 2 },
        rating: { security: 'B', reliability: 'C', maintainability: null },
      },
      delta: null,
      measures: { coverage: 72.3, duplication_density: 2 },
      coverage: { coveredLines: 723, totalLines: 1000 },
      duplication,
      rating: {
        security: 'D',
        reliability: 'C',
        maintainability: 'B',
        techDebtMinutes: 10,
        debtRatioPct: 0.1,
        linesOfCode: 1000,
      },
    },
    result: {
      target: 'project',
      scanMode: 'full',
      languages: [],
      components: [],
      dependencies: [],
      vulnerabilities: [],
      licenses: [],
      findings,
      toolVersions: {},
      vulnDBSnapshot: '',
      completeness: { lockfiles: [], componentsTotal: 0, componentsResolved: 0, confident: true, warning: '' },
      licenseCoverage: { total: 0, detected: 0, unknown: 0, pct: 0 },
      manifest: {
        toolVersions: {},
        vulnDBSnapshot: '',
        grypeDBVersion: '',
        correlationVersion: 1,
        sbomSha256: '',
        reproScore: 100,
        pinnedInputs: [],
        unpinnedInputs: [],
      },
      findingQuality: {
        rawFindings: findings.length,
        actionable: findings.length,
        background: 0,
        production: findings.length,
        development: 0,
        exampleTest: 0,
        thirdParty: 0,
        firstPartyHistorical: 0,
        versionCoveragePct: 100,
        pathCoveragePct: 100,
        confidence: 'high',
        byPriority: {},
      },
      codeQuality: {
        inventory: [{ language: 'TypeScript', files: 2, codeLines: 1000, commentLines: 0, blankLines: 0, functions: 10, functionsKnown: true }],
        findings: findings.filter((finding) => finding.kind === 'quality' || finding.kind === 'reliability'),
        duplication,
        rating: {
          security: 'D',
          reliability: 'C',
          maintainability: 'B',
          techDebtMinutes: 10,
          debtRatioPct: 0.1,
          linesOfCode: 1000,
        },
      },
      debugEvents: [],
    },
  }
}

export function buildFinding(
  id: string,
  title: string,
  kind: string,
  severity: Finding['severity'],
): Finding {
  return {
    id,
    engagementId: '',
    title,
    description: `${title} description`,
    severity,
    cvssVector: '',
    cwe: '',
    status: 'open',
    dedupKey: id,
    kev: false,
    riskScore: 0,
    class: '',
    scope: '',
    reachability: '',
    impact: '',
    priority: 1,
    assignee: '',
    version: 1,
    kind,
    evidenceScore: 100,
    proposedBy: '',
    complianceControls: [],
  }
}
