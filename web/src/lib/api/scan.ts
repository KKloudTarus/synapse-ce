import type {
  AITriage,
  CodeQualityReport,
  CodeRating,
  Component,
  ImportedSBOMMetadata,
  ScanJob,
  ScanResult,
  Vulnerability,
  Writeup,
} from '../types'
import { ApiError, req } from './client'
import { mapFinding, mapSLAView } from './findings'

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

export function mapScanJob(r: any): ScanJob {
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

function mapAITriage(r: any): AITriage {
  return {
    findingId: r.finding_id ?? '',
    dedupKey: r.dedup_key ?? '',
    verdict: r.verdict ?? '',
    driver: r.driver ?? '',
    confidence: r.confidence ?? 0,
    suspectedFP: r.suspected_fp ?? false,
    proposerModel: r.proposer_model ?? '',
    proposerProvider: r.proposer_provider ?? '',
    proposerModelFamily: r.proposer_model_family ?? '',
    verifierModel: r.verifier_model ?? '',
    verifierProvider: r.verifier_provider ?? '',
    verifierModelFamily: r.verifier_model_family ?? '',
    independencePolicy: r.independence_policy ?? '',
    promptVersion: r.prompt_version ?? '',
    policyVersion: r.policy_version ?? '',
    policyReason: r.policy_reason ?? '',
    shadow: r.shadow ?? false,
    wouldGateExempt: r.would_gate_exempt ?? false,
    gateExempt: r.gate_exempt ?? false,
    reviewRequired: r.review_required ?? false,
    verified: r.verified ?? false,
    verifierVerdict: r.verifier_verdict ?? '',
    verifierDriver: r.verifier_driver ?? '',
    verifierConfidence: r.verifier_confidence ?? 0,
  }
}

function mapCodeQualityReport(rep: any): CodeQualityReport {
  return {
    inventory: (rep?.inventory?.languages ?? []).map((l: any) => ({
      language: l.language,
      files: l.files ?? 0,
      codeLines: l.code_lines ?? 0,
      commentLines: l.comment_lines ?? 0,
      blankLines: l.blank_lines ?? 0,
      functions: l.functions ?? 0,
      functionsKnown: !!l.functions_known,
    })),
    findings: (rep?.findings ?? []).map(mapFinding),
    duplication: {
      blocks: (rep?.duplication?.blocks ?? []).map((b: any) => ({
        tokens: b.tokens ?? 0,
        occurrences: (b.occurrences ?? []).map((o: any) => ({ file: o.file, startLine: o.start_line ?? 0, endLine: o.end_line ?? 0 })),
      })),
      duplicatedLines: rep?.duplication?.duplicated_lines ?? 0,
      totalLines: rep?.duplication?.total_lines ?? 0,
      files: rep?.duplication?.files ?? 0,
    },
    rating: {
      security: (rep?.rating?.security ?? '?') as CodeRating['security'],
      reliability: (rep?.rating?.reliability ?? '?') as CodeRating['reliability'],
      maintainability: (rep?.rating?.maintainability ?? '?') as CodeRating['maintainability'],
      techDebtMinutes: rep?.rating?.tech_debt_minutes ?? 0,
      debtRatioPct: rep?.rating?.debt_ratio_pct ?? 0,
      linesOfCode: rep?.rating?.lines_of_code ?? 0,
    },
  }
}

export { mapCodeQualityReport }

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
    slas: (r.slas ?? []).map(mapSLAView),
    aiTriage: (r.ai_triage ?? []).map(mapAITriage),
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
    codeQuality: r.code_quality ? mapCodeQualityReport(r.code_quality) : undefined,
    debugEvents: (r.debug_events ?? []).map(mapScanDebugEvent),
  }
}

export const scanApi = {
  startScan: async (engagementId: string, target: string, kind: string, ref = '', mode = 'full', codeQuality = false): Promise<ScanJob> => {
    const r = await req('/sca/scans', {
      method: 'POST',
      body: JSON.stringify({ engagement_id: engagementId, target, kind, ref, mode, code_quality: codeQuality }),
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

  latestScan: async (engagementId: string): Promise<ScanResult | null> => {
    try {
      const r = await req(`/engagements/${encodeURIComponent(engagementId)}/scan`)
      return mapScanResult(r)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  writeups: async (): Promise<Writeup[]> => (await req('/writeups')) ?? [],

  importedSBOM: async (engagementId: string): Promise<ImportedSBOMMetadata> =>
    mapImportedSBOMMetadata(await req(`/engagements/${encodeURIComponent(engagementId)}/sbom`)),

  importSBOM: async (engagementId: string, cdxJSON: string): Promise<{ target: string; components: number; dependencies: number }> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/sbom`, { method: 'POST', body: cdxJSON }),

  applyVEX: async (engagementId: string, vexJSON: string): Promise<{ statements: number; matched: number; applied: number }> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/vex`, { method: 'POST', body: vexJSON }),
}
