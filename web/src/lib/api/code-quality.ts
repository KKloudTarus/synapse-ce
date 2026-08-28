import type {
  CodeQualityView,
  CodeRating,
  CreateProjectInput,
  Grade,
  Hotspot,
  HotspotListFilter,
  HotspotPage,
  HotspotReviewEvent,
  HotspotStatus,
  IssuePage,
  IssueListFilter,
  IssueReviewEvent,
  IssueStatus,
  LatestProjectAnalysis,
  Project,
  ProjectAnalysis,
  ProjectAnalysisCursor,
  ProjectAnalysisPage,
  ProjectCodeDiffCapabilities,
  ProjectCodeDiffResponse,
  ProjectCodeCapabilities,
  ProjectCodeCapability,
  ProjectCodeFile,
  ProjectCodeFileIndex,
  ProjectCodeFileView,
  ProjectCodeRevision,
  ProjectCodeView,
  ProjectIssue,
  QualityGate,
  QualityProfile,
  RuleType,
  ScanJob,
  Severity,
} from '../types'
import { mapProjectOverviewResponse, type ProjectOverview } from '../projectOverview'
import { mapProjectMeasureResponse, type MeasuresQuery, type ProjectMeasureResponse } from '../projectMeasures'
import { ApiError, getToken, getOnUnauthorized, req } from './client'
import { mapScanJob, mapCodeQualityReport } from './scan'

function mapQualityProfile(r: any): QualityProfile {
  const activatedRules: Record<string, { severity: string }> = {}
  for (const [k, v] of Object.entries(r?.activated_rules ?? {})) {
    activatedRules[k] = { severity: (v as any)?.severity ?? '' }
  }
  return {
    key: r?.key ?? '',
    name: r?.name ?? '',
    language: r?.language ?? '',
    parent: r?.parent ?? '',
    activatedRules,
    builtIn: r?.built_in ?? false,
  }
}

function mapQualityGate(r: any): QualityGate {
  return {
    key: r.key ?? '',
    name: r.name ?? '',
    conditions: (r.conditions ?? []).map((condition: any) => ({ metric: condition.metric ?? '', op: condition.op ?? '<=', threshold: condition.threshold ?? 0 })),
    builtIn: r.built_in ?? false,
  }
}

function mapProject(r: any): Project {
  return {
    id: r.ID ?? '',
    name: r.Name ?? '',
    key: r.Key ?? '',
    sourceBinding: {
      kind: r.SourceBinding?.kind ?? 'local',
      value: r.SourceBinding?.value ?? '',
      ref: r.SourceBinding?.ref ?? '',
    },
    defaultProfileByLang: r.DefaultProfileByLang ?? {},
    gateId: r.GateID ?? '',
    createdAt: r.Audit?.CreatedAt ?? null,
    latestAnalysis: r.latest_analysis ? mapProjectSummaryAnalysis(r.latest_analysis) : null,
    latestJob: r.latest_job ? mapScanJob(r.latest_job) : null,
  }
}

function mapProjectSummaryAnalysis(r: any): ProjectAnalysis {
  const counts = (value: any) => ({ total: value?.total ?? 0, byKind: value?.by_kind ?? {}, bySeverity: value?.by_severity ?? {}, byStatus: value?.by_status ?? {} })
  const grade = (value: any): CodeRating => ({ security: (value?.security ?? '?') as CodeRating['security'], reliability: (value?.reliability ?? '?') as CodeRating['reliability'], maintainability: (value?.maintainability ?? '?') as CodeRating['maintainability'], techDebtMinutes: 0, debtRatioPct: 0, linesOfCode: 0 })
  return { id: r.id ?? '', createdAt: r.created_at ?? '', sourceRef: '', sourceCommit: r.source_commit ?? '', gate: { passed: r.gate_passed ?? false, results: [] }, gateInfo: { key: r.gate_info?.key ?? '', name: r.gate_info?.name ?? 'Quality gate', source: r.gate_info?.source ?? '' }, issues: counts(r.issues), newCode: { previousId: '', counts: { ...counts(null), total: r.new_issues ?? 0 }, rating: { security: '?', reliability: '?', maintainability: null } }, delta: null, measures: {}, coverage: null, duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 }, rating: grade(r.rating) }
}

function mapProjectAnalysis(r: any): ProjectAnalysis {
  const counts = (value: any) => ({ total: value?.total ?? 0, byKind: value?.by_kind ?? {}, bySeverity: value?.by_severity ?? {}, byStatus: value?.by_status ?? {} })
  const rating = (value: any): CodeRating => ({
    security: (value?.security ?? '?') as CodeRating['security'], reliability: (value?.reliability ?? '?') as CodeRating['reliability'],
    maintainability: (value?.maintainability ?? '?') as CodeRating['maintainability'], techDebtMinutes: value?.tech_debt_minutes ?? 0,
    debtRatioPct: value?.debt_ratio_pct ?? 0, linesOfCode: value?.lines_of_code ?? 0,
  })
  return {
    id: r.id ?? '', createdAt: r.created_at ?? '', sourceRef: r.source_ref ?? '', sourceCommit: r.source_commit ?? '',
    gate: { passed: r.gate?.passed ?? false, results: (r.gate?.results ?? []).map((result: any) => ({ condition: { metric: result.metric ?? '', op: result.op ?? '', threshold: result.threshold ?? 0 }, actual: result.actual ?? 0, passed: result.passed ?? false })) },
    gateInfo: { key: r.gate_info?.key ?? '', name: r.gate_info?.name ?? 'Quality gate', source: r.gate_info?.source ?? '' },
    issues: counts(r.issues), newCode: { previousId: r.new_code?.previous_id ?? '', counts: counts(r.new_code?.counts), rating: { security: (r.new_code?.rating?.security ?? '?') as Grade, reliability: (r.new_code?.rating?.reliability ?? '?') as Grade, maintainability: r.new_code?.rating?.maintainability ? r.new_code.rating.maintainability as Grade : null } },
    delta: r.delta ? { issues: counts(r.delta.issues), measures: r.delta.measures ?? {}, ratings: r.delta.ratings ?? {} } : null, measures: r.measures ?? {},
    coverage: r.coverage ? { coveredLines: r.coverage.covered_lines ?? 0, totalLines: r.coverage.total_lines ?? 0 } : null,
    duplication: { blocks: [], duplicatedLines: r.duplication?.duplicated_lines ?? 0, totalLines: r.duplication?.total_lines ?? 0, files: r.duplication?.files ?? 0 }, rating: rating(r.rating),
  }
}

function mapHotspot(r: any): Hotspot {
  return {
    id: r.id ?? '',
    ruleKey: r.rule_key ?? '',
    ruleName: r.rule_name ?? '',
    title: r.title ?? '',
    description: r.description ?? '',
    severity: (r.severity ?? 'unknown') as Severity,
    kind: r.finding_kind ?? '',
    cwe: r.cwe ?? '',
    location: r.location ?? '',
    status: (r.status ?? 'to_review') as HotspotStatus,
    version: r.version ?? 1,
    firstSeenAnalysisId: r.first_seen_analysis_id ?? '',
    lastSeenAnalysisId: r.last_seen_analysis_id ?? '',
    firstSeenAt: r.first_seen_at ?? '',
    lastSeenAt: r.last_seen_at ?? '',
  }
}

function mapHotspotReviewEvent(r: any): HotspotReviewEvent {
  return {
    actor: r.actor ?? '',
    status: (r.to || r.status || 'to_review') as HotspotStatus,
    rationale: r.rationale ?? '',
    version: r.version ?? (r.previous_version ? r.previous_version + 1 : 1),
    at: r.created_at || r.at || '',
  }
}

function mapProjectIssue(r: any): ProjectIssue {
  return {
    id: r.id ?? '',
    ruleKey: r.rule_key ?? '',
    ruleName: r.rule_name ?? '',
    type: asRuleType(r.type),
    title: r.title ?? '',
    description: r.description ?? '',
    severity: (r.severity ?? 'unknown') as Severity,
    findingKind: r.finding_kind ?? '',
    cwe: r.cwe ?? '',
    language: r.language ?? '',
    file: r.file ?? '',
    location: r.location ?? '',
    status: (r.status ?? 'open') as IssueStatus,
    version: r.version ?? 1,
    isNew: r.is_new ?? false,
    firstSeenAnalysisId: r.first_seen_analysis_id ?? '',
    lastSeenAnalysisId: r.last_seen_analysis_id ?? '',
    firstSeenAt: r.first_seen_at ?? '',
    lastSeenAt: r.last_seen_at ?? '',
  }
}

function mapIssueReviewEvent(r: any): IssueReviewEvent {
  return {
    from: (r.from ?? 'open') as IssueStatus,
    to: (r.to ?? 'open') as IssueStatus,
    actor: r.actor ?? '',
    rationale: r.rationale ?? '',
    version: r.version ?? 1,
    createdAt: r.created_at ?? '',
  }
}

function mapProjectCodeRevision(r: any): ProjectCodeRevision {
  return { ref: r?.ref ?? '', commit: r?.commit ?? '', artifactDigest: r?.artifact_digest ?? '' }
}

function mapProjectCodeCapabilities(r: any): ProjectCodeCapabilities {
  return {
    source: r?.source === true,
    unifiedDiff: r?.unified_diff === true,
    splitDiff: r?.split_diff === true,
    lineCoverage: r?.line_coverage === true,
  }
}

function mapProjectCodeCapability(r: any): ProjectCodeCapability {
  return { available: r?.available === true, reason: typeof r?.reason === 'string' ? r.reason : null }
}

function mapProjectCodeDiffCapabilities(r: any): ProjectCodeDiffCapabilities {
  return {
    source: mapProjectCodeCapability(r?.source),
    comparison: mapProjectCodeCapability(r?.comparison),
    unifiedDiff: mapProjectCodeCapability(r?.unified_diff),
    splitDiff: mapProjectCodeCapability(r?.split_diff),
    highlighting: mapProjectCodeCapability(r?.highlighting),
  }
}

function mapProjectCodeFile(r: any): ProjectCodeFile {
  return {
    path: r?.path ?? '',
    oldPath: typeof r?.old_path === 'string' && r.old_path ? r.old_path : null,
    status: r?.status ?? 'unchanged',
    language: r?.language ?? '',
    lines: r?.lines ?? 0,
    findingCount: r?.finding_count ?? 0,
    changedLineCount: r?.changed_line_count ?? 0,
    binary: r?.binary === true,
    generated: r?.generated === true,
    sourceAvailable: r?.source_available === true,
    sourceReason: typeof r?.source_reason === 'string' ? r.source_reason : null,
  }
}

function mapProjectCodeFileIndex(r: any): ProjectCodeFileIndex {
  return {
    analysisId: r?.analysis_id ?? '',
    base: r?.base ? mapProjectCodeRevision(r.base) : null,
    head: mapProjectCodeRevision(r?.head),
    capabilities: mapProjectCodeCapabilities(r?.capabilities),
    files: (r?.files ?? []).map(mapProjectCodeFile),
  }
}

function mapProjectCodeFileView(r: any): ProjectCodeFileView {
  return {
    analysisId: r?.analysis_id ?? '',
    base: r?.base ? mapProjectCodeRevision(r.base) : null,
    head: mapProjectCodeRevision(r?.head),
    file: mapProjectCodeFile(r?.file),
    fromLine: r?.from_line ?? 0,
    toLine: r?.to_line ?? 0,
    totalLines: r?.total_lines ?? 0,
    lines: (r?.lines ?? []).map((line: any) => ({
      number: line?.number ?? 0,
      content: line?.content ?? '',
      change: line?.change === 'addition' ? 'addition' : 'unchanged',
      duplicated: line?.duplicated === true,
      coverage: ['covered', 'uncovered', 'partial'].includes(line?.coverage) ? line.coverage : null,
    })),
    findings: (r?.findings ?? []).map((finding: any) => ({
      id: finding?.id ?? '',
      kind: finding?.kind === 'hotspot' ? 'hotspot' : 'issue',
      ruleKey: finding?.rule_key ?? '',
      ruleName: finding?.rule_name ?? '',
      type: finding?.type ?? '',
      severity: finding?.severity ?? 'unknown',
      detectionStatus: finding?.detection_status ?? '',
      currentStatus: typeof finding?.current_status === 'string' ? finding.current_status : null,
      message: finding?.message ?? '',
      location: {
        file: finding?.location?.file ?? '',
        startLine: finding?.location?.start_line ?? 0,
        endLine: finding?.location?.end_line ?? 0,
        startColumn: typeof finding?.location?.start_column === 'number' ? finding.location.start_column : null,
        endColumn: typeof finding?.location?.end_column === 'number' ? finding.location.end_column : null,
      },
      isNew: finding?.new === true,
    })),
    capabilities: mapProjectCodeCapabilities(r?.capabilities),
  }
}

function mapProjectCodeDiffResponse(r: any): ProjectCodeDiffResponse {
  const diff = r?.diff ?? {}
  return {
    capabilities: mapProjectCodeDiffCapabilities(r?.capabilities),
    diff: {
      analysisId: diff.analysis_id ?? '',
      base: diff.base ? mapProjectCodeRevision(diff.base) : null,
      head: mapProjectCodeRevision(diff.head),
      path: diff.path ?? '',
      view: diff.view === 'split' ? 'split' : 'unified',
      contextTruncated: diff.context_truncated === true,
      change: {
        oldPath: diff.change?.old_path ?? '',
        newPath: diff.change?.new_path ?? '',
        status: diff.change?.status ?? 'unchanged',
        binary: diff.change?.binary === true,
        modeOld: diff.change?.mode_old ?? '',
        modeNew: diff.change?.mode_new ?? '',
        hunks: (diff.change?.hunks ?? []).map((hunk: any) => ({
          oldStart: hunk?.old_start ?? 0,
          oldLines: hunk?.old_lines ?? 0,
          newStart: hunk?.new_start ?? 0,
          newLines: hunk?.new_lines ?? 0,
          rows: (hunk?.rows ?? []).map((row: any) => ({
            kind: ['context', 'added', 'removed'].includes(row?.kind) ? row.kind : 'context',
            oldLine: typeof row?.old_line === 'number' && row.old_line > 0 ? row.old_line : null,
            newLine: typeof row?.new_line === 'number' && row.new_line > 0 ? row.new_line : null,
            text: row?.text ?? '',
            noFinalNewline: row?.no_final_newline === true,
          })),
        })),
      },
    },
  }
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function asRuleType(value: unknown): RuleType {
  const s = asString(value)
  return ['bug', 'vulnerability', 'code_smell', 'security_hotspot'].includes(s) ? (s as RuleType) : 'code_smell'
}

export const codeQualityApi = {
  projectMeasures: async (projectKey: string, query: MeasuresQuery, signal?: AbortSignal): Promise<ProjectMeasureResponse> => {
    const q = new URLSearchParams()
    if (query.path) q.set('path', query.path)
    if (query.limit) q.set('limit', query.limit.toString())
    if (query.cursor) q.set('cursor', query.cursor)
    if (query.domain) {
      for (const d of query.domain) {
        if (d) q.append('domain', d)
      }
    }
    const qs = q.toString()
    const raw = await req(`/projects/${encodeURIComponent(projectKey)}/measures${qs ? `?${qs}` : ''}`, { signal })
    return mapProjectMeasureResponse(raw)
  },

  listQualityGates: async (): Promise<QualityGate[]> =>
    ((await req('/quality-gates')) ?? []).map(mapQualityGate),

  createQualityGate: async (gate: Omit<QualityGate, 'builtIn'>): Promise<QualityGate> =>
    mapQualityGate(await req('/quality-gates', { method: 'POST', body: JSON.stringify(gate) })),

  updateQualityGate: async (key: string, gate: Omit<QualityGate, 'key' | 'builtIn'>): Promise<QualityGate> =>
    mapQualityGate(await req(`/quality-gates/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify(gate) })),

  deleteQualityGate: async (key: string): Promise<void> => {
    await req(`/quality-gates/${encodeURIComponent(key)}`, { method: 'DELETE' })
  },

  listQualityProfiles: async (language?: string): Promise<QualityProfile[]> =>
    ((await req(`/quality-profiles${language ? `?language=${encodeURIComponent(language)}` : ''}`)) ?? []).map(mapQualityProfile),

  copyQualityProfile: async (sourceKey: string, key: string, name: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(sourceKey)}/copy`, { method: 'POST', body: JSON.stringify({ key, name }) })),

  activateProfileRule: async (key: string, rule: string, severity = ''): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/activate`, { method: 'POST', body: JSON.stringify({ rule, severity }) })),

  deactivateProfileRule: async (key: string, rule: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/deactivate`, { method: 'POST', body: JSON.stringify({ rule }) })),

  setProfileRuleSeverity: async (key: string, rule: string, severity: string): Promise<QualityProfile> =>
    mapQualityProfile(await req(`/quality-profiles/${encodeURIComponent(key)}/severity`, { method: 'POST', body: JSON.stringify({ rule, severity }) })),

  deleteQualityProfile: async (key: string): Promise<void> => {
    await req(`/quality-profiles/${encodeURIComponent(key)}`, { method: 'DELETE' })
  },

  assignProjectProfile: async (projectKey: string, language: string, profile: string): Promise<void> => {
    await req(`/projects/${encodeURIComponent(projectKey)}/profiles/${encodeURIComponent(language)}`, { method: 'PUT', body: JSON.stringify({ profile }) })
  },

  listProjects: async (): Promise<Project[]> =>
    ((await req('/projects')) ?? []).map(mapProject),

  createProject: async (input: CreateProjectInput): Promise<Project> =>
    mapProject(
      await req('/projects', {
        method: 'POST',
        body: JSON.stringify({
          name: input.name,
          key: input.key,
          source_binding: {
            kind: input.sourceBinding.kind,
            value: input.sourceBinding.value,
            ref: input.sourceBinding.ref,
          },
          gate_id: input.gateId ?? '',
        }),
      }),
    ),

  createProjectFromArchive: async (name: string, key: string, archive: File, gateId = ''): Promise<Project> => {
    const form = new FormData()
    form.append('name', name)
    form.append('key', key)
    form.append('gate_id', gateId)
    form.append('archive', archive)
    const token = getToken()
    const onUnauthorized = getOnUnauthorized()
    const res = await fetch('/api/v1/projects', {
      method: 'POST',
      headers: token ? { authorization: `Bearer ${token}` } : {},
      body: form,
    })
    if (res.status === 401 && onUnauthorized) onUnauthorized()
    if (!res.ok) {
      let message = `HTTP ${res.status}`
      try { message = (await res.json())?.error ?? message } catch { /* non-JSON */ }
      throw new ApiError(res.status, message)
    }
    return mapProject(await res.json())
  },

  getProject: async (key: string): Promise<Project> =>
    mapProject(await req(`/projects/${encodeURIComponent(key)}`)),

  projectOverview: async (key: string): Promise<ProjectOverview> =>
    mapProjectOverviewResponse(await req(`/projects/${encodeURIComponent(key)}/overview`)),

  listProjectCodeFiles: async (projectKey: string, analysisId: string, signal?: AbortSignal): Promise<ProjectCodeFileIndex> =>
    mapProjectCodeFileIndex(await req(`/projects/${encodeURIComponent(projectKey)}/analyses/${encodeURIComponent(analysisId)}/code/files`, { signal })),

  projectCodeFile: async (projectKey: string, analysisId: string, path: string, fromLine: number, signal?: AbortSignal): Promise<ProjectCodeFileView> => {
    const query = new URLSearchParams({ path, from_line: String(fromLine) })
    return mapProjectCodeFileView(await req(`/projects/${encodeURIComponent(projectKey)}/analyses/${encodeURIComponent(analysisId)}/code/file?${query}`, { signal }))
  },

  projectCodeDiff: async (projectKey: string, analysisId: string, path: string, view: Extract<ProjectCodeView, 'unified' | 'split'>, signal?: AbortSignal): Promise<ProjectCodeDiffResponse> => {
    const query = new URLSearchParams({ path, view })
    return mapProjectCodeDiffResponse(await req(`/projects/${encodeURIComponent(projectKey)}/analyses/${encodeURIComponent(analysisId)}/code/diff?${query}`, { signal }))
  },

  listProjectHotspots: async (projectKey: string, lens: 'overall' | 'new-code', filter: HotspotListFilter): Promise<HotspotPage> => {
    const q = new URLSearchParams()
    q.set('lens', lens)
    if (filter.status) q.set('status', filter.status)
    if (filter.rule) q.set('rule', filter.rule)
    if (filter.severity) q.set('severity', filter.severity)
    if (filter.search?.trim()) q.set('search', filter.search.trim())
    if (filter.limit) q.set('limit', String(filter.limit))
    if (filter.before_last_seen_at) q.set('before_last_seen_at', filter.before_last_seen_at)
    if (filter.before_id) q.set('before_id', filter.before_id)
    const qs = q.toString()
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots${qs ? `?${qs}` : ''}`)
    return {
      items: (res.items ?? []).map(mapHotspot),
      next: res.next ? { beforeLastSeenAt: res.next.before_last_seen_at ?? '', beforeId: res.next.before_id ?? '' } : null,
      facets: {
        statuses: res.facets?.statuses ?? {},
        ruleKeys: res.facets?.rule_keys ?? {},
        severities: res.facets?.severities ?? {},
      },
      summary: {
        total: res.summary?.total ?? 0,
        reviewed: res.summary?.reviewed ?? 0,
        reviewedPct: res.summary?.reviewed_pct ?? 100,
        grade: (res.summary?.grade ?? 'A') as Grade,
      },
    }
  },

  getProjectHotspot: async (projectKey: string, id: string): Promise<Hotspot> =>
    mapHotspot(await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}`)),

  transitionProjectHotspot: async (projectKey: string, id: string, status: HotspotStatus, rationale: string, expectedVersion: number): Promise<{ hotspot: Hotspot, event: HotspotReviewEvent }> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}/transitions`, {
      method: 'POST',
      body: JSON.stringify({ to: status, rationale, expected_version: expectedVersion }),
    })
    return { hotspot: mapHotspot(res.hotspot), event: mapHotspotReviewEvent(res.event) }
  },

  getProjectHotspotHistory: async (projectKey: string, id: string): Promise<HotspotReviewEvent[]> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/hotspots/${encodeURIComponent(id)}/history`)
    return (res ?? []).map(mapHotspotReviewEvent)
  },

  listProjectIssues: async (projectKey: string, filter: IssueListFilter): Promise<IssuePage> => {
    const q = new URLSearchParams()
    if (filter.lens) q.set('lens', filter.lens)
    if (filter.status) q.set('status', filter.status)
    if (filter.type) q.set('type', filter.type)
    if (filter.severity) q.set('severity', filter.severity)
    if (filter.rule) q.set('rule', filter.rule)
    if (filter.language) q.set('language', filter.language)
    if (filter.path) q.set('path', filter.path)
    if (filter.newCode) q.set('new_code', 'true')
    if (filter.search?.trim()) q.set('search', filter.search.trim())
    if (filter.limit) q.set('limit', String(filter.limit))
    if (filter.before_last_seen_at) q.set('before_last_seen_at', filter.before_last_seen_at)
    if (filter.before_id) q.set('before_id', filter.before_id)
    const qs = q.toString()
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/issues${qs ? `?${qs}` : ''}`)
    return {
      items: (res.items ?? []).map(mapProjectIssue),
      next: res.next ? { beforeLastSeenAt: res.next.before_last_seen_at ?? '', beforeId: res.next.before_id ?? '' } : null,
      facets: {
        types: res.facets?.types ?? {},
        statuses: res.facets?.statuses ?? {},
        severities: res.facets?.severities ?? {},
        ruleKeys: res.facets?.rule_keys ?? {},
        languages: res.facets?.languages ?? {},
      },
      summary: {
        total: res.summary?.total ?? 0,
        open: res.summary?.open ?? 0,
        resolved: res.summary?.resolved ?? 0,
      },
    }
  },

  getProjectIssue: async (projectKey: string, id: string): Promise<ProjectIssue> =>
    mapProjectIssue(await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}`)),

  transitionProjectIssue: async (projectKey: string, id: string, status: IssueStatus, rationale: string, expectedVersion: number): Promise<ProjectIssue> =>
    mapProjectIssue(await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}/transitions`, {
      method: 'POST',
      body: JSON.stringify({ to: status, rationale, expected_version: expectedVersion }),
    })),

  getProjectIssueHistory: async (projectKey: string, id: string): Promise<IssueReviewEvent[]> => {
    const res = await req(`/projects/${encodeURIComponent(projectKey)}/issues/${encodeURIComponent(id)}/history`)
    return (res ?? []).map(mapIssueReviewEvent)
  },

  assignProjectGate: async (key: string, gateId: string): Promise<Project> =>
    mapProject(await req(`/projects/${encodeURIComponent(key)}/gate`, { method: 'PUT', body: JSON.stringify({ gate_id: gateId }) })),

  startProjectAnalysis: async (key: string, coverage?: File): Promise<ScanJob> => {
    const path = `/projects/${encodeURIComponent(key)}/analyses`
    if (!coverage) return mapScanJob(await req(path, { method: 'POST' }))
    const form = new FormData()
    form.append('coverage', coverage)
    const token = getToken()
    const onUnauthorized = getOnUnauthorized()
    const res = await fetch(`/api/v1${path}`, { method: 'POST', headers: token ? { authorization: `Bearer ${token}` } : {}, body: form })
    if (res.status === 401 && onUnauthorized) onUnauthorized()
    if (!res.ok) {
      let message = `HTTP ${res.status}`
      try { message = (await res.json())?.error ?? message } catch { /* non-JSON */ }
      throw new ApiError(res.status, message)
    }
    return mapScanJob(await res.json())
  },

  projectAnalyses: async (key: string, cursor: ProjectAnalysisCursor | null = null): Promise<ProjectAnalysisPage> => {
    const query = new URLSearchParams({ limit: '25' })
    if (cursor) {
      query.set('before_created_at', cursor.beforeCreatedAt)
      query.set('before_id', cursor.beforeId)
    }
    const page = await req(`/projects/${encodeURIComponent(key)}/analyses?${query}`)
    return {
      items: (page?.items ?? []).map(mapProjectAnalysis),
      next: page?.next ? { beforeCreatedAt: page.next.before_created_at ?? '', beforeId: page.next.before_id ?? '' } : null,
    }
  },

  projectAnalysis: async (key: string, id: string): Promise<ProjectAnalysis> =>
    mapProjectAnalysis(await req(`/projects/${encodeURIComponent(key)}/analyses/${encodeURIComponent(id)}`)),

  projectAnalysisStatus: async (key: string): Promise<ScanJob | null> => {
    try {
      return mapScanJob(await req(`/projects/${encodeURIComponent(key)}/analysis-status`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  latestProjectAnalysis: async (key: string): Promise<LatestProjectAnalysis | null> => {
    try {
      const latest = await req(`/projects/${encodeURIComponent(key)}/analysis`)
      return { analysis: mapProjectAnalysis(latest.analysis), result: mapScanResult(latest.result) }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  codeQuality: async (engagementId: string): Promise<CodeQualityView> => {
    let r: any
    try {
      r = await req(`/engagements/${encodeURIComponent(engagementId)}/code-quality`)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return { available: false, reason: 'code quality is not enabled on this server' }
      throw e
    }
    if (!r?.available || !r.report) return { available: false, reason: r?.reason }
    return { available: true, report: mapCodeQualityReport(r.report) }
  },
}

function mapScanResult(r: any) {
  // Use the scan module's mapScanResult logic inline for the latestProjectAnalysis endpoint
  const mapScanResultInline = (raw: any) => {
    return {
      target: raw.target ?? '',
      scanMode: raw.scan_mode ?? 'full',
      languages: (raw.languages ?? []).map((l: any) => ({ name: l.Name ?? '', percent: l.Percent ?? 0 })),
      components: (raw.sbom?.Components ?? []).map((c: any) => ({
        name: c.Name ?? '', version: c.Version ?? '', purl: c.PURL ?? '',
        licenses: (c.Licenses ?? []).map((l: any) => ({ spdxId: l.SPDXID ?? '', name: l.Name ?? '', category: l.Category ?? 'unknown' })),
        licenseSource: c.LicenseSource ?? '', licenseConfidence: c.LicenseConfidence ?? '', unknownReason: c.UnknownReason ?? '',
        firstParty: c.FirstParty ?? false, location: c.Location ?? '',
      })),
      dependencies: (raw.sbom?.Dependencies ?? []).map((d: any) => ({ ref: d.Ref ?? '', dependsOn: d.DependsOn ?? [] })),
      vulnerabilities: (raw.vulnerabilities ?? []).map((v: any) => ({
        id: v.ID, source: v.Source ?? '', severity: v.Severity ?? 'unknown', cvssVector: v.CVSSVector ?? '', cvssScore: v.CVSSScore ?? 0,
        component: v.Component ?? '', version: v.Version ?? '', fixedVersion: v.FixedVersion ?? '', description: v.Description ?? '',
        kev: v.KEV ?? false, epss: v.EPSS ?? 0, path: v.Path ?? [], direct: v.Direct ?? false, sources: v.Sources ?? [],
        confidence: v.Confidence ?? '', detections: (v.Detections ?? []).map((d: any) => ({ source: d.Source ?? '', advisoryId: d.AdvisoryID ?? '', severity: d.Severity ?? 'unknown', fixedVersion: d.FixedVersion ?? '' })),
        firstParty: v.FirstParty ?? false, unversioned: v.Unversioned ?? false,
      })),
      licenses: (raw.licenses ?? []).map((l: any) => ({ license: l.license ?? '', category: l.category ?? 'unknown', verdict: l.verdict ?? 'warn', components: l.components ?? [] })),
      findings: (raw.findings ?? []).map((f: any) => ({ id: f.ID, engagementId: f.EngagementID ?? '', title: f.Title ?? '', description: f.Description ?? '', severity: f.Severity ?? 'unknown', cvssVector: f.CVSSVector ?? '', cwe: f.CWE ?? '', status: f.Status ?? 'open', dedupKey: f.DedupKey ?? '', kev: f.KEV ?? false, riskScore: f.RiskScore ?? 0, class: f.Class ?? 'third_party', scope: f.Scope ?? 'unknown', reachability: f.Reachability ?? 'unknown', impact: f.Impact ?? '', priority: f.Priority ?? 3, assignee: f.Assignee ?? '', version: f.Version ?? 1, kind: f.Kind ?? '', evidenceScore: f.EvidenceScore ?? 0, proposedBy: f.ProposedBy ?? '', complianceControls: (f.compliance_controls ?? []).map((c: any) => ({ framework: c.Framework ?? '', id: c.ID ?? '', title: c.Title ?? '' })) })),
      slas: (raw.slas ?? []).map((s: any) => s),
      aiTriage: (raw.ai_triage ?? []).map((t: any) => t),
      toolVersions: raw.tool_versions ?? {},
      vulnDBSnapshot: raw.vuln_db_snapshot ?? '',
      completeness: { lockfiles: raw.completeness?.lockfiles ?? [], componentsTotal: raw.completeness?.components_total ?? 0, componentsResolved: raw.completeness?.components_resolved ?? 0, confident: raw.completeness?.confident ?? true, warning: raw.completeness?.warning ?? '' },
      licenseCoverage: { total: raw.license_coverage?.total ?? 0, detected: raw.license_coverage?.detected ?? 0, unknown: raw.license_coverage?.unknown ?? 0, pct: raw.license_coverage?.pct ?? 0 },
      findingQuality: { rawFindings: raw.finding_quality?.raw_findings ?? 0, actionable: raw.finding_quality?.actionable ?? 0, background: raw.finding_quality?.background ?? 0, production: raw.finding_quality?.production ?? 0, development: raw.finding_quality?.development ?? 0, exampleTest: raw.finding_quality?.example_test ?? 0, thirdParty: raw.finding_quality?.third_party ?? 0, firstPartyHistorical: raw.finding_quality?.first_party_historical ?? 0, versionCoveragePct: raw.finding_quality?.version_coverage_pct ?? 0, pathCoveragePct: raw.finding_quality?.path_coverage_pct ?? 0, confidence: raw.finding_quality?.confidence ?? '', byPriority: raw.finding_quality?.by_priority ?? {} },
      manifest: { toolVersions: raw.manifest?.tool_versions ?? {}, vulnDBSnapshot: raw.manifest?.vuln_db_snapshot ?? '', grypeDBVersion: raw.manifest?.grype_db_version ?? '', correlationVersion: raw.manifest?.correlation_version ?? 0, sbomSha256: raw.manifest?.sbom_sha256 ?? '', reproScore: raw.manifest?.repro_score ?? 0, pinnedInputs: raw.manifest?.pinned_inputs ?? [], unpinnedInputs: raw.manifest?.unpinned_inputs ?? [] },
      codeQuality: raw.code_quality ? mapCodeQualityReport(raw.code_quality) : undefined,
      debugEvents: (raw.debug_events ?? []).map((e: any) => ({ stage: e.stage ?? '', step: e.step ?? '', status: e.status ?? 'running', message: e.message ?? '', tool: e.tool ?? '', counts: e.counts ?? {}, startedAt: e.started_at ?? null, finishedAt: e.finished_at ?? null, durationMs: e.duration_ms ?? 0, error: e.error ?? '' })),
    }
  }
  return mapScanResultInline(r)
}
