import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import { mapProjectOverviewResponse } from './projectOverview'

describe('Projects API', () => {
  let fetchSpy: any

  beforeEach(() => { fetchSpy = vi.spyOn(globalThis, 'fetch') })

  it('maps project fields and portfolio summaries', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [{ ID: 'p1', Name: 'Synapse', Key: 'synapse', SourceBinding: { Kind: 'git', Value: 'https://example.com/repo.git', Ref: 'main' }, DefaultProfileByLang: { go: 'default' }, GateID: 'gate', Audit: { CreatedAt: '2026-07-15T00:00:00Z' }, latest_analysis: { id: 'a1', gate: { passed: false, results: [] }, gate_info: { key: 'release', name: 'Release', source: 'managed' } }, latest_job: { id: 'j1', status: 'succeeded' } }] } as Response)
    const projects = await api.listProjects()
    expect(projects[0]).toMatchObject({ id: 'p1', key: 'synapse', gateId: 'gate', sourceBinding: { kind: 'git', ref: 'main' }, latestAnalysis: { id: 'a1', gateInfo: { name: 'Release', source: 'managed' }, rating: { security: '?', reliability: '?', maintainability: '?' }, newCode: { rating: { security: '?', reliability: '?', maintainability: null } } }, latestJob: { id: 'j1', status: 'succeeded' } })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects', expect.any(Object))
  })

  it('marks absent engagement code-quality grades as unavailable', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ available: true, report: {} }) } as Response)
    const view = await api.codeQuality('e1')
    expect(view).toMatchObject({ available: true, report: { rating: { security: '?', reliability: '?', maintainability: '?' } } })
  })

  it('creates with the backend source and gate contract', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ ID: 'p1', Key: 'synapse', SourceBinding: { Kind: 'local', Value: '/repo' } }) } as Response)
    await api.createProject({ name: 'Synapse', key: 'synapse', gateId: 'release', sourceBinding: { kind: 'local', value: '/repo', ref: '' } })
    const init = fetchSpy.mock.calls[0][1] as RequestInit
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/projects')
    expect(JSON.parse(String(init.body))).toEqual({ name: 'Synapse', key: 'synapse', gate_id: 'release', source_binding: { Kind: 'local', Value: '/repo', Ref: '' } })
  })

  it('manages quality gates', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [{ key: 'synapse-way', name: 'Synapse way', built_in: true, conditions: [] }] } as Response)
    expect(await api.listQualityGates()).toMatchObject([{ key: 'synapse-way', builtIn: true }])

    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ key: 'release', name: 'Release', conditions: [] }) } as Response)
    await api.createQualityGate({ key: 'release', name: 'Release', conditions: [] })
    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/quality-gates', expect.objectContaining({ method: 'POST' }))
  })

  it('encodes project keys', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ Key: 'a b' }) } as Response)
    await api.getProject('a b')
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects/a%20b', expect.any(Object))
  })

  it('maps project overview and encodes project keys', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => overviewAnalyzedWire() } as Response)
    const overview = await api.projectOverview('a b')
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects/a%20b/overview', expect.any(Object))
    expect(overview).toMatchObject({
      state: 'analyzed',
      project: { key: 'payments-api', name: 'Payments API' },
      latestAnalysis: {
        id: 'analysis-42',
        sourceRef: 'main',
        newCode: { hasBaseline: true, baselineAnalysisId: 'analysis-41' },
      },
      gate: {
        status: 'failed',
        failedConditions: [{ metric: 'new_high', operator: '<=', threshold: 0, actual: 2 }],
      },
      issueSummary: {
        newCodeTotal: { availability: 'available', value: 4, unavailableReason: null },
        acceptedOverallTotal: { availability: 'unavailable', value: null, unavailableReason: 'issue_lifecycle_not_available' },
      },
      lenses: {
        overall: { coverage: { availability: 'available', value: 72.349 } },
        newCode: { coverage: { availability: 'unavailable', unavailableReason: 'changed_line_metrics_not_available' } },
      },
    })
  })

  it('preserves not-analyzed overview nulls', () => {
    const overview = mapProjectOverviewResponse(overviewNotAnalyzedWire())
    expect(overview).toMatchObject({
      state: 'not_analyzed',
      latestAnalysis: null,
      gate: null,
      issueSummary: { newCodeTotal: { value: null, unavailableReason: 'no_analysis' } },
      lenses: { overall: { security: { grade: null, unavailableReason: 'no_analysis' } } },
    })
  })

  it('accepts every project overview gate operator', () => {
    for (const operator of ['<=', '>=', '==', '<', '>']) {
      const raw = overviewAnalyzedWire()
      raw.gate.failed_conditions[0].operator = operator
      expect(mapProjectOverviewResponse(raw).gate?.failedConditions[0].operator).toBe(operator)
    }
  })

  it('does not convert project overview 404 to null', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response)
    await expect(api.projectOverview('missing')).rejects.toThrow('not found')
  })

  it('rejects malformed project overview contracts without raw payload leakage', () => {
    const cases: Array<[string, (raw: any) => void]> = [
      ['unknown state', raw => { raw.state = 'done' }],
      ['unknown availability', raw => { raw.lenses.overall.coverage.availability = 'maybe' }],
      ['unknown grade', raw => { raw.lenses.overall.security.grade = 'S' }],
      ['available rating missing grade', raw => { raw.lenses.overall.security.grade = null }],
      ['unavailable rating with grade', raw => { raw.lenses.new_code.maintainability.grade = 'A' }],
      ['available percentage null', raw => { raw.lenses.overall.coverage.value = null }],
      ['out of range percentage', raw => { raw.lenses.overall.coverage.value = 101 }],
      ['negative count', raw => { raw.issue_summary.new_code_total.value = -1 }],
      ['fractional count', raw => { raw.issue_summary.new_code_total.value = 1.5 }],
      ['unknown reason', raw => { raw.issue_summary.accepted_overall_total.unavailable_reason = 'later' }],
      ['invalid timestamp', raw => { raw.latest_analysis.created_at = 'not-a-date' }],
      ['date-only timestamp', raw => { raw.latest_analysis.created_at = '2026-07-17' }],
      ['empty analysis id', raw => { raw.latest_analysis.id = '' }],
      ['empty project key', raw => { raw.project.key = ' ' }],
      ['whitespace metric', raw => { raw.gate.failed_conditions[0].metric = ' ' }],
      ['unknown metric', raw => { raw.gate.failed_conditions[0].metric = 'unknown_metric' }],
      ['invalid operator', raw => { raw.gate.failed_conditions[0].operator = '!=' }],
      ['invalid word operator', raw => { raw.gate.failed_conditions[0].operator = 'approximately' }],
      ['empty operator', raw => { raw.gate.failed_conditions[0].operator = '' }],
      ['whitespace operator', raw => { raw.gate.failed_conditions[0].operator = ' ' }],
      ['invalid gate source', raw => { raw.gate.source = 'imported' }],
      ['passed gate with failed conditions', raw => { raw.gate.status = 'passed' }],
      ['failed gate without conditions', raw => { raw.gate.failed_conditions = [] }],
      ['first analysis with baseline', raw => { raw.latest_analysis.new_code = { first_analysis: true, has_baseline: true, baseline_analysis_id: 'analysis-41' } }],
      ['false false new-code period', raw => { raw.latest_analysis.new_code = { first_analysis: false, has_baseline: false, baseline_analysis_id: null } }],
      ['baseline id without baseline', raw => { raw.latest_analysis.new_code = { first_analysis: true, has_baseline: false, baseline_analysis_id: 'analysis-41' } }],
      ['baseline without id', raw => { raw.latest_analysis.new_code = { first_analysis: false, has_baseline: true, baseline_analysis_id: null } }],
      ['blank baseline id', raw => { raw.latest_analysis.new_code = { first_analysis: false, has_baseline: true, baseline_analysis_id: ' ' } }],
      ['unavailable value/reason mismatch', raw => { raw.lenses.new_code.coverage.unavailable_reason = null }],
      ['non-finite gate number', raw => { raw.gate.failed_conditions[0].actual = Number.POSITIVE_INFINITY }],
    ]
    for (const [name, mutate] of cases) {
      const raw = overviewAnalyzedWire()
      mutate(raw)
      expect(() => mapProjectOverviewResponse(raw), name).toThrow('Invalid project overview response')
      try {
        mapProjectOverviewResponse(raw)
      } catch (err) {
        expect(String(err)).not.toContain('payments-api')
        expect(String(err)).not.toContain('secret')
      }
    }
  })

  it('does not mutate project overview raw responses', () => {
    const raw = overviewAnalyzedWire()
    const before = JSON.stringify(raw)
    mapProjectOverviewResponse(raw)
    expect(JSON.stringify(raw)).toBe(before)
  })

  it('keeps an unavailable first delta null', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ items: [{ id: 'a1', delta: null, gate: { passed: true, results: [] } }] }) } as Response)
    const page = await api.projectAnalyses('project')
    expect(page.items[0].delta).toBeNull()
  })

  it('uploads coverage as multipart but keeps no-file requests unchanged', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({ id: 'job-1' }) } as Response)
    await api.startProjectAnalysis('project')
    expect(fetchSpy.mock.calls[0][1].headers).toMatchObject({ 'content-type': 'application/json' })

    fetchSpy.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({ id: 'job-2' }) } as Response)
    await api.startProjectAnalysis('project', new File(['SF:a.go\nDA:1,1\n'], 'coverage.info'))
    const init = fetchSpy.mock.calls[1][1] as RequestInit
    expect(init.body).toBeInstanceOf(FormData)
    expect(init.headers).not.toHaveProperty('content-type')
  })

  it('maps and sends project analysis cursors', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({
      items: [{ id: 'a1', created_at: '2026-07-17T00:00:00Z', gate: { passed: true, results: [] }, coverage: null }],
      next: { before_created_at: '2026-07-16T00:00:00Z', before_id: 'a0' },
    }) } as Response)
    const page = await api.projectAnalyses('a b', { beforeCreatedAt: '2026-07-18T00:00:00Z', beforeId: 'a2' })
    expect(page.items[0]).toMatchObject({ id: 'a1', coverage: null, rating: { security: '?', reliability: '?', maintainability: '?' }, newCode: { rating: { security: '?', reliability: '?', maintainability: null } } })
    expect(page.next).toEqual({ beforeCreatedAt: '2026-07-16T00:00:00Z', beforeId: 'a0' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects/a%20b/analyses?limit=25&before_created_at=2026-07-18T00%3A00%3A00Z&before_id=a2', expect.any(Object))
  })
})

function overviewAnalyzedWire(): any {
  return {
    state: 'analyzed',
    project: { key: 'payments-api', name: 'Payments API' },
    latest_analysis: {
      id: 'analysis-42',
      created_at: '2026-07-17T10:00:00Z',
      source_ref: 'main',
      source_commit: 'abc123',
      new_code: { first_analysis: false, has_baseline: true, baseline_analysis_id: 'analysis-41' },
    },
    gate: {
      status: 'failed',
      key: 'release',
      name: 'Release',
      source: 'managed',
      failed_conditions: [{ metric: 'new_high', operator: '<=', threshold: 0, actual: 2 }],
    },
    issue_summary: {
      new_code_total: { availability: 'available', value: 4, unavailable_reason: null },
      accepted_overall_total: { availability: 'unavailable', value: null, unavailable_reason: 'issue_lifecycle_not_available' },
    },
    lenses: {
      overall: {
        security: { availability: 'available', grade: 'B', unavailable_reason: null },
        reliability: { availability: 'available', grade: 'A', unavailable_reason: null },
        maintainability: { availability: 'available', grade: 'C', unavailable_reason: null },
        security_hotspots_reviewed: { availability: 'unavailable', value: null, unavailable_reason: 'security_hotspots_not_available' },
        coverage: { availability: 'available', value: 72.349, unavailable_reason: null },
        duplications: { availability: 'available', value: 4.25, unavailable_reason: null },
      },
      new_code: {
        security: { availability: 'available', grade: 'A', unavailable_reason: null },
        reliability: { availability: 'available', grade: 'B', unavailable_reason: null },
        maintainability: { availability: 'unavailable', grade: null, unavailable_reason: 'changed_line_metrics_not_available' },
        security_hotspots_reviewed: { availability: 'unavailable', value: null, unavailable_reason: 'security_hotspots_not_available' },
        coverage: { availability: 'unavailable', value: null, unavailable_reason: 'changed_line_metrics_not_available' },
        duplications: { availability: 'unavailable', value: null, unavailable_reason: 'changed_line_metrics_not_available' },
      },
    },
  }
}

function overviewNotAnalyzedWire(): any {
  const rating = { availability: 'unavailable', grade: null, unavailable_reason: 'no_analysis' }
  const percentage = { availability: 'unavailable', value: null, unavailable_reason: 'no_analysis' }
  return {
    state: 'not_analyzed',
    project: { key: 'payments-api', name: 'Payments API' },
    latest_analysis: null,
    gate: null,
    issue_summary: {
      new_code_total: { availability: 'unavailable', value: null, unavailable_reason: 'no_analysis' },
      accepted_overall_total: { availability: 'unavailable', value: null, unavailable_reason: 'no_analysis' },
    },
    lenses: {
      overall: {
        security: { ...rating },
        reliability: { ...rating },
        maintainability: { ...rating },
        security_hotspots_reviewed: { ...percentage },
        coverage: { ...percentage },
        duplications: { ...percentage },
      },
      new_code: {
        security: { ...rating },
        reliability: { ...rating },
        maintainability: { ...rating },
        security_hotspots_reviewed: { ...percentage },
        coverage: { ...percentage },
        duplications: { ...percentage },
      },
    },
  }
}
