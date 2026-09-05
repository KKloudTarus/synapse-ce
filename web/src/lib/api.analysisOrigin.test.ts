import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

// The wire shape is projectAnalysisResponse in internal/adapter/httpapi/project_analysis_handler.go.
// `origin` and `ci` are what let the Activity page tell a pipeline-recorded analysis from a server one.
describe('project analysis origin', () => {
  let fetchSpy: any

  beforeEach(() => { fetchSpy = vi.spyOn(globalThis, 'fetch') })

  const base = {
    id: 'a1', created_at: '2026-09-05T12:00:00Z', source_ref: 'main', source_commit: 'abc123',
    gate: { passed: true, results: [] }, gate_info: { key: 'synapse-way', name: 'Synapse way', source: 'managed' },
    issues: { total: 1 }, new_code: { previous_id: '', counts: { total: 1 }, rating: { security: 'A', reliability: 'A' } },
    delta: null, measures: {}, coverage: null, duplication: {}, rating: { security: 'A', reliability: 'A', maintainability: 'A' },
  }

  it('maps a pipeline-recorded analysis with its CI context', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({
      ...base, origin: 'ci',
      ci: { provider: 'github-actions', run_url: 'https://github.com/acme/app/actions/runs/7', run_id: '7', branch: 'main', actor: 'octocat' },
    }) } as Response)
    const analysis = await api.projectAnalysis('app', 'a1')
    expect(analysis.origin).toBe('ci')
    expect(analysis.ci).toEqual({ provider: 'github-actions', runUrl: 'https://github.com/acme/app/actions/runs/7', runId: '7', branch: 'main', actor: 'octocat' })
  })

  it('reads a server analysis, and a row written before the field existed, as origin server', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ ...base, origin: 'server' }) } as Response)
    expect((await api.projectAnalysis('app', 'a1')).origin).toBe('server')

    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => base } as Response)
    const legacy = await api.projectAnalysis('app', 'a1')
    expect(legacy.origin).toBe('server')
    expect(legacy.ci).toBeNull()
  })

  it('maps imported findings from the SARIF route', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ([{
      id: 'if-1', finding_id: '', severity: 'high', title: 'SQL injection', message: 'm', path: 'src/db.py', start_line: 42,
      start_column: 3, suppressed_by_tool: false, fingerprint: 'fp', external: true, can_self_promote: false,
      tool: 'semgrep', tool_version: '1.90.0', rule: 'python.sqli', source_digest: 'sha256:x', ingested_by: 'ci-bot', ingested_at: '2026-09-05T12:00:00Z',
    }]) } as Response)
    const rows = await api.listImportedFindings('e1')
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/engagements/e1/imported-findings', expect.any(Object))
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ id: 'if-1', severity: 'high', path: 'src/db.py', startLine: 42, tool: 'semgrep', toolVersion: '1.90.0', canSelfPromote: false, ingestedBy: 'ci-bot' })
  })
})
