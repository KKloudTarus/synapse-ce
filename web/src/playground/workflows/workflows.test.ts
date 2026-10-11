import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { api } from '@/lib/api'
import { workflowHandlers } from './handlers'
import { AI_ENG, HOST_ID, INCIDENT_ID, PROJECT_KEY, PROJECT_TARGET, REVIEWER, RUNTIME_ENG, chooseMode, emptyWorkflows, resetWorkflow, settleWorkflows, updateWorkflows, workflowStore } from './store'
import { AI_CASES, DETECTIONS, LANGUAGES, QUALITY_ISSUES } from './catalog'
import { WORKFLOW_STEPS } from './steps'

const server = setupServer(...workflowHandlers, http.get('/api/v1/projects', () => HttpResponse.json([{ key: 'overview-project' }])))
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => updateWorkflows(s => Object.assign(s, emptyWorkflows())))
async function call(path: string, method = 'GET', body?: unknown) {
  return fetch(new URL(`/api/v1${path}`, window.location.origin), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
async function ok(path: string, method = 'GET', body?: unknown) {
  const r = await call(path, method, body), value = await r.json()
  expect(r.ok, JSON.stringify(value)).toBe(true)
  return value
}
const tick = () => settleWorkflows(Date.now() + 5000)
describe('Focused walkthroughs', () => {
  it('keeps mode datasets independent and restores the original overview fixtures', async () => {
    chooseMode('runtime'); await ok('/agents/enrolment-tokens', 'POST', { ttl_seconds: 900 }); await ok('/playground/runtime/enroll', 'POST')
    chooseMode('ai'); await ok('/playground/ai/proposals', 'POST')
    expect(workflowStore.getSnapshot().runtime.enrolledAt).toBeTruthy()
    resetWorkflow('ai')
    expect(workflowStore.getSnapshot().ai.proposalsAt).toBeNull()
    expect(workflowStore.getSnapshot().runtime.enrolledAt).toBeTruthy()
    chooseMode('overview'); expect(await ok('/projects')).toEqual([{ key: 'overview-project' }])
  })
  it('requires token, coverage, investigation and scope before applying a reversible response', async () => {
    chooseMode('runtime')
    expect((await call('/playground/runtime/enroll', 'POST')).status).toBe(409)
    await ok('/agents/enrolment-tokens', 'POST', { ttl_seconds: 900 }); await ok('/playground/runtime/enroll', 'POST')
    expect((await call('/playground/runtime/enroll', 'POST')).status).toBe(409)
    expect((await call('/playground/runtime/detect', 'POST')).status).toBe(409)
    await ok('/playground/runtime/telemetry', 'POST'); await ok('/playground/runtime/detect', 'POST')
    const detections = await api.listEngagementDetections(RUNTIME_ENG)
    expect(detections.detections[0]).toMatchObject({ ruleId: 'demo.unexpected_file_access', assetId: HOST_ID, severity: 'high', evidenceCount: 1 })
    expect(detections.detections).toHaveLength(DETECTIONS.length)
    expect(new Set(detections.detections.map(d => d.severity))).toEqual(new Set(['critical', 'high', 'medium', 'low', 'info']))
    const correlated = await ok(`/fleet/engagements/${RUNTIME_ENG}/correlate`, 'POST')
    expect(correlated.created).toHaveLength(DETECTIONS.length)
    await ok(`/fleet/incidents/${INCIDENT_ID}/owner`, 'POST', { owner: REVIEWER })
    await ok(`/fleet/incidents/${INCIDENT_ID}/status`, 'POST', { to: 'investigating' })
    await ok(`/fleet/incidents/${INCIDENT_ID}/disposition`, 'POST', { disposition: 'true_positive' })
    const body = { kind: 'isolate_host', target: HOST_ID }
    expect((await call(`/blueteam/engagements/${RUNTIME_ENG}/response/apply`, 'POST', body)).status).toBe(409)
    await ok(`/blueteam/engagements/${RUNTIME_ENG}/response/plan`, 'POST', body)
    expect((await call(`/blueteam/engagements/${RUNTIME_ENG}/response/apply`, 'POST', { ...body, target: 'another-host' })).status).toBe(409)
    await ok(`/blueteam/engagements/${RUNTIME_ENG}/response/apply`, 'POST', body)
    await ok('/blueteam/response/learn-response-1/revert', 'POST', { target: HOST_ID })
    await ok(`/fleet/incidents/${INCIDENT_ID}/status`, 'POST', { to: 'resolved' })
    expect((await api.listResponses())?.[0]).toMatchObject({ state: 'reverted', target: HOST_ID, approver: REVIEWER })
  })
  it('retains distinct human accept/reject decisions and rejects stale or unowned decisions', async () => {
    chooseMode('ai'); await ok('/playground/ai/proposals', 'POST')
    expect(await api.aiTriageReviews()).toHaveLength(5)
    expect((await call('/ai-triage/reviews/learn-review-1/decision', 'POST', { version: 1, decision: 'accept', rationale: 'Test fixture excluded.' })).status).toBe(409)
    for (const i of [1, 2]) {
      const path = `/ai-triage/reviews/learn-review-${i}`
      await ok(`${path}/claim`, 'POST', { version: 1 })
      expect((await call(`${path}/decision`, 'POST', { version: 1, decision: i === 1 ? 'accept' : 'reject', rationale: 'Reviewed recorded context.' })).status).toBe(409)
      await ok(`${path}/decision`, 'POST', { version: 2, decision: i === 1 ? 'accept' : 'reject', rationale: 'Reviewed recorded context.' })
    }
    const rows = await api.aiTriageReviews()
    expect(new Set(rows.map(r => r.severity))).toEqual(new Set(['critical', 'high', 'medium', 'low', 'info']))
    expect(await api.aiTriageReviews({ severity: 'critical' })).toHaveLength(1)
    expect(rows.map(r => [r.state, r.gateExempt])).toEqual([['accepted', true], ['rejected', false], ['pending', false], ['pending', false], ['pending', false]])
    await ok(`/engagements/${AI_ENG}/findings/learn-ai-finding-2`, 'PATCH', { version: 1, status: 'confirmed' })
    await ok(`/engagements/${AI_ENG}/findings/learn-ai-finding-2/assignee`, 'PUT', { version: 2, assignee: REVIEWER })
    await ok(`/engagements/${AI_ENG}/findings/learn-ai-finding-2/comments`, 'POST', { body: 'Bind parameters and re-test.' })
    const outcome = await api.aiTriageObservability()
    expect(Object.keys(outcome.distribution.languageBasisPoints)).toEqual(AI_CASES.map(c => c.language))
    expect(Object.values(outcome.distribution.languageBasisPoints).reduce((sum, value) => sum + value, 0)).toBe(10000)
    expect(outcome.byCWE.reduce((sum, row) => sum + row.findings, 0)).toBe(5)
    expect(outcome.totals).toMatchObject({ comparisons: 5, disagreements: 2, gateExemptions: 1, findings: 5, totalTokens: 0 })
  })
  it('retains baseline metrics and evaluates improved code under the same policy', async () => {
    chooseMode('quality')
    await ok('/projects', 'POST', { name: 'Checkout Quality', key: PROJECT_KEY, source_binding: { kind: 'git', value: PROJECT_TARGET, ref: 'main' }, gate_id: 'default' })
    await ok(`/projects/${PROJECT_KEY}/analyses`, 'POST')
    expect((await call('/playground/quality/improve', 'POST')).status).toBe(409)
    tick()
    const issues = await api.listProjectIssues(PROJECT_KEY, {})
    expect(issues.items).toHaveLength(QUALITY_ISSUES.length)
    expect(issues.facets.severities).toEqual({ critical: 2, high: 2, medium: 2, low: 2, info: 2 })
    expect(Object.keys(issues.facets.languages).sort()).toEqual(LANGUAGES.map(l => l.Name.toLowerCase()).sort())
    expect(issues.facets.types).toEqual({ vulnerability: 3, bug: 2, code_smell: 5 })
    const criticalGo = await api.listProjectIssues(PROJECT_KEY, { severity: 'critical', language: 'go' })
    expect(criticalGo.items).toHaveLength(1); expect(criticalGo.summary).toEqual({ total: 1, open: 1, resolved: 0 })
    await ok(`/projects/${PROJECT_KEY}/issues/learn-issue-1/transitions`, 'POST', { to: 'accepted', rationale: 'Track duplicated validation.', expected_version: 1 })
    await ok(`/projects/${PROJECT_KEY}/hotspots/learn-hotspot-1/transitions`, 'POST', { to: 'safe', rationale: 'Cache checksum, no security decision.', expected_version: 1 })
    expect((await api.listProjectHotspots(PROJECT_KEY, 'overall', {})).summary.reviewedPct).toBeCloseTo(100 / 3)
    await ok('/playground/quality/improve', 'POST'); await ok(`/projects/${PROJECT_KEY}/analyses`, 'POST'); tick()
    const base = await api.projectOverview(PROJECT_KEY, 'main'), head = await api.projectOverview(PROJECT_KEY, 'improved')
    expect(base.gate?.status).toBe('failed'); expect(head.gate?.status).toBe('passed')
    expect(base.lenses.overall.coverage.value).toBe(64); expect(head.lenses.overall.coverage.value).toBe(86)
    expect(base.lenses.overall.duplications.value).toBe(5); expect(head.lenses.overall.duplications.value).toBe(1)
    const resolved = await api.listProjectIssues(PROJECT_KEY, {})
    expect(resolved.summary).toEqual({ total: 0, open: 0, resolved: 0 })
    expect((await api.listProjectHotspots(PROJECT_KEY, 'overall', {})).summary).toEqual({ total: 3, reviewed: 3, reviewedPct: 100, grade: 'A' })
    expect((await api.projectAnalyses(PROJECT_KEY)).items).toHaveLength(2)
    expect((await api.getProject(PROJECT_KEY)).latestAnalysis?.gate.passed).toBe(true)
    const retained = await api.listProjectIssues(PROJECT_KEY, { branch: 'main' })
    expect(retained.items).toHaveLength(10)
    expect(retained.facets.severities).toEqual({ critical: 2, high: 2, medium: 2, low: 2, info: 2 })
    expect((await api.listProjectHotspots(PROJECT_KEY, 'overall', { branch: 'main' })).summary.reviewed).toBe(1)
    expect((await api.getProjectHotspot(PROJECT_KEY, 'learn-hotspot-2', 'main')).status).toBe('to_review')
    expect((await api.getProjectHotspotHistory(PROJECT_KEY, 'learn-hotspot-2', 'main'))).toEqual([])
    expect((await api.projectAnalyses(PROJECT_KEY, null, 'main')).items.map(a => a.id)).toEqual(['learn-quality-analysis-main'])
    expect((await call(`/projects/${PROJECT_KEY}/analyses`, 'POST')).status).toBe(409)
  })
  it('opens retained source, dependency exports and measures after Explore results', async () => {
    chooseMode('quality')
    const at = new Date().toISOString(), base = 'learn-quality-analysis-main', head = 'learn-quality-analysis-improved'
    updateWorkflows(s => {
      s.quality.project = { name: 'Checkout Quality', key: PROJECT_KEY, source: PROJECT_TARGET, ref: 'improved', gateId: 'default', createdAt: at }
      s.quality.analyses = [{ id: base, ref: 'main', startedAt: at, finishedAt: at }, { id: head, ref: 'improved', startedAt: at, finishedAt: at }]
      s.quality.hotspotStatus = 'safe'
    })
    const index = await api.listProjectCodeFiles(PROJECT_KEY, base)
    expect(index.files).toHaveLength(28)
    expect(new Set(index.files.map(f => f.language)).size).toBe(5)
    expect(index.files.reduce((n, f) => n + f.findingCount, 0)).toBe(13)
    const source = await api.projectCodeFile(PROJECT_KEY, base, QUALITY_ISSUES[0].file, 20)
    expect(source.fromLine).toBe(20); expect(source.findings[0].location.startLine).toBe(24)
    expect(source.head.ref).toBe('refs/heads/main')
    expect((await api.projectCodeFile(PROJECT_KEY, head, QUALITY_ISSUES[0].file, 1)).findings).toEqual([])
    const diff = await api.projectCodeDiff(PROJECT_KEY, head, QUALITY_ISSUES[0].file, 'unified')
    expect(diff.diff.base?.ref).toBe('refs/heads/main')
    expect(diff.diff.change.hunks[0].rows.some(row => row.kind === 'removed')).toBe(true)
    expect((await call(`/projects/${PROJECT_KEY}/analyses/${head}/code/diff?path=src%2Fcheckout.ts&view=split`)).status).toBe(422)
    expect((await call(`/projects/${PROJECT_KEY}/analyses/${base}/code/file?path=..%2Fsecret&from_line=1`)).status).toBe(404)
    expect((await call(`/projects/${PROJECT_KEY}/analyses/${base}/code/file?path=src%2Fcheckout.ts&from_line=10000`)).status).toBe(400)
    const graph = await api.projectDependencyGraph(PROJECT_KEY)
    expect(graph.summary).toMatchObject({ components: 12, direct: 8, transitive: 4, vulnerable: 8, licenseRisk: 2, edges: 4 })
    expect(graph.edges.every(e => graph.nodes.some(n => n.id === e.from) && graph.nodes.some(n => n.id === e.to))).toBe(true)
    const root = graph.nodes.find(n => n.name === 'checkout-parser')!.id
    const exported = await ok(`/projects/${PROJECT_KEY}/dependency-graph/export?root=${encodeURIComponent(root)}`)
    expect(exported.components.map((c: { name: string }) => c.name).sort()).toEqual(['checkout-archive', 'checkout-parser', 'checkout-path'])
    expect((await call(`/projects/${PROJECT_KEY}/dependency-graph/export?root=unknown`)).status).toBe(404)
    for (const [branch, coverage, duplication, issueCount] of [['main', 64, 5, 10], ['improved', 86, 1, 0]] as const) {
      const measures = await api.projectMeasures(PROJECT_KEY, { branch, domain: ['coverage', 'issues'] })
      expect(measures.node?.coverage?.coverage.value).toBe(coverage)
      expect(measures.node?.duplication?.duplicationDensity.value).toBe(duplication)
      expect(Object.values(measures.node!.issues!.bySeverity).reduce((n, metric) => n + metric.value!, 0)).toBe(issueCount)
      expect(measures.children.items.reduce((n, child) => n + child.size!.ncloc.value!, 0)).toBe(1000)
      expect(measures.children.items.reduce((n, child) => n + child.coverage!.coveredLines.value!, 0)).toBe(coverage * 10)
      expect((await api.projectMeasures(PROJECT_KEY, { branch, path: 'services/session' })).children.items.length).toBe(3)
    }
    expect((await api.projectBehavioralHotspots(PROJECT_KEY, head, {}))).toMatchObject({ availability: 'unavailable', items: [], reason: 'Git history is not retained in this training snapshot.' })
  })
  it('never treats an unloaded comparison or AI outcome as a completed review', () => {
    const s = emptyWorkflows()
    s.quality.analyses = [{ id: 'main', ref: 'main', startedAt: '', finishedAt: 'now' }, { id: 'improved', ref: 'improved', startedAt: '', finishedAt: 'now' }]
    expect(WORKFLOW_STEPS.quality[22].done(s, document)).toBe(false)
    document.body.innerHTML = '<div data-quality-base="learn-quality-analysis-main" data-quality-head="learn-quality-analysis-improved"><table data-quality-metric-comparison><tbody><tr><td>Loaded comparison</td></tr></tbody></table></div>'
    const visible = vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
    expect(WORKFLOW_STEPS.quality[22].done(s, document)).toBe(true)
    visible.mockRestore()
    document.body.innerHTML = ''
  })
})
