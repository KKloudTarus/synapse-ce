import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { setupHandlers } from './handlers'
import { DEMO_SECRET, REVIEW_GOAL, SETUP_KEY, resetSetup, setupStore } from './store'
import { saveDemoMode } from '../demo-mode'
import { handlers } from '@/mocks/handlers'
import { advancedHandlers } from '../advanced/handlers'
import { workflowHandlers } from '../workflows/handlers'
import { scenarioHandlers } from '../scenario/handlers'
import { resetAdvanced, advancedStore, ADVANCED_KEY, updateAdvanced } from '../advanced/store'
import { ADVANCED_STEPS } from '../advanced/steps'
import { demoReport, reportPDF } from '../demo-report'
import { strFromU8, unzipSync } from 'fflate'
import { demoDependencies } from '../dependency-data'
import { guidePlacement } from '../guide-placement'

// Match the browser handler order: contract tests must exercise the shipped stack.
const server = setupServer(...setupHandlers, ...advancedHandlers, ...workflowHandlers, ...scenarioHandlers, ...handlers)
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { localStorage.clear(); resetSetup('ci-setup'); resetSetup('ai-setup'); saveDemoMode('ci-setup') })
const call = (path: string, method = 'GET', body?: unknown) => fetch(new URL(`/api/v1${path}`, window.location.origin), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
const ok = async (path: string, method = 'GET', body?: unknown) => { const r = await call(path, method, body); const data = r.status === 204 ? null : await r.json(); expect(r.ok, JSON.stringify(data)).toBe(true); return data }
const connection = () => ok('/integrations', 'POST', { provider: 'jenkins', name: 'Jenkins build evidence', endpoint: 'https://ci.example', poll_interval_seconds: 300 })
it('starts AI setup with explicit navigation and covers each deployment prerequisite', () => {
  const steps = ADVANCED_STEPS['ai-setup']
  expect(steps.slice(0, 4).map(s => [s.route, s.auto])).toEqual([
    ['/dashboard', true], ['/engagements', true], ['/engagements/eng-001', true], ['/engagements/eng-001/recon', true],
  ])
  expect(steps[0].target?.name).toContain('Primary navigation')
  expect(steps.filter(s => s.target?.name.startsWith('[data-setup-field=')).map(s => s.target?.name)).toHaveLength(6)
  expect(steps.find(s => s.title === 'Return to the readiness panel')?.auto).toBe(true)
})
it('restarts old AI guide checkpoints without erasing other chapter progress or setup data', () => {
  resetAdvanced('ai-setup')
  const saved = JSON.parse(JSON.stringify(advancedStore.getSnapshot()))
  delete saved.aiSetupRevision
  saved['ai-setup'] = { step: 9, completed: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], complete: true, open: false }
  saved.policy.step = 7
  localStorage.setItem(ADVANCED_KEY, JSON.stringify(saved))
  const retainedSetup = JSON.stringify(setupStore.getSnapshot())
  updateAdvanced(() => undefined)
  expect(advancedStore.getSnapshot()['ai-setup']).toMatchObject({ step: 0, completed: [], complete: false })
  expect(advancedStore.getSnapshot().policy.step).toBe(7)
  expect(JSON.stringify(setupStore.getSnapshot())).toBe(retainedSetup)
})
async function operation(id: string, type: string) { const op = await ok(`/integrations/${id}/operations`, 'POST', { type }); return ok(`/integration-operations/${op.id}`) }

describe('Setup scenarios and honest outputs', () => {
  it('uses current AI contracts, blocks missing readiness and retains a read-only transcript', async () => {
    saveDemoMode('ai-setup')
    expect(await ok('/engagements/eng-001/agent/sessions')).toEqual([])
    expect((await ok('/engagements/eng-001/agent/readiness')).overall).toBe('blocked')
    expect((await call('/engagements/eng-001/agent/sessions', 'POST', { goal: REVIEW_GOAL })).status).toBe(409)
    await ok('/playground/setup/ai-ready', 'POST', {})
    expect((await ok('/engagements/eng-001/agent/readiness')).overall).toBe('ready')
    const session = await ok('/engagements/eng-001/agent/sessions', 'POST', { goal: REVIEW_GOAL })
    expect(session.Status).toBe('succeeded')
    const detail = await ok(`/engagements/eng-001/agent/sessions/${session.ID}`)
    expect(detail.transcript[1].content).toContain('No tools, network requests or model calls')
    expect((await ok('/engagements/eng-001/agent/sessions')).length).toBe(1)
    expect((await call('/engagements/eng-001/agent/sessions', 'POST', { goal: 'Unscripted action' })).status).toBe(422)
  })
  it('records CI setup, operation state and exact/missing/ambiguous correlation without storing credentials', async () => {
    const c = await connection(), base = `/integrations/${c.id}`
    expect((await call(`${base}/enable`, 'POST', {})).status).toBe(409)
    await ok(`${base}/credentials`, 'PUT', { secrets: { username: 'demo-reader', api_token: DEMO_SECRET } })
    await operation(c.id, 'test')
    const discovery = await operation(c.id, 'discover')
    await ok(`${base}/bindings`, 'POST', { project_id: 'proj-001', external_key: discovery.pipelines[0].external_key, external_name: 'Synapse CE / main' })
    await ok(`${base}/enable`, 'POST', {})
    await operation(c.id, 'poll')
    const runs = await ok(`${base}/external-runs`)
    expect(runs.map((r: { correlation: string }) => r.correlation)).toEqual(['linked', 'missing', 'ambiguous'])
    expect(runs.map((r: { analysis_id: string }) => r.analysis_id)).toEqual(['an-001', '', ''])
    expect((await ok(`${base}/operations`)).every((o: { state: string; finished_at: string }) => o.state === 'succeeded' && o.finished_at)).toBe(true)
    expect(localStorage.getItem(SETUP_KEY)).not.toContain(DEMO_SECRET)
    expect(localStorage.getItem(SETUP_KEY)).not.toContain('demo-reader')
  })
  it('invalidates connection tests after credential replacement while retaining operation history', async () => {
    const c = await connection(), base = `/integrations/${c.id}`
    await ok(`${base}/credentials`, 'PUT', { secrets: { username: 'demo-reader', api_token: DEMO_SECRET } })
    await operation(c.id, 'test')
    await ok(`${base}/credentials`, 'PUT', { secrets: { username: 'demo-reader', api_token: DEMO_SECRET } })
    expect((await call(`${base}/enable`, 'POST', {})).status).toBe(409)
    expect((await ok(`${base}/operations`)).length).toBe(1)
    await operation(c.id, 'test')
    expect((await ok(`${base}/enable`, 'POST', {})).enabled).toBe(true)
  })
  it('requires inbound provisioning and one binding, exposes no fake polling capability', async () => {
    const providers = await ok('/integration-providers')
    expect(providers.find((p: { provider: string }) => p.provider === 'github').capabilities).toEqual([])
    const c = await ok('/integrations', 'POST', { provider: 'github', name: 'GitHub repository events', endpoint: 'https://github.com' }), base = `/integrations/${c.id}`
    expect((await call('/playground/setup/event', 'POST', {})).status).toBe(409)
    await ok(`${base}/bindings`, 'POST', { project_id: 'proj-001', external_key: '/inbound/proj-001', external_name: 'Synapse CE' })
    expect((await call(`${base}/bindings`, 'POST', { project_id: 'proj-002', external_key: '/inbound/proj-002' })).status).toBe(400)
    await ok('/playground/setup/webhook', 'POST', {})
    await ok(`${base}/enable`, 'POST', {})
    await ok('/playground/setup/event', 'POST', {})
    expect((await ok(`${base}/external-runs`))[0].analysis_id).toBe('an-001')
    expect((await call(`${base}/operations`, 'POST', { type: 'poll' })).status).toBe(422)
  })
  it('clears setup data on restart without clearing another setup chapter', async () => {
    await ok('/playground/setup/ai-ready', 'POST', {})
    await connection()
    resetAdvanced('ci-setup')
    expect(setupStore.getSnapshot().connections).toEqual([])
    expect(setupStore.getSnapshot().aiReady).toBe(true)
    for (const mode of ['ai-setup', 'ci-setup'] as const) {
      expect(ADVANCED_STEPS[mode].length).toBe(mode === 'ai-setup' ? 22 : 34)
      expect(advancedStore.getSnapshot()[mode].complete).toBe(false)
    }
  })
  it('rejects unsupported mutations instead of claiming success', async () => {
    saveDemoMode('overview')
    const r = await call('/unimplemented-example', 'POST', {})
    expect(r.status).toBe(422)
    expect((await r.json()).message).toContain('not simulated')
  })
  it('exports valid PDF, escaped HTML and a DOCX package from the same findings', async () => {
    const findings = [{ Title: '<script>alert(1)</script>', Severity: 'high', Status: 'open' }]
    const pdf = demoReport(new Request('https://demo.example/report.pdf'), 'eng-001', 'Demo', findings)
    const data = new TextDecoder().decode(await pdf.arrayBuffer())
    expect(data.startsWith('%PDF-1.4')).toBe(true)
    expect(data).toContain('Included findings: 1 of 1')
    expect(data).toContain('HIGH: 1')
    const xref = Number(data.match(/startxref\n(\d+)/)?.[1]); expect(data.slice(xref, xref + 4)).toBe('xref')
    const html = await demoReport(new Request('https://demo.example/report.html'), 'eng-001', 'Demo', findings).text()
    expect(html).not.toContain('<script>'); expect(html).toContain('&lt;script&gt;')
    const docx = new Uint8Array(await demoReport(new Request('https://demo.example/report.docx'), 'eng-001', 'Demo', findings).arrayBuffer())
    expect(strFromU8(unzipSync(docx)['word/document.xml'])).toContain('Included findings: 1 of 1')
    expect(new TextDecoder().decode(reportPDF(Array.from({ length: 100 }, (_, i) => `Finding ${i}`)))).toContain('/Count 3')
  })
  it('serves the native PDF route with a populated payload', async () => {
    saveDemoMode('overview')
    const r = await call('/engagements/eng-001/report.pdf')
    expect(r.headers.get('content-type')).toBe('application/pdf')
    expect((await r.text()).startsWith('%PDF')).toBe(true)
  })
  it('derives dependency totals and badges from the displayed components', () => {
    const graph = demoDependencies('an-001')
    expect(graph.summary.components).toBe(graph.nodes.length)
    expect(graph.summary.vulnerable).toBe(graph.nodes.filter(n => n.vulnerabilities.length).length)
    expect(graph.nodes.every(n => n.vulnerability_count === n.vulnerabilities.length && n.purl.startsWith('pkg:'))).toBe(true)
  })
  it('puts the guide beside a lower-left action and stays within a mobile viewport', () => {
    expect(guidePlacement({ top: 600, left: 24, width: 200, height: 40 }, 1280, 800).left).toBeGreaterThan(224)
    const mobile = guidePlacement({ top: 600, left: 10, width: 300, height: 40 }, 390, 844)
    expect(mobile.left).toBe(8); expect(mobile.top).toBe(80)
  })
})
