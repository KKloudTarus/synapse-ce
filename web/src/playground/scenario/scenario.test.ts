import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { scenarioHandlers } from './handlers'
import { CORE_PHASES, DEMO_ISSUES, DEMO_PACKAGES, PHASE_DURATION, SCAN_DURATION } from './catalog'
import { jobWire } from './data'
import { CYCLE_ID, DEMO_ADVISORY, EVENT_TYPE, INITIAL_ID, RETEST_ID, SCENARIO_KEY, TARGET, publishDemoAdvisory, resetScenario, scenarioStore, settleScenario, updateScenario } from './store'
import { mapEngagement } from '@/lib/api/engagements'
import { mapScanResult } from '@/lib/api/scan'
import { mapAssessmentSnapshot } from '@/lib/api/assessment-snapshots'
import { mapAssessmentComparison } from '@/lib/api/assessment-comparisons'

const server = setupServer(...scenarioHandlers, http.get('/api/v1/engagements', () => HttpResponse.json([{ id: 'original-seed' }])))
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { resetScenario(); updateScenario(s => { s.enabled = true }) })

async function call(path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) {
  return fetch(new URL(`/api/v1${path}`, window.location.origin), { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
}
async function ok(path: string, method = 'GET', body?: unknown, headers?: Record<string, string>) {
  const r = await call(path, method, body, headers)
  const value = r.status === 204 ? null : await r.json()
  expect(r.ok, JSON.stringify(value)).toBe(true)
  return value
}
async function createInitial() {
  const asset = await ok('/appsec/assets', 'POST', { key: 'checkout-api', name: 'Checkout API', owner: 'Checkout Team', type: 'application', criticality: 'high' })
  return ok('/engagements', 'POST', { asset_id: asset.id, name: 'Checkout API · Initial', in_scope: [{ kind: 'repo', value: TARGET }] })
}
async function authorize(id: string) {
  await ok(`/engagements/${id}`, 'PATCH', { status: 'active' })
  await ok(`/engagements/${id}/authorization-window`, 'PUT', { authorized_from: '2020-01-01T00:00:00Z', authorized_to: '2090-01-01T00:00:00Z', timezone: 'UTC' })
  await ok(`/engagements/${id}/roe`, 'PUT', { allowed_tool_classes: ['sca'] })
}
function scanBody(id: string, ref = id === INITIAL_ID ? 'main' : 'remediated') {
  return { engagement_id: id, target: TARGET, kind: 'git', mode: 'full', code_quality: false, ref }
}
async function scanAndFinalize(id: string) {
  await ok('/sca/scans', 'POST', scanBody(id))
  expect((await call(`/engagements/${id}/snapshots/finalize`, 'POST', { selected_runs: [{ run_id: `${id}-run-1` }] }, { 'If-Match': '0' })).status).toBe(409)
  settleScenario(Date.now() + SCAN_DURATION + 100)
  const scan = await ok(`/engagements/${id}/scan`)
  const snapshot = await ok(`/engagements/${id}/snapshots/finalize`, 'POST', { selected_runs: [{ run_id: `${id}-run-1` }] }, { 'If-Match': '0' })
  await ok(`/engagements/${id}`, 'PATCH', { status: 'completed' })
  return { scan, snapshot }
}
async function closeCycle() {
  await createInitial(); await authorize(INITIAL_ID)
  const baseline = await scanAndFinalize(INITIAL_ID)
  await ok(`/engagements/${INITIAL_ID}/retests`, 'POST', { scope_strategy: 'copy' })
  await authorize(RETEST_ID)
  const current = await scanAndFinalize(RETEST_ID)
  const diff = await ok('/assessment-comparisons', 'POST', { baseline_snapshot_id: `${INITIAL_ID}-snapshot-1`, current_snapshot_id: `${RETEST_ID}-snapshot-1`, mode: 'lifecycle' })
  const reason = 'Verified remediation with comparable coverage'
  const preview = await ok(`/assessment-cycles/${CYCLE_ID}/closure-previews`, 'POST', { reason })
  await ok(`/assessment-cycles/${CYCLE_ID}/closure-commits`, 'POST', { reason, preview_token: preview.preview_token }, { 'If-Match': String(preview.cycle_version) })
  return { baseline, current, diff }
}
async function createSource() {
  const source = { key: 'checkout-demo', name: 'Checkout demo feed', endpoint: 'https://checkout.example/advisories.json', adapter_type: 'osv', enabled: true, cadence_seconds: 86400, stale_after_seconds: 172800, sync_mode: 'incremental' }
  await ok('/vulnerability/sources/test', 'POST', { source })
  await ok('/vulnerability/sources', 'POST', source)
}
async function sync() {
  await ok('/vulnerability/sources/learn-source/sync', 'POST', { mode: 'incremental' })
  settleScenario(Date.now() + 3000)
}

describe('browser-local scan learning scenario', () => {
  it('falls through to the original seed when the walkthrough is inactive', async () => {
    updateScenario(s => { s.enabled = false })
    expect(await ok('/engagements')).toEqual([{ id: 'original-seed' }])
  })
  it('requires Asset linkage, current authorization, SCA permission and the specified source version', async () => {
    expect((await call('/engagements', 'POST', { name: 'unlinked' })).status).toBe(400)
    const wire = await createInitial()
    expect(mapEngagement(wire).businessAssetId).toBe('learn-checkout-asset')
    expect((await call('/sca/scans', 'POST', scanBody(INITIAL_ID))).status).toBe(409)
    await authorize(INITIAL_ID)
    expect((await call('/sca/scans', 'POST', scanBody(INITIAL_ID, 'wrong-branch'))).status).toBe(400)
    expect((await call('/sca/scans', 'POST', { ...scanBody(INITIAL_ID), mode: 'licenses' })).status).toBe(400)
    expect((await call(`/engagements/${INITIAL_ID}/unsupported`, 'POST', {})).status).toBe(422)
    expect(scenarioStore.getSnapshot().assessments[0].scan).toBeNull()
    await ok(`/engagements/${INITIAL_ID}/authorization-window`, 'PUT', { authorized_from: '2020-01-01T00:00:00Z', authorized_to: '2020-01-02T00:00:00Z' })
    expect((await call('/sca/scans', 'POST', scanBody(INITIAL_ID))).status).toBe(409)
  })
  it('keeps the Re-test separate and never copies execution permission', async () => {
    await createInitial(); await authorize(INITIAL_ID); await scanAndFinalize(INITIAL_ID)
    const created = await ok(`/engagements/${INITIAL_ID}/retests`, 'POST', { scope_strategy: 'copy' })
    const retest = mapEngagement(created.engagement)
    expect(retest.id).toBe(RETEST_ID)
    expect(retest.inScope).toEqual([{ kind: 'repo', value: TARGET }])
    expect(retest.authorizedFrom).toBe('')
    expect(retest.roe.allowedToolClasses).toEqual([])
    expect((await call('/sca/scans', 'POST', scanBody(RETEST_ID))).status).toBe(409)
    expect((await call(`/engagements/${INITIAL_ID}/findings/learn-finding-1`, 'PATCH', { status: 'remediated', version: 1 })).status).toBe(409)
  })
  it('enforces scope before starting and retains the inputs once a run is recorded', async () => {
    await createInitial(); await authorize(INITIAL_ID)
    await ok(`/engagements/${INITIAL_ID}/scope`, 'PUT', { in_scope: [] })
    expect((await call('/sca/scans', 'POST', scanBody(INITIAL_ID))).status).toBe(409)
    await ok(`/engagements/${INITIAL_ID}/scope`, 'PUT', { in_scope: [{ kind: 'repo', value: TARGET }], out_of_scope: [{ kind: 'repo', value: TARGET }] })
    expect((await call('/sca/scans', 'POST', scanBody(INITIAL_ID))).status).toBe(409)
    await ok(`/engagements/${INITIAL_ID}/scope`, 'PUT', { in_scope: [{ kind: 'repo', value: TARGET }], out_of_scope: [] })
    await ok('/sca/scans', 'POST', scanBody(INITIAL_ID))
    expect((await call(`/engagements/${INITIAL_ID}/scope`, 'PUT', { in_scope: [] })).status).toBe(409)
  })
  it('advances each core phase without exposing results before finalization', async () => {
    await createInitial(); await authorize(INITIAL_ID)
    await ok('/sca/scans', 'POST', scanBody(INITIAL_ID))
    const assessment = scenarioStore.getSnapshot().assessments[0]
    const started = Date.parse(assessment.scan!.startedAt)
    for (let index = 0; index < CORE_PHASES.length; index++) {
      const job = jobWire(assessment, started + index * PHASE_DURATION + 100)
      expect(job.stage).toBe(CORE_PHASES[index].stage)
      expect(job.debug_events).toHaveLength(index + 1)
      expect(job.debug_events.at(-1)?.status).toBe('running')
      expect(job.debug_events.slice(0, -1).every(event => event.status === 'completed')).toBe(true)
      expect(job.engine_coverage.completed).toBeLessThanOrEqual(job.engine_coverage.required)
    }
    settleScenario(started + SCAN_DURATION - 1)
    expect(scenarioStore.getSnapshot().assessments[0].findings).toHaveLength(0)
    expect((await call(`/engagements/${INITIAL_ID}/scan`)).status).toBe(404)
    settleScenario(started + SCAN_DURATION)
    const scan = mapScanResult(await ok(`/engagements/${INITIAL_ID}/scan`))
    expect(scan.findings).toHaveLength(DEMO_ISSUES.length)
    expect(new Set(scan.findings.map(finding => finding.kind))).toEqual(new Set(['vulnerability', 'sast', 'secret', 'misconfig', 'license']))
    expect(new Set(scan.findings.map(finding => finding.severity))).toEqual(new Set(['critical', 'high', 'medium', 'low', 'info']))
    expect(scan.languages.map(l => l.name)).toEqual(['TypeScript', 'Go', 'Python', 'Java', 'JavaScript'])
    expect(scan.languages.reduce((sum, l) => sum + l.percent, 0)).toBe(100)
    expect(new Set(scan.components.map(c => c.purl.split(':')[1].split('/')[0]))).toEqual(new Set(['npm', 'pypi', 'golang', 'maven']))
    expect(scan.components).toHaveLength(12)
    expect(scan.licenseCoverage.unknown).toBe(1)
    expect(scan.engineCoverage).toMatchObject({ status: 'complete', required: 7, completed: 7 })
  })
  it('persists triage, assignment, comments and downloadable evidence using the UI wire contract', async () => {
    await createInitial(); await authorize(INITIAL_ID)
    await ok('/sca/scans', 'POST', scanBody(INITIAL_ID)); settleScenario(Date.now() + SCAN_DURATION + 100)
    const path = `/engagements/${INITIAL_ID}/findings/learn-finding-1`
    const confirmed = await ok(path, 'PATCH', { status: 'confirmed', version: 1 })
    expect(confirmed.DedupKey).toBe('vuln:DEMO-CHECKOUT-001:checkout-parser:1.0.0')
    await ok(path + '/assignee', 'PUT', { assignee: 'user-001', version: confirmed.Version })
    await ok(path + '/comments', 'POST', { body: 'Verified inventory; upgrade and re-test.' })
    expect((await ok(path + '/comments'))[0]).toMatchObject({ Author: 'admin@synapse.local', Body: 'Verified inventory; upgrade and re-test.' })
    expect(await ok(path + '/ownership')).toMatchObject({ assignment: { assignee_id: 'user-001' }, resolution: 'resolved' })
    const evidence = await call(`/engagements/${INITIAL_ID}/evidence/demo/scan-log.txt`)
    expect(evidence.headers.get('Content-Type')).toBe('text/plain')
    expect(await evidence.text()).toContain('Branch: main')
  })
  it('maps complete runs, immutable snapshots, and the 18 Fixed / 0 New / 0 Persistent comparison into the existing UI contract', async () => {
    const { baseline, current, diff } = await closeCycle()
    expect(mapScanResult(baseline.scan).vulnerabilities).toHaveLength(8)
    expect(mapScanResult(current.scan).vulnerabilities).toHaveLength(0)
    expect(mapScanResult(current.scan).components.map(c => c.version)).toEqual(DEMO_PACKAGES.map(p => p.fixed))
    expect(mapAssessmentSnapshot(current.snapshot.snapshot).dimensions.every(d => d.state === 'complete')).toBe(true)
    expect(mapAssessmentComparison(diff.comparison).summary).toMatchObject({ fixedCount: 18, currentCount: 0, newCount: 0, stillDetectedCount: 0, notEvaluatedCount: 0 })
    for (const [scope, count] of [['vulnerability', 8], ['security', 16], ['all', 18]] as const) {
      const root = '/assessment-comparisons/learn-checkout-comparison'
      expect(await ok(`${root}/summary?scope=${scope}`)).toMatchObject({ fixed_count: count, baseline_count: count })
      expect((await ok(`${root}/items?scope=${scope}`)).items).toHaveLength(count)
    }
    const configItems = await ok('/assessment-comparisons/learn-checkout-comparison/items?scope=security&finding_kind=misconfig&producer=iac')
    expect(configItems.items).toHaveLength(2)
    expect(configItems.items.every((item: { finding_kind: string }) => item.finding_kind === 'misconfig')).toBe(true)
    expect((await call(`/engagements/${RETEST_ID}/snapshots/finalize`, 'POST', { selected_runs: [] }, { 'If-Match': '0' })).status).toBe(409)
  })
  it('publishes → syncs → matches → notifies once, without rewriting historical snapshots or the downloaded report', async () => {
    await closeCycle(); await createSource()
    const preference = await ok('/me/notification-preferences', 'PUT', { event_type: EVENT_TYPE, channel: 'in_app', state: 'enabled', revision: 1 })
    expect(preference).toMatchObject({ state: 'enabled', revision: 2 })
    const reportPath = `/assessment-cycles/${CYCLE_ID}/closure-manifests/learn-checkout-closure/report`
    const beforeReport = await (await call(reportPath)).text()
    const report = JSON.parse(beforeReport)
    expect(report.manifest.demo).toBe(true)
    expect(report.manifest.content_hash).toBe('DEMO-NOT-A-CRYPTOGRAPHIC-DIGEST')
    const beforeSnapshot = await ok(`/assessment-snapshots/${RETEST_ID}-snapshot-1`)
    await sync()
    expect((await ok('/me/inbox')).items).toEqual([])
    publishDemoAdvisory()
    expect((await ok('/me/inbox')).items).toEqual([])
    await ok('/vulnerability/sources/learn-source/sync', 'POST', { mode: 'incremental' })
    expect((await ok('/me/inbox')).items).toEqual([])
    settleScenario(Date.now() + 3000)
    expect((await ok('/vulnerability/occurrences?advisory_id=' + DEMO_ADVISORY)).items[0]).toMatchObject({ Package: 'checkout-token', ComponentVersion: '2.0.0', FixedVersion: '2.0.1', EngagementID: RETEST_ID })
    expect((await ok('/me/inbox')).items).toHaveLength(1)
    expect(await ok('/me/inbox/unread')).toEqual({ unread: 1 })
    await sync()
    expect((await ok('/me/inbox')).items).toHaveLength(1)
    expect((await ok('/vulnerability/sync-runs')).items[0].counts).toMatchObject({ inserted: 0, unchanged: 1 })
    expect(await ok('/me/notification-preferences', 'PUT', { ...preference, state: 'disabled' })).toMatchObject({ state: 'disabled', revision: 3 })
    expect((await ok('/me/inbox')).items).toHaveLength(1)
    expect(await (await call(reportPath)).text()).toBe(beforeReport)
    expect(await ok(`/assessment-snapshots/${RETEST_ID}-snapshot-1`)).toEqual(beforeSnapshot)
    expect((await ok(`/engagements/${RETEST_ID}/findings`))).toEqual([])
    await ok('/me/inbox/learn-monitor-message/read', 'POST')
    expect(await ok('/me/inbox/unread')).toEqual({ unread: 0 })
    await ok(`/vulnerability/advisories/${DEMO_ADVISORY}`)
    expect(scenarioStore.getSnapshot().monitorInvestigated).toBe(false)
    await ok('/vulnerability/occurrences/learn-token-occurrence/assessments')
    expect(scenarioStore.getSnapshot().monitorInvestigated).toBe(true)
  })
  it('does not notify before a matching retained inventory exists, or when delivery is disabled', async () => {
    await createSource()
    publishDemoAdvisory()
    expect(scenarioStore.getSnapshot().feedPublished).toBe(false)
    await sync()
    expect((await ok('/me/inbox')).items).toHaveLength(0)
    await closeCycle()
    await ok('/me/notification-preferences', 'PUT', { event_type: EVENT_TYPE, channel: 'in_app', state: 'disabled', revision: 1 })
    publishDemoAdvisory(); await sync()
    expect((await ok('/vulnerability/actions')).items).toHaveLength(1)
    expect((await ok('/me/inbox')).items).toHaveLength(0)
    await ok('/me/notification-preferences', 'PUT', { event_type: EVENT_TYPE, channel: 'in_app', state: 'enabled', revision: 2 })
    await sync()
    expect((await ok('/me/inbox')).items).toHaveLength(0)
  })
  it('persists progress with the same dataset and scopes reset to the exercise', async () => {
    await createInitial()
    localStorage.setItem('synapse-theme', 'dark')
    updateScenario(s => { s.step = 2; s.completed = ['asset', 'engagement']; s.open = false })
    const saved = JSON.parse(localStorage.getItem(SCENARIO_KEY)!)
    expect(saved).toMatchObject({ step: 2, open: false, asset: { key: 'checkout-api' }, assessments: [{ id: INITIAL_ID }] })
    vi.resetModules()
    const restored = await import('./store')
    expect(restored.scenarioStore.getSnapshot()).toMatchObject(saved)
    resetScenario()
    expect(localStorage.getItem(SCENARIO_KEY)).toBeNull()
    expect(localStorage.getItem('synapse-theme')).toBe('dark')
  })
})
