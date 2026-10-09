import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { File as NodeFile } from 'node:buffer'
import { setupServer } from 'msw/node'
import { advancedHandlers } from './handlers'
import { advancedStore, CLOSURE_REASON, GATE_KEY, OVERRIDE_REASON, PROFILE_KEY, resetAdvanced, settleAdvanced, updateAdvanced } from './store'
import { COVERAGE_ARTIFACT, ADVANCED_STEPS } from './steps'
import { INTEL_CASES, VERIFIED_COMPARISON, gateConditions, intelRunWire, policyAnalysis, remediationSummary } from './data'
import { saveDemoMode } from '../demo-mode'
import { COMPARISON_ID, CYCLE_ID, INITIAL_ID, RETEST_ID, SCENARIO_KEY } from '../scenario/store'
import { PROJECT_KEY, WORKFLOW_KEY } from '../workflows/store'
import { mapProjectOverviewResponse } from '@/lib/projectOverview'

const server = setupServer(...advancedHandlers)
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
afterEach(() => vi.unstubAllGlobals())
beforeEach(() => { localStorage.clear(); resetAdvanced('remediation'); resetAdvanced('intelligence'); resetAdvanced('policy'); saveDemoMode('remediation') })
const call = (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) => fetch(new URL(`/api/v1${path}`, window.location.origin), { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
const ok = async (path: string, method = 'GET', body?: unknown, headers?: Record<string, string>) => { const response = await call(path, method, body, headers); const result = response.status === 204 ? null : await response.json(); expect(response.ok, JSON.stringify(result)).toBe(true); return result }
const pair = { baseline_snapshot_id: `${INITIAL_ID}-snapshot-1`, current_snapshot_id: `${RETEST_ID}-snapshot-1`, mode: 'lifecycle' }
const ownership = `/engagements/${INITIAL_ID}/findings/learn-finding-1/ownership`
const assign = async (transfer = false) => { const current = await ok(ownership); return ok(ownership, 'POST', { action: transfer ? 'transfer' : 'assign', team_id: transfer ? 'team-security' : 'team-platform', assignee_id: transfer ? '' : 'user-001', clear_assignee: transfer, finding_version: current.finding_version, ownership_revision: current.assignment.revision, manual_generation: current.assignment.manual_generation }) }
describe('Isolated advanced walkthroughs', () => {
  it('preserves foundations and other advanced chapters during writes and reset', () => {
    localStorage.setItem(SCENARIO_KEY, 'foundation scan'); localStorage.setItem(WORKFLOW_KEY, 'foundation workflows')
    updateAdvanced(s => { s.intelligence.step = 3; s.intelligence.completed = [0, 1, 2]; s.policy.step = 2 })
    resetAdvanced('remediation')
    expect(advancedStore.getSnapshot().intelligence.step).toBe(3)
    expect(advancedStore.getSnapshot().policy.step).toBe(2)
    expect(localStorage.getItem(SCENARIO_KEY)).toBe('foundation scan')
    expect(localStorage.getItem(WORKFLOW_KEY)).toBe('foundation workflows')
    expect(Object.fromEntries(Object.entries(ADVANCED_STEPS).map(([k, v]) => [k, v.length]))).toEqual({ remediation: 26, intelligence: 18, policy: 21, 'ai-setup': 22, 'ci-setup': 34 })
  })
  it('rejects stale ownership versions and retains assignment and transfer decisions', async () => {
    const stale = await ok(ownership)
    await assign(); await assign(true)
    expect((await ok(ownership)).assignment).toMatchObject({ team_id: 'team-security', assignee_id: '', mode: 'manual', revision: 3 })
    expect((await ok(`${ownership}/history`)).items).toHaveLength(2)
    expect((await call(ownership, 'POST', { action: 'claim', finding_version: stale.finding_version, ownership_revision: stale.assignment.revision, manual_generation: 0 })).status).toBe(409)
    const retained = structuredClone(advancedStore.getSnapshot())
    expect((await call('/assets', 'POST', { key: 'another-asset' })).status).toBe(422)
    expect(advancedStore.getSnapshot()).toEqual(retained)
  })
  it('retains mixed evidence after a separate verification and blocks closure until authoritative exceptions are reviewed', async () => {
    await assign(); await assign(true); await ok('/assessment-comparisons', 'POST', pair)
    const initial = await ok(`/assessment-comparisons/${COMPARISON_ID}/summary?scope=all`)
    const rows = (await ok(`/assessment-comparisons/${COMPARISON_ID}/items?scope=all`)).items
    const partialLanes = (await ok(`/engagements/${RETEST_ID}/scan-status`)).engine_outcomes.filter((o: { coverage: string }) => o.coverage === 'partial').map((o: { engine: string }) => o.engine)
    const added = rows.filter((row: { presence: string }) => row.presence === 'new')
    expect(added).toHaveLength(3)
    for (const row of added) {
      expect(partialLanes).not.toContain(row.producer_kind)
      expect(advancedStore.getSnapshot().remediation.scenario.assessments[1].findings.some(f => f.id === row.identity_id)).toBe(true)
    }
    expect(initial).toMatchObject({ baseline_count: 18, fixed_count: 10, still_detected_count: 4, new_count: 3, not_evaluated_count: 4 })
    expect((await ok(`/engagements/${RETEST_ID}/scan-status`)).engine_coverage).toMatchObject({ status: 'partial', completed: 5 })
    expect((await ok(`/engagements/${RETEST_ID}/scan-runs`))[0].complete_coverage).toBe(false)
    const previewPath = `/assessment-cycles/${CYCLE_ID}/closure-previews`
    const noOverride = { reason: CLOSURE_REASON, override_blocker_ids: [], override_reason: '' }
    let preview = await ok(previewPath, 'POST', noOverride)
    expect(preview.policy.commit_allowed).toBe(false)
    expect(preview.policy.blockers[0]).toMatchObject({ overrideable: false, code: 'coverage_incomplete' })
    expect((await call(previewPath, 'POST', { ...noOverride, override_blocker_ids: ['coverage:missing-lane'] })).status).toBe(400)
    await ok('/playground/remediation/verify', 'POST')
    expect(await ok(`/assessment-comparisons/${COMPARISON_ID}/summary?scope=all`)).toEqual(initial)
    const verified = await ok(`/assessment-comparisons/${VERIFIED_COMPARISON}/summary?scope=all`)
    expect(verified).toMatchObject({ fixed_count: 14, still_detected_count: 4, new_count: 3, not_evaluated_count: 0 })
    preview = await ok(previewPath, 'POST', noOverride)
    expect(preview.policy.commit_allowed).toBe(false)
    const exception = { reason: CLOSURE_REASON, override_blocker_ids: ['release:retained-findings'], override_reason: OVERRIDE_REASON }
    preview = await ok(previewPath, 'POST', exception)
    expect(preview.policy.commit_allowed).toBe(true)
    expect((await call(`/assessment-cycles/${CYCLE_ID}/closure-commits`, 'POST', { ...exception, preview_token: 'stale' }, { 'If-Match': '3' })).status).toBe(409)
    const closed = await ok(`/assessment-cycles/${CYCLE_ID}/closure-commits`, 'POST', { ...exception, preview_token: preview.preview_token }, { 'If-Match': '3' })
    expect(closed.cycle.status).toBe('completed')
    expect(closed.manifest.override_reason).toBe(OVERRIDE_REASON)
    expect(closed.manifest.references[0].expires_at).toBeTruthy()
    expect(remediationSummary(advancedStore.getSnapshot().remediation)).toMatchObject({ not_evaluated_count: 4 })
  })
  it('recovers feeds independently, reconciles four ecosystems and acknowledges delivery without closing exposure', async () => {
    saveDemoMode('intelligence')
    await ok('/playground/intelligence/failure', 'POST')
    expect((await ok('/vulnerability/sources'))[0].health.state).toBe('failed')
    expect((await ok('/me/inbox')).items).toEqual([])
    await ok('/vulnerability/sources/learn-source/sync', 'POST', { mode: 'incremental' }); settleAdvanced(Date.now() + 3000)
    expect((await ok('/vulnerability/sources'))[1].health.stale).toBe(true)
    await ok('/vulnerability/sources/learn-osv-secondary/sync', 'POST', { mode: 'incremental' }); settleAdvanced(Date.now() + 3000)
    await ok('/me/notification-preferences', 'PUT', { event_type: 'vulnerability_action.created', channel: 'in_app', revision: 1, state: 'enabled' })
    await ok('/vulnerability/sources/learn-source/sync', 'POST', { mode: 'full' }); settleAdvanced(Date.now() + 3000)
    expect((await ok('/vulnerability/sources')).every((s: { health: { state: string } }) => s.health.state === 'healthy')).toBe(true)
    expect((await ok('/vulnerability/advisories')).items).toHaveLength(4)
    const ecosystems = []
    for (const c of INTEL_CASES) { expect((await ok(`/vulnerability/advisories/${c.id}`)).canonical.Advisory.ID).toBe(c.id); const occurrence = (await ok(`/vulnerability/occurrences?advisory_id=${c.id}`)).items[0]; ecosystems.push(occurrence.Ecosystem); expect((await ok(`/vulnerability/occurrences/${occurrence.ID}/assessments`)).items[0].FixedVersion).toBe(c.fixed) }
    expect(new Set(ecosystems)).toEqual(new Set(['npm', 'pypi', 'golang', 'maven']))
    expect((await ok('/me/inbox')).items[0].read_at).toBeUndefined()
    await ok('/me/inbox/learn-monitor-message/read', 'POST')
    expect((await ok('/me/inbox')).items[0].read_at).toBeTruthy()
    expect((await ok('/vulnerability/actions')).items).toHaveLength(4)
    const state = advancedStore.getSnapshot().intelligence
    expect(intelRunWire(state.runs.at(-1)!, state).affected_revisions).toHaveLength(4)
    expect(state.runs[0].state).toBe('failed')
  })
  it('derives gate results from evidence and retains the original policy after a synthetic CI upload', async () => {
    saveDemoMode('policy')
    const baseline = await ok(`/projects/${PROJECT_KEY}/analyses/learn-quality-analysis-main`)
    await ok('/quality-profiles/default-typescript/copy', 'POST', { key: PROFILE_KEY, name: 'Checkout TypeScript' })
    await ok(`/quality-profiles/${PROFILE_KEY}/severity`, 'POST', { rule: 'typescript:checkout-1', severity: 'high' })
    await ok(`/projects/${PROJECT_KEY}/profiles/typescript`, 'PUT', { profile: PROFILE_KEY })
    await ok('/quality-gates', 'POST', { key: GATE_KEY, name: 'Checkout Release', conditions: gateConditions })
    await ok(`/projects/${PROJECT_KEY}/gate`, 'PUT', { gate_id: GATE_KEY })
    await ok(`/projects/${PROJECT_KEY}/decoration`, 'PUT', { enabled: true })
    const boundary = 'synapse-test-coverage'
    vi.stubGlobal('File', NodeFile)
    const payload = `--${boundary}\r\nContent-Disposition: form-data; name="coverage"; filename="${COVERAGE_ARTIFACT.name}"\r\nContent-Type: text/plain\r\n\r\n${COVERAGE_ARTIFACT.content}\r\n--${boundary}--\r\n`
    const uploaded = await fetch(new URL(`/api/v1/projects/${PROJECT_KEY}/analyses`, window.location.origin), { method: 'POST', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` }, body: payload })
    expect(uploaded.ok).toBe(true); settleAdvanced(Date.now() + 4000)
    const p = advancedStore.getSnapshot().policy
    expect(policyAnalysis(p, p.quality.analyses[1])).toMatchObject({ origin: 'ci', source_ref: 'refs/pull/42/head', gate: { passed: true }, gate_info: { key: GATE_KEY } })
    expect(await ok(`/projects/${PROJECT_KEY}/analyses/learn-quality-analysis-main`)).toEqual(baseline)
    expect((await call('/quality-gates', 'DELETE')).status).toBe(422)
    expect(p.coverageImported).toBe(true)
    expect(mapProjectOverviewResponse(await ok(`/projects/${PROJECT_KEY}/overview?branch=main`)).gate?.status).toBe('failed')
    expect(mapProjectOverviewResponse(await ok(`/projects/${PROJECT_KEY}/overview?branch=improved`)).gate?.status).toBe('passed')
    expect((await ok(`/projects/${PROJECT_KEY}/hotspots?branch=improved`)).items.map((h: { status: string }) => h.status)).toEqual(['fixed', 'fixed', 'fixed'])
    expect((await ok(`/projects/${PROJECT_KEY}/hotspots?branch=main`)).items[0].status).toBe('to_review')
  })
})
