import { demoReport } from '../demo-report'
import { http, HttpResponse } from 'msw'
import { DEMO_ISSUES, DEMO_PACKAGES } from './catalog'
import { CYCLE_ID, DEMO_ADVISORY, EVENT_TYPE, INITIAL_ID, RETEST_ID, TARGET, initial, retest, scenarioStore, settleScenario, updateScenario, type DemoAssessment, type Scenario } from './store'
import { ACTOR, COMPARISON_ID, MANIFEST_ID, actionWire, advisoryWire, closureManifest, closurePreview, comparisonItems, comparisonWire, components, cycleWire, engagementWire, findingWire, inboxItems, inComparisonScope, jobWire, lifecycleWire, members, occurrenceWire, runId, runWire, scanWire, snapshotId, snapshotWire, sourceWire, summaryWire, syncWire } from './data'

const json = (value: unknown, status = 200) => new HttpResponse(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const error = (message: string, status = 400) => json({ error: message, message }, status)
const noContent = () => new HttpResponse(null, { status: 204 })
const text = (x: unknown, max = 512) => typeof x === 'string' ? x.trim().slice(0, max) : ''
type Body = Record<string, unknown>
const targets = (v: unknown) => Array.isArray(v) ? v.slice(0, 10).map(t => ({ kind: text(t?.kind, 32), value: text(t?.value) })).filter(t => t.value) : []
const now = () => new Date().toISOString()
const authorized = (a: DemoAssessment) => a.status === 'active' && a.tools.includes('sca') && Date.parse(a.authorizedFrom) <= Date.now() && Date.parse(a.authorizedTo) > Date.now()
const preference = (s: Scenario) => {
  return { event_type: EVENT_TYPE, channel: 'in_app', state: s.notificationPreference, revision: s.preferenceRevision, mandatory: false, available: true, reason: 'Playground demo exposure notifications' }
}

// These routes precede the original fixtures only in a playground build. Returning undefined lets
// MSW continue to the original handler; it never sends exercise requests to a real backend.
export function createScenarioHandlers(backend = { getSnapshot: scenarioStore.getSnapshot, update: updateScenario, settle: settleScenario }) {
const scenarioStore = backend, updateScenario = backend.update, settleScenario = backend.settle
return [http.all('/api/v1/*', async ({ request }) => {
  settleScenario()
  let s = scenarioStore.getSnapshot()
  const url = new URL(request.url)
  const path = decodeURIComponent(url.pathname.slice('/api/v1'.length))
  const method = request.method
  if (path === '/me' && method === 'GET') return json({ id: 'user-001', username: 'admin', display_name: 'Admin User', email: ACTOR, role: 'admin', features: { assessment_lifecycle_read: true, assessment_lifecycle_ui_default: true } })
  if (!s.enabled) return
  let b: Body = {}
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    try { const raw = await request.text(); b = raw ? JSON.parse(raw) as Body : {} } catch { return error('This exercise accepts JSON forms only.') }
    if (!b || typeof b !== 'object' || Array.isArray(b)) return error('Submit a JSON object.')
  }
  const refresh = () => { s = scenarioStore.getSnapshot() }
  const patchAssessment = (id: string, change: (a: DemoAssessment) => void) => {
    updateScenario(d => { const a = d.assessments.find(x => x.id === id); if (a) change(a) }); refresh()
    return json(engagementWire(s.assessments.find(x => x.id === id)!, s))
  }

  if (path === '/appsec/assets') {
    if (method === 'GET') {
      let items = s.asset ? [s.asset] : []
      const q = url.searchParams.get('q')?.toLowerCase()
      if (q) items = items.filter(a => `${a.key} ${a.name}`.toLowerCase().includes(q))
      for (const field of ['type', 'criticality', 'lifecycle'] as const) {
        const value = url.searchParams.get(field)
        if (value) items = items.filter(a => (field === 'lifecycle' ? 'active' : a[field]) === value)
      }
      const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0)
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit')) || 50))
      return json({ items: items.slice(offset, offset + limit).map(a => ({ ...a, lifecycle: 'active', version: 1 })), total: items.length, limit, offset })
    }
    if (method === 'POST') {
      if (s.asset) return error('The walkthrough Asset already exists. Open it or reset the exercise.', 409)
      const key = text(b.key, 64)
      if (!/^[a-z0-9][a-z0-9-]*$/.test(key) || !text(b.name) || !text(b.owner)) return error('Enter a lowercase key, name, and owner.')
      updateScenario(d => { d.asset = { id: 'learn-checkout-asset', key, name: text(b.name), owner: text(b.owner), description: text(b.description, 2000), type: text(b.type) || 'application', criticality: text(b.criticality) || 'high', created_at: now() } })
      refresh(); return json({ ...s.asset!, lifecycle: 'active', version: 1 }, 201)
    }
  }
  if (path === '/appsec/asset-counts' && method === 'GET') return json({ by_criticality: s.asset ? { [s.asset.criticality]: 1 } : {}, total: s.asset ? 1 : 0 })
  const assetMatch = path.match(/^\/appsec\/assets\/([^/]+)(?:\/(.+))?$/)
  if (assetMatch && s.asset && [s.asset.id, s.asset.key].includes(assetMatch[1])) {
    const tab = assetMatch[2]
    if (method !== 'GET') return error('Asset editing is outside this exercise.', 422)
    if (!tab) return json({ ...s.asset, lifecycle: 'active', version: 1 })
    if (tab === 'engagements') return json(s.assessments.map(a => engagementWire(a, s)))
    if (tab === 'projects' || tab === 'technical-assets') return json([])
    if (tab === 'findings') return json(s.assessments.flatMap(a => a.findings.map(f => ({ finding: findingWire(a, f), engagement_id: a.id, engagement_name: a.name, reachability: { state: 'unknown', tier: 'tier-0', confidence: 0, path: [], history: [] } }))))
    const latest = retest(s)?.scan?.finishedAt ? retest(s) : initial(s)
    if (tab === 'coverage') return json({ rows: latest?.scan?.finishedAt ? [{ kind: 'repository', component_id: 'learn-repository', name: TARGET, verdict: 'covered', engagement_id: latest.id, last_assessed: latest.scan.finishedAt, freshness_target_days: 30 }] : [], counts: { covered: latest?.scan?.finishedAt ? 1 : 0 }, freshness_target_days: 30 })
    if (tab === 'posture') return json({ rating: s.correlatedAt ? 'attention' : latest?.scan?.finishedAt ? latest.findings.length ? 'attention' : 'good' : 'unknown', explanation: 'Demo posture follows the latest recorded inventory; older assessment findings remain historical.', finding_counts: { total: latest?.findings.length ?? 0 }, coverage_counts: {} })
    if (tab === 'history') return json(s.assessments.map(a => ({ engagement_id: a.id, name: a.name, status: a.status, scope_count: a.scope.length, finding_count: a.findings.length, retest_count: a.id === INITIAL_ID && retest(s) ? 1 : 0, updated_at: a.createdAt, authorized_from: a.authorizedFrom, authorized_to: a.authorizedTo })))
  }

  if (path === '/engagements') {
    if (method === 'GET') return json(s.assessments.map(a => engagementWire(a, s)))
    if (method === 'POST') {
      if (!s.asset || b.asset_id !== s.asset.id) return error('Create and select the walkthrough Asset first.')
      if (initial(s)) return error('The initial assessment already exists. Continue from its detail page.', 409)
      if (!text(b.name) || !targets(b.in_scope).some(t => t.value === TARGET)) return error(`Use the demo repository ${TARGET} as an in-scope target.`)
      const a: DemoAssessment = { id: INITIAL_ID, name: text(b.name), client: text(b.client), status: 'draft', createdAt: now(), scope: targets(b.in_scope), outOfScope: targets(b.out_of_scope), authorizedFrom: text(b.authorized_from), authorizedTo: text(b.authorized_to), timezone: text(b.timezone), tools: [], scan: null, snapshotAt: null, findings: [] }
      updateScenario(d => { d.assessments.push(a) }); refresh(); return json(engagementWire(a, s), 201)
    }
  }
  if (path === '/sca/scans' && method === 'POST') {
    const a = s.assessments.find(x => x.id === b.engagement_id)
    if (!a) return error('Choose the walkthrough assessment.')
    if (!authorized(a)) return error('Activate the Assessment, save a current authorization window, and allow sca in Rules of Engagement.', 409)
    if (!a.scope.some(t => t.kind === 'repo' && t.value === TARGET) || a.outOfScope.length) return error('Keep the demo repository in scope with no exclusions for this comparable exercise.', 409)
    if (a.snapshotAt || s.closure) return error('This assessment has a finalized snapshot. Create a Re-test.', 409)
    if (a.scan) return error('This exercise retains one run per assessment. Continue with the existing run or reset.', 409)
    if (b.target !== TARGET || b.kind !== 'git' || b.mode !== 'full' || b.code_quality === true) return error('Use the demo Git repository, Full mode, and leave static code quality off for this exercise.')
    if (text(b.ref) !== (a.id === RETEST_ID ? 'remediated' : 'main')) return error(`Set Git branch to ${a.id === RETEST_ID ? 'remediated' : 'main'} in Scan Settings.`)
    patchAssessment(a.id, draft => { draft.scan = { target: TARGET, kind: 'git', mode: 'full', ref: text(b.ref), startedAt: now(), finishedAt: null } })
    return json(jobWire(s.assessments.find(x => x.id === a.id)!))
  }
  const engMatch = path.match(/^\/engagements\/([^/]+)(?:\/(.+))?$/)
  if (engMatch && [INITIAL_ID, RETEST_ID].includes(engMatch[1])) {
    const a = s.assessments.find(x => x.id === engMatch[1])
    if (!a) return error('Assessment not created yet.', 404)
    const tab = engMatch[2]
    if (!tab) {
      if (method === 'GET') return json(engagementWire(a, s))
      if (method === 'PATCH') {
        const status = text(b.status)
        if (!(a.status === 'draft' && status === 'active' || a.status === 'active' && status === 'completed')) return error('Use Draft → Active → Completed in this exercise.', 409)
        if (status === 'completed' && !a.snapshotAt) return error('Finalize the assessment snapshot before completing it.', 409)
        return patchAssessment(a.id, d => { d.status = status })
      }
    }
    if (['authorization-window', 'roe', 'scope'].includes(tab) && method === 'PUT') {
      if (a.scan || a.snapshotAt || s.closure) return error('Recorded assessment inputs are retained. Create a Re-test for new inputs.', 409)
      if (tab === 'authorization-window') {
        const from = text(b.authorized_from), to = text(b.authorized_to)
        if (!Number.isFinite(Date.parse(from)) || !Number.isFinite(Date.parse(to)) || Date.parse(from) >= Date.parse(to)) return error('Authorization start must be before end.')
        return patchAssessment(a.id, d => { d.authorizedFrom = from; d.authorizedTo = to; d.timezone = text(b.timezone) })
      }
      if (tab === 'roe') {
        if (Array.isArray(b.blackouts) && b.blackouts.length) return error('Blackout simulation is outside this exercise.', 422)
        return patchAssessment(a.id, d => { d.tools = Array.isArray(b.allowed_tool_classes) ? b.allowed_tool_classes.map(x => text(x, 32)).filter(Boolean) : [] })
      }
      return patchAssessment(a.id, d => { d.scope = targets(b.in_scope); d.outOfScope = targets(b.out_of_scope) })
    }
    if (tab === 'source' || tab === 'sbom') return error('This exercise uses a linked Git repository.', 404)
    if (tab === 'scan-status' && method === 'GET') return a.scan ? json(jobWire(a)) : error('No scan job yet.', 404)
    if (tab === 'scan' && method === 'GET') return a.scan?.finishedAt ? json(scanWire(a)) : error('No completed scan yet.', 404)
    if (tab === 'scan-runs' && method === 'GET') return json(a.scan?.finishedAt ? [runWire(a)] : [])
    if (/^report\.(pdf|html|docx)$/.test(tab ?? '') && method === 'GET') return demoReport(request, a.id, a.name, a.findings.map(f => findingWire(a, f)))
    if (tab === 'findings' && method === 'GET') return json(a.findings.map(f => findingWire(a, f)))
    const findingMatch = tab?.match(/^findings\/([^/]+)(?:\/(.+))?$/)
    if (findingMatch) {
      const f = a.findings.find(x => x.id === findingMatch[1])
      if (!f) return error('Finding not found.', 404)
      const action = findingMatch[2]
      if (method === 'GET' && !action) return json(findingWire(a, f))
      if (method === 'GET' && action === 'comments') return json(f.comments.map(c => ({ ID: c.id, FindingID: f.id, Body: c.body, Author: ACTOR, CreatedAt: c.created_at })))
      if (method === 'GET' && ['retests', 'judgments'].includes(action)) return json([])
      if (method === 'GET' && action?.startsWith('ownership')) return json(action.endsWith('/history') ? { items: [] } : { assignment: { team_id: '', assignee_id: f.assignee, mode: 'manual', revision: 1, manual_generation: 0 }, finding_version: f.version, finding_assignee: f.assignee, resolution: f.assignee ? 'resolved' : 'unresolved', reason: 'Playground personal assignment', updated_at: a.scan?.finishedAt })
      if (a.snapshotAt) return error('Triage the finding before finalizing this training snapshot.', 409)
      if ((!action && method === 'PATCH') || (action === 'assignee' && method === 'PUT')) {
        if (Number(b.version) !== f.version) return error('Finding version changed. Refresh and retry.', 409)
        if (!action && !['open', 'triage', 'confirmed', 'false_positive', 'remediated'].includes(text(b.status))) return error('Choose a valid triage status.')
        patchAssessment(a.id, d => { const row = d.findings.find(x => x.id === f.id)!; if (action) row.assignee = text(b.assignee); else row.status = text(b.status); row.version++ })
        return json({ ...findingWire(s.assessments.find(x => x.id === a.id)!, s.assessments.find(x => x.id === a.id)!.findings.find(x => x.id === f.id)!), assignee_user_id: action ? text(b.assignee) : f.assignee || undefined })
      }
      if (action === 'comments' && method === 'POST') {
        if (!text(b.body)) return error('Add a non-empty investigation note.')
        const c = { id: `learn-comment-${f.comments.length + 1}`, body: text(b.body, 2000), created_at: now() }
        patchAssessment(a.id, d => { d.findings.find(x => x.id === f.id)!.comments.push(c) })
        return json({ ID: c.id, FindingID: f.id, Body: c.body, Author: ACTOR, CreatedAt: c.created_at }, 201)
      }
    }
    if (tab === 'evidence' && method === 'GET') return json({ items: a.scan?.finishedAt ? [{ ID: `${a.id}-evidence`, Kind: 'terminal_log', Content: btoa('DEMO: three lockfiles resolved twelve packages. Eighteen synthetic dependency, source, secret, configuration and license findings on main; none on remediated. No real tools executed.'), Hash: 'd'.repeat(64), PreviousHash: '', StorageRef: 'demo/scan-log.txt', CreatedBy: ACTOR, CreatedAt: a.scan.finishedAt }] : [], intact: true, head: 'd'.repeat(64), verified: a.scan?.finishedAt ? 1 : 0, error: '' })
    if (tab === 'evidence/demo/scan-log.txt' && method === 'GET' && a.scan?.finishedAt) return new HttpResponse(`DEMO scan log\nRepository: ${TARGET}\nBranch: ${a.scan.ref}\nComponents: ${DEMO_PACKAGES.length}\nFindings: ${a.id === INITIAL_ID ? DEMO_ISSUES.length : 0}\nDependency advisories: ${a.id === INITIAL_ID ? 8 : 0}\nCoverage: complete (simulated)\nNo scanner, repository clone, or cryptographic verification executed.`, { headers: { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="checkout-demo-scan-log.txt"' } })
    if (tab === 'lifecycle' && method === 'GET') return json({ assessment_id: a.id, ...lifecycleWire(s) })
    if (tab === 'retests' && method === 'POST') {
      if (a.id !== INITIAL_ID || a.status !== 'completed' || s.closure) return error('Complete the initial Assessment in an open Cycle first.', 409)
      if (retest(s)) return error('Re-test #1 already exists. Open it to continue.', 409)
      if (b.scope_strategy !== 'copy') return error('Copy the scope to keep this Re-test comparable.')
      const r: DemoAssessment = { ...structuredClone(a), id: RETEST_ID, name: text(b.name) || `${s.asset!.name} · Re-test #1`, status: 'draft', createdAt: now(), authorizedFrom: '', authorizedTo: '', tools: [], scan: null, snapshotAt: null, findings: [] }
      updateScenario(d => { d.assessments.push(r) }); refresh()
      return json({ engagement: engagementWire(r, s), cycle: cycleWire(s), member: members(s).at(-1), inheritance_diff: { scope: 'copy', authorization: 'explicit_only', roe: 'explicit_only', scanner_profile: 'none' }, warnings: [] }, 201)
    }
    if (tab === 'snapshots' && method === 'GET') return json({ items: a.snapshotAt ? [snapshotWire(a, s)] : [], next_cursor: '', default_snapshot_id: a.snapshotAt ? snapshotId(a) : '', default_version: a.snapshotAt ? 1 : 0 })
    if (tab === 'snapshots/finalize' && method === 'POST') {
      if (!a.scan?.finishedAt || a.status !== 'active' || s.closure) return error('A completed scan in an active assessment is required.', 409)
      if (a.snapshotAt || request.headers.get('If-Match') !== '0') return error('snapshot_conflict', 409)
      const runs = b.selected_runs as { run_id?: string }[] | undefined
      if (!Array.isArray(runs) || runs.length !== 1 || runs[0].run_id !== runId(a)) return error('Select the completed walkthrough scan run.')
      patchAssessment(a.id, d => { d.snapshotAt = now() })
      return json({ snapshot: snapshotWire(s.assessments.find(x => x.id === a.id)!, s), default_version: 1 }, 201)
    }
    if (tab === 'vulnerability/occurrences' && method === 'GET') return json({ items: a.id === RETEST_ID && s.correlatedAt ? [occurrenceWire(s)] : [] })
    if (tab === 'vulnerability/actions' && method === 'GET') return json({ items: a.id === RETEST_ID && s.correlatedAt ? [actionWire(s)] : [] })
    if (method === 'GET' && ['credentials', 'activity', 'imported-findings', 'sarif', 'judgments'].includes(tab)) return json([])
    if (method === 'GET' && tab === 'slas') return json({ slas: [] })
    // Never claim success for an exercise mutation that has no state transition.
    return error(`The walkthrough does not simulate ${method} ${tab ?? 'assessment'}.`, 422)
  }
  if (path.startsWith('/assessment-snapshots/') && method === 'GET') {
    const a = s.assessments.find(x => snapshotId(x) === path.split('/')[2] && x.snapshotAt)
    return a ? json(snapshotWire(a, s)) : error('Snapshot not finalized yet.', 404)
  }
  if (path === '/assessment-comparisons' && method === 'POST') {
    if (!initial(s)?.snapshotAt || !retest(s)?.snapshotAt || b.baseline_snapshot_id !== snapshotId(initial(s)!) || b.current_snapshot_id !== snapshotId(retest(s)!) || b.mode !== 'lifecycle') return error('Choose the initial Snapshot as baseline and the Re-test Snapshot as current.')
    const created = !s.comparisonAt
    if (created) updateScenario(d => { d.comparisonAt = now() })
    refresh(); return json({ comparison: comparisonWire(s), created })
  }
  if (path.startsWith(`/assessment-comparisons/${COMPARISON_ID}`) && method === 'GET') {
    if (!s.comparisonAt) return error('Comparison not created.', 404)
    if (path.endsWith('/summary')) return json(summaryWire(s, url.searchParams.get('scope')))
    if (path.endsWith('/items')) {
      let items = comparisonItems(s).filter(item => inComparisonScope(item.finding_kind, url.searchParams.get('scope')))
      const presence = url.searchParams.get('presence'), severity = url.searchParams.get('severity')
      const kind = url.searchParams.get('finding_kind'), producer = url.searchParams.get('producer')
      if (presence) items = items.filter(x => x.presence === presence)
      if (severity) items = items.filter(x => x.baseline_observation.severity === severity)
      if (kind) items = items.filter(x => x.finding_kind === kind)
      if (producer) items = items.filter(x => x.producer_kind === producer)
      return json({ items, next_cursor: '' })
    }
    return json(comparisonWire(s))
  }
  if (path === '/assessment-cycles' && method === 'GET') return json({ items: initial(s) ? [{ ...cycleWire(s), member_count: s.assessments.length, active_branch_count: 1, latest_assessment_id: s.assessments.at(-1)?.id, latest_retest_number: retest(s) ? 1 : 0, members: members(s), root_snapshot_id: initial(s)?.snapshotAt ? snapshotId(initial(s)!) : '', current_snapshot_id: retest(s)?.snapshotAt ? snapshotId(retest(s)!) : '', comparison_id: s.comparisonAt ? COMPARISON_ID : '', comparison_status: s.comparisonAt ? 'complete' : '', comparison_summary: s.comparisonAt ? summaryWire(s) : null }] : [], next_cursor: '', migration_pending: [], migration_pending_total: 0 })
  if (path.startsWith(`/assessment-cycles/${CYCLE_ID}`)) {
    if (!initial(s)) return error('Cycle not created.', 404)
    const action = path.slice(`/assessment-cycles/${CYCLE_ID}`.length)
    if (method === 'GET' && !action) return json(lifecycleWire(s))
    if (method === 'GET' && action === '/members') return json({ items: members(s), next_cursor: '' })
    if (method === 'GET' && action === '/closure-manifests') return json({ items: s.closure ? [closureManifest(s)] : [] })
    if (method === 'GET' && action === `/closure-manifests/${MANIFEST_ID}/report`) {
      if (!s.closure) return error('Close the Cycle before downloading its report.', 409)
      const report = { demo: true, notice: 'Simulated assessment closure report. No scanner or cryptographic verification executed.', manifest: closureManifest(s), comparison: summaryWire(s), inventory: components(retest(s)!) }
      updateScenario(d => { d.reportDownloaded = true })
      return new HttpResponse(JSON.stringify(report, null, 2), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="checkout-demo-closure.json"' } })
    }
    if (action === '/closure-previews' && method === 'POST') {
      if (retest(s)?.status !== 'completed' || !s.comparisonAt || s.closure) return error('Complete the Re-test and compare its finalized Snapshot first.', 409)
      if (!text(b.reason)) return error('Explain why this Cycle is ready to close.')
      updateScenario(d => { d.preview = { token: crypto.randomUUID(), expiresAt: new Date(Date.now() + 600_000).toISOString(), reason: text(b.reason) } })
      refresh(); return json(closurePreview(s))
    }
    if (action === '/closure-commits' && method === 'POST') {
      if (!s.preview || s.closure || b.preview_token !== s.preview.token || Date.parse(s.preview.expiresAt) <= Date.now() || text(b.reason) !== s.preview.reason || request.headers.get('If-Match')?.replaceAll('"', '') !== String(cycleWire(s).version)) return error('Closure preview is stale. Generate a new preview.', 409)
      updateScenario(d => { d.closure = { at: now(), reason: d.preview!.reason, token: d.preview!.token } })
      refresh(); return json({ cycle: cycleWire(s), manifest: closureManifest(s), report_job_id: 'learn-report-job' })
    }
    return error('This Cycle command is outside the walkthrough.', 422)
  }

  if (path === '/users/picker' && method === 'GET') return json({ items: [{ id: 'user-001', name: 'Admin User', display_name: 'Admin User', username: 'admin', email: ACTOR }], next: '' })
  if (path === '/me/notification-preferences') {
    if (method === 'GET') return json({ items: [preference(s)] })
    if (method === 'PUT') {
      if (b.event_type !== EVENT_TYPE || b.channel !== 'in_app' || Number(b.revision) !== s.preferenceRevision || !['inherit', 'enabled', 'disabled'].includes(text(b.state))) return error('Refresh notification preferences and retry.', 409)
      updateScenario(d => { d.notificationPreference = b.state as typeof d.notificationPreference; d.preferenceRevision++ })
      refresh()
      return json(preference(s))
    }
  }
  if (path === '/me/inbox' && method === 'GET') return json({ items: inboxItems(s).filter(x => url.searchParams.get('unread') !== 'true' || !x.read_at), next: '' })
  if (path === '/me/inbox/unread' && method === 'GET') return json({ unread: inboxItems(s).filter(x => !x.read_at).length })
  if ((path === '/me/inbox/learn-monitor-message/read' || path === '/me/inbox/read') && method === 'POST') {
    if (s.correlatedAt) updateScenario(d => { d.notificationReadAt = now() })
    if (typeof document !== 'undefined') document.dispatchEvent(new Event('visibilitychange'))
    return noContent()
  }

  if (path === '/vulnerability/sources/types' && method === 'GET') return json([{ type: 'osv', implemented: true, supports_test: true, supports_credentials: false }])
  if (path === '/vulnerability/sources/test' && method === 'POST') {
    const source = b.source as Body | undefined
    if (source?.endpoint !== 'https://checkout.example/advisories.json' || source?.adapter_type !== 'osv') return error('Use the simulated OSV feed https://checkout.example/advisories.json. No network connection is made.')
    updateScenario(d => { d.connectionTested = true }); return noContent()
  }
  if (path === '/vulnerability/sources') {
    if (method === 'GET') return json(s.source ? [sourceWire(s)] : [])
    if (method === 'POST') {
      if (s.source) return error('Demo source already exists.', 409)
      if (!s.connectionTested || b.endpoint !== 'https://checkout.example/advisories.json' || b.adapter_type !== 'osv' || !text(b.key) || !text(b.name) || !b.enabled || Number(b.cadence_seconds) <= 0 || Number(b.stale_after_seconds) < Number(b.cadence_seconds)) return error('Test the demo connection, enable the source, and set stale threshold at least as long as its cadence.')
      if (text(b.credential_ref)) return error('The demo feed does not require credentials. Leave Credential reference empty.')
      updateScenario(d => { d.source = { id: 'learn-source', key: text(b.key, 64), name: text(b.name), endpoint: 'https://checkout.example/advisories.json', adapter_type: 'osv', enabled: true, cadence_seconds: Number(b.cadence_seconds), stale_after_seconds: Number(b.stale_after_seconds), sync_mode: text(b.sync_mode) || 'incremental', version: 1, created_at: now() } })
      refresh(); return json(sourceWire(s), 201)
    }
  }
  const sourceMatch = path.match(/^\/vulnerability\/sources\/learn-source\/(sync|test|enable|disable)$/)
  if (sourceMatch && method === 'POST' && s.source) {
    const action = sourceMatch[1]
    if (action === 'test') return noContent()
    if (action === 'enable' || action === 'disable') { updateScenario(d => { d.source!.enabled = action === 'enable'; d.source!.version++ }); refresh(); return json(sourceWire(s)) }
    if (!s.source.enabled) return error('Enable the source before syncing.', 409)
    if (s.syncs.some(r => !r.finishedAt)) return error('A demo sync is already running.', 409)
    if (s.syncs.length >= 100) return error('Reset the exercise to start more demo syncs.', 409)
    const id = `learn-sync-${s.syncs.length + 1}`
    updateScenario(d => { d.syncs.push({ id, startedAt: now(), finishedAt: null, feedPublished: d.feedPublished, mode: text(b.mode) || 'incremental' }) })
    return json({ run_id: id, source_id: s.source.id, mode: text(b.mode) || 'incremental', state: 'running', created: true }, 202)
  }
  if (path === '/vulnerability/sync-runs' && method === 'GET') return json({ items: [...s.syncs].reverse().filter(r => !url.searchParams.get('state') || (r.finishedAt ? 'succeeded' : 'running') === url.searchParams.get('state')).map(r => syncWire(r, s)), next: null })
  if (path === '/vulnerability/overview' && method === 'GET') return json({ enabled_sources: s.source?.enabled ? 1 : 0, stale_or_failed_sources: 0, last_successful_sync: [...s.syncs].reverse().find(r => r.finishedAt)?.finishedAt, changed_advisories_24_hours: s.correlatedAt ? 1 : 0, newly_disclosed_24_hours: s.correlatedAt ? 1 : 0, newly_ingested_24_hours: s.correlatedAt ? 1 : 0, newly_affected_assets_24_hours: s.correlatedAt ? 1 : 0, open_high_critical_exposure: s.correlatedAt ? 1 : 0, pending_risk_actions: s.correlatedAt ? 1 : 0, queue_depth: s.syncs.filter(r => !r.finishedAt).length, dead_letters: 0 })
  if (path === '/vulnerability/advisories' && method === 'GET') {
    const search = url.searchParams.get('search')?.toLowerCase()
    return json({ items: s.correlatedAt && (!search || `${DEMO_ADVISORY} checkout-token`.toLowerCase().includes(search)) ? [advisoryWire(s)] : [], next: '' })
  }
  if (path === `/vulnerability/advisories/${DEMO_ADVISORY}` && method === 'GET') {
    if (!s.correlatedAt) return error('Publish and sync the demo advisory first.', 404)
    return json(advisoryWire(s))
  }
  if (path === `/vulnerability/advisories/${DEMO_ADVISORY}/revisions` && method === 'GET') return json({ items: s.correlatedAt ? [advisoryWire(s)] : [], next: 0 })
  if (path === '/vulnerability/occurrences' && method === 'GET') return json({ items: s.correlatedAt && url.searchParams.get('advisory_id') === DEMO_ADVISORY ? [occurrenceWire(s)] : [] })
  if (path === '/vulnerability/actions' && method === 'GET') return json({ items: s.correlatedAt ? [actionWire(s)] : [] })
  if (path.startsWith('/vulnerability/occurrences/learn-token-occurrence/') && method === 'GET') {
    if (!s.correlatedAt) return error('No matching occurrence yet.', 404)
    if (path.endsWith('/assessments')) updateScenario(d => { d.monitorInvestigated = true })
    return json({ items: path.endsWith('/assessments') ? [{ ID: 'learn-risk', OccurrenceID: 'learn-token-occurrence', AdvisoryRevision: 1, Severity: 'high', CVSSScore: 7.5, KEV: false, Scope: 'in_scope', Reachability: 'unknown', FixedVersion: '2.0.1', OccurrenceState: 'detected', RiskScore: 7.5, Priority: 2, ReasonCodes: ['matching_recorded_inventory'], AssessedAt: s.correlatedAt }] : [] })
  }
  if (path.startsWith('/vulnerability/')) return error('This Intelligence command is outside the demo exercise.', 422)
})]
}
export const scenarioHandlers = createScenarioHandlers()
