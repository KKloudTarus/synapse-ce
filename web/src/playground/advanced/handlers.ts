import { http, HttpResponse } from 'msw'
import { readDemoMode } from '../demo-mode'
import { createScenarioHandlers } from '../scenario/handlers'
import { createWorkflowHandlers } from '../workflows/handlers'
import { emptyScenario, COMPARISON_ID, CYCLE_ID, INITIAL_ID, RETEST_ID, initial, type Scenario } from '../scenario/store'
import { ACTOR, engagementWire, findingWire, inComparisonScope, jobWire, lifecycleWire, runWire, scanWire } from '../scenario/data'
import { emptyWorkflows, PROJECT_KEY, type Workflows } from '../workflows/store'
import { LANGUAGES, QUALITY_ISSUES } from '../workflows/catalog'
import { DEMO_ISSUES } from '../scenario/catalog'
import { advancedStore, emptyRemediation, GATE_KEY, PROFILE_KEY, isAdvanced, settleAdvanced, updateAdvanced } from './store'
import { VERIFIED_COMPARISON, VERIFIED_ID, gateConditions, INTEL_CASES, intelActions, intelAdvisories, intelOccurrences, intelRunWire, intelSources, ownershipCurrent, policyAnalysis, policyOverview, policyProfiles, policyProject, remediationComparison, remediationCycle, remediationItems, remediationManifest, remediationMembers, remediationPreview, remediationSnapshot, remediationSummary, resolution, teams, verifiedAssessment } from './data'

const json = (value: unknown, status = 200) => HttpResponse.json(value as never, { status })
const error = (message: string, status = 409) => json({ error: message, message }, status)
const str = (v: unknown) => typeof v === 'string' ? v.trim().slice(0, 4096) : ''
const at = () => new Date().toISOString()
const advancedRoutes = http.all('/api/v1/*', async ({ request }) => {
  const mode = readDemoMode('overview')
  if (!isAdvanced(mode) || mode === 'ai-setup' || mode === 'ci-setup') return
  settleAdvanced()
  const url = new URL(request.url), path = decodeURIComponent(url.pathname.slice(7)), method = request.method
  let s = advancedStore.getSnapshot()
  const patch = (change: Parameters<typeof updateAdvanced>[0]) => { updateAdvanced(change); s = advancedStore.getSnapshot() }
  // Multipart CI evidence is consumed here; the shared fixture handlers accept JSON forms only.
  if (mode === 'policy' && path === `/projects/${PROJECT_KEY}/analyses` && method === 'POST') {
    const q = s.policy
    if (!q.gate || !q.profileAssigned || !q.decoration || q.quality.analyses.length !== 1) return error('Copy the profile, assign the release gate and enable PR decoration first.')
    if (!request.headers.get('content-type')?.includes('multipart/form-data')) return error('Attach the synthetic LCOV report before recording the CI analysis.', 400)
    const form = await request.formData(), file = form.get('coverage')
    if (!file || typeof file === 'string' || file.name !== 'checkout-demo.lcov' || file.size > 16000) return error('Use the supplied synthetic coverage artifact.', 400)
    const coverage = await file.text(), lines = coverage.split('\n').filter(line => line.startsWith('DA:'))
    if (lines.length !== 1000 || lines.filter(line => line.endsWith(',1')).length !== 860 || !coverage.includes('LH:860\n')) return error('The synthetic report must retain 860 of 1,000 covered lines.', 400)
    patch(d => { const p = d.policy; p.coverageImported = true; p.ciImportedAt = at(); p.quality.improvedAt = at(); p.quality.project!.ref = 'improved'; p.quality.analyses.push({ id: 'learn-quality-analysis-improved', ref: 'improved', startedAt: at(), finishedAt: null }) })
    return json({ id: 'learn-quality-analysis-improved-job', target: PROJECT_KEY, kind: 'git', mode: 'full', status: 'running', stage: 'importing synthetic CI evidence', started_at: at(), finished_at: null })
  }
  let b: Record<string, unknown> = {}
  if (['POST', 'PUT', 'PATCH'].includes(method)) { try { const raw = await request.clone().text(); b = raw ? JSON.parse(raw) : {}; if (!b || typeof b !== 'object' || Array.isArray(b)) return error('Submit a JSON object.', 400) } catch { return error('Submit a JSON form.', 400) } }
  if (path === '/me') return json({ id: 'user-001', username: 'admin', display_name: 'Admin User', email: ACTOR, role: 'admin', features: { assessment_lifecycle_read: true, assessment_lifecycle_ui_default: true } })
  if (mode === 'remediation') {
    const r = s.remediation
    if (path === '/ownership/capabilities') return json({ enabled: true, mode: 'enforce', routing_available: true })
    if (path === '/ownership/teams') return json({ items: teams, next: '' })
    if (/^\/ownership\/teams\/[^/]+\/members$/.test(path)) return json({ items: [{ user_id: 'user-001', team_id: path.split('/')[3], role: 'member', created_at: r.scenario.asset!.created_at }], next: '' })
    if (path === '/users/picker') return json({ items: [{ id: 'user-001', name: 'Admin User' }], next: '' })
    if (path === '/ownership/findings') {
      let items = initial(r.scenario)!.findings.map((f, n) => { const wire = findingWire(initial(r.scenario)!, f); return { id: f.id, engagement_id: INITIAL_ID, title: wire.Title, severity: wire.Severity, kind: wire.Kind, status: 'confirmed', version: n ? 1 : r.findingVersion, assignment: n ? { team_id: n % 2 ? 'team-security' : 'team-platform', assignee_id: '', mode: 'auto', revision: 1, manual_generation: 0 } : r.assignment, resolution: 'resolved', reason: n ? 'codeowners_match' : resolution(r).reason, sla_status: n < 5 ? 'open' : 'mitigating', remediate_by: new Date(Date.parse(r.scenario.asset!.created_at) + (n + 1) * 86400000).toISOString() } })
      for (const [key, value] of url.searchParams) if (['severity', 'kind', 'status', 'sla_status', 'engagement_id'].includes(key)) items = items.filter(i => i[key as 'severity'] === value)
      if (url.searchParams.get('team_id')) items = items.filter(i => i.assignment.team_id === url.searchParams.get('team_id'))
      return json({ items, total: items.length, next: '' })
    }
    const own = path.match(new RegExp(`^/engagements/${INITIAL_ID}/findings/learn-finding-1/ownership(?:/(history))?$`))
    if (own) {
      if (own[1]) return json({ items: r.history, next: '' })
      if (method === 'GET') return json(ownershipCurrent(r))
      if (method !== 'POST') return error('Use the ownership assignment endpoint.', 422)
      if (b.finding_version !== r.findingVersion || b.ownership_revision !== r.assignment.revision || b.manual_generation !== r.assignment.manual_generation) return error('Ownership changed. Reload the current assignment before retrying.')
      if (!['assign', 'transfer', 'claim', 'release', 'clear'].includes(str(b.action))) return error('Choose an ownership action.', 400)
      if (['assign', 'transfer'].includes(str(b.action)) && !teams.some(t => t.id === b.team_id)) return error('Choose an active demo team.', 400)
      if (b.assignee_id && b.assignee_id !== 'user-001') return error('Choose an eligible demo user.', 400)
      patch(d => { const current = d.remediation, before = structuredClone(current.assignment), action = str(b.action); current.assignment = { ...before, team_id: action === 'release' ? 'team-platform' : action === 'clear' ? '' : str(b.team_id) || before.team_id, assignee_id: action === 'claim' ? 'user-001' : action === 'release' || action === 'clear' || b.clear_assignee ? '' : str(b.assignee_id), legacy_assignee: action === 'claim' || b.assignee_id ? 'Admin User' : '', mode: action === 'release' ? 'auto' : 'manual', revision: before.revision + 1, manual_generation: before.manual_generation + 1 }; current.findingVersion++; current.history.push({ id: `learn-owner-${current.history.length + 1}`, engagement_id: INITIAL_ID, finding_id: 'learn-finding-1', actor: ACTOR, before, after: structuredClone(current.assignment), result: resolution(current), created_at: at(), transition_key: request.headers.get('Idempotency-Key') ?? '' }) })
      return json(s.remediation.history.at(-1))
    }
    if (path === '/playground/remediation/verify' && method === 'POST') { if (!r.scenario.comparisonAt || r.history.length < 2) return error('Review ownership and the mixed comparison first.'); patch(d => { d.remediation.verificationAt ??= at(); d.remediation.coverageRestored = true }); return json({ simulation: true, comparison_id: VERIFIED_COMPARISON }) }
    if (path === '/assessment-comparisons' && method === 'POST') { if (b.baseline_snapshot_id !== `${INITIAL_ID}-snapshot-1` || b.current_snapshot_id !== `${RETEST_ID}-snapshot-1` || b.mode !== 'lifecycle') return error('Choose the retained Initial and Re-test snapshots.'); const created = !r.scenario.comparisonAt; patch(d => { d.remediation.scenario.comparisonAt ??= at() }); return json({ comparison: remediationComparison(s.remediation), created }) }
    if (path === '/assessment-cycles' && method === 'GET') return json({ items: [{ ...remediationCycle(r), member_count: remediationMembers(r).length, active_branch_count: 1, latest_assessment_id: r.verificationAt ? VERIFIED_ID : RETEST_ID, latest_retest_number: r.verificationAt ? 2 : 1, members: remediationMembers(r), root_snapshot_id: `${INITIAL_ID}-snapshot-1`, current_snapshot_id: `${r.verificationAt ? VERIFIED_ID : RETEST_ID}-snapshot-1`, comparison_id: r.verificationAt ? VERIFIED_COMPARISON : r.scenario.comparisonAt ? COMPARISON_ID : '', comparison_status: r.scenario.comparisonAt ? 'complete' : '', comparison_summary: r.scenario.comparisonAt ? remediationSummary(r, Boolean(r.verificationAt)) : null }], next_cursor: '', migration_pending: [], migration_pending_total: 0 })
    if (path.startsWith('/assessment-comparisons/') && method === 'GET') {
      const id = path.split('/')[2], verified = id === VERIFIED_COMPARISON
      if (![COMPARISON_ID, VERIFIED_COMPARISON].includes(id) || (verified ? !r.verificationAt : !r.scenario.comparisonAt)) return error('This comparison has not been recorded.', 404)
      if (path.endsWith('/summary')) return json(remediationSummary(r, verified, url.searchParams.get('scope')))
      if (path.endsWith('/items')) { let items = remediationItems(r, verified).filter(i => inComparisonScope(i.finding_kind, url.searchParams.get('scope'))); for (const k of ['presence', 'finding_kind', 'producer_kind'] as const) if (url.searchParams.get(k === 'producer_kind' ? 'producer' : k)) items = items.filter(i => i[k] === url.searchParams.get(k === 'producer_kind' ? 'producer' : k)); if (url.searchParams.get('severity')) items = items.filter(i => (i.current_observation ?? i.baseline_observation)?.severity === url.searchParams.get('severity')); return json({ items, next_cursor: '' }) }
      return json(remediationComparison(r, verified))
    }
    const assessment = path.match(/^\/engagements\/([^/]+)(?:\/(.+))?$/)
    if (assessment && [INITIAL_ID, RETEST_ID, VERIFIED_ID].includes(assessment[1]) && method === 'GET') {
      const id = assessment[1], a = id === VERIFIED_ID ? verifiedAssessment(r) : r.scenario.assessments.find(a => a.id === id)!
      if (id === VERIFIED_ID && !r.verificationAt) return error('No comparable follow-up exists.', 404)
      if (!assessment[2]) return json(engagementWire(a, r.scenario))
      if (assessment[2] === 'lifecycle') return json({ assessment_id: id, cycle: remediationCycle(r), members: remediationMembers(r), branch_heads: remediationMembers(r).slice(-1) })
      if (assessment[2] === 'snapshots') return json({ items: [remediationSnapshot(r, id)], next_cursor: '', default_snapshot_id: `${id}-snapshot-1`, default_version: 1 })
      if (assessment[2] === 'scan') {
        const wire = scanWire(id === VERIFIED_ID ? { ...a, id: RETEST_ID } : a), findings = a.findings.map(f => findingWire(a, f)), partial = id === RETEST_ID
        wire.vulnerabilities = scanWire(initial(r.scenario)!).vulnerabilities.filter(v => a.findings.some(f => DEMO_ISSUES[Number(f.id.split('-').at(-1)) - 1].advisory === v.ID))
        const engineOutcomes = wire.engine_outcomes.map(o => ({ ...o, coverage: partial && ['iac', 'licenses'].includes(o.engine) ? 'partial' : o.coverage, counts: { ...o.counts, findings: findings.filter(f => (o.engine === 'sca' ? 'vulnerability' : o.engine === 'secrets' ? 'secret' : o.engine === 'iac' ? 'misconfig' : o.engine === 'licenses' ? 'license' : o.engine) === f.Kind).length } }))
        return json({ ...wire, engine_outcomes: engineOutcomes, engine_coverage: { ...wire.engine_coverage, status: partial ? 'partial' : 'complete', completed: partial ? 5 : 7 } })
      }
      if (assessment[2] === 'scan-status') {
        const wire = jobWire(a), partial = id === RETEST_ID
        const engineOutcomes = wire.engine_outcomes.map(o => ({ ...o, coverage: partial && ['iac', 'licenses'].includes(o.engine) ? 'partial' : o.coverage, counts: ['sca', 'sast', 'secrets', 'iac', 'licenses'].includes(o.engine) ? { findings: a.findings.filter(f => DEMO_ISSUES[Number(f.id.split('-').at(-1)) - 1].kind === ({ sca: 'vulnerability', secrets: 'secret', iac: 'misconfig', licenses: 'license' }[o.engine] ?? o.engine)).length } : o.counts }))
        return json({ ...wire, engine_outcomes: engineOutcomes, engine_coverage: { ...wire.engine_coverage, status: partial ? 'partial' : 'complete', completed: partial ? 5 : 7 } })
      }
      if (assessment[2] === 'scan-runs') return json([{ ...runWire(a), complete_coverage: id !== RETEST_ID }])
      if (assessment[2] === 'evidence') return json({ items: [], intact: true, head: '', verified: 0, error: '' })
    }
    if (path.startsWith('/assessment-snapshots/') && method === 'GET') { const id = path.split('/')[2].replace(/-snapshot-1$/, ''); if ([INITIAL_ID, RETEST_ID, VERIFIED_ID].includes(id)) return json(remediationSnapshot(r, id)) }
    if (path.startsWith(`/assessment-cycles/${CYCLE_ID}`)) {
      const action = path.slice(`/assessment-cycles/${CYCLE_ID}`.length)
      if (!action && method === 'GET') return json({ ...lifecycleWire(r.scenario), cycle: remediationCycle(r), members: remediationMembers(r), branch_heads: remediationMembers(r).slice(-1) })
      if (action === '/members') return json({ items: remediationMembers(r), next_cursor: '' })
      if (action === '/closure-manifests') return json({ items: r.scenario.closure ? [remediationManifest(r)] : [] })
      if (action === '/closure-previews' && method === 'POST') {
        if (!r.scenario.comparisonAt || !str(b.reason)) return error('Review the comparison and provide a closure reason.')
        const ids = b.override_blocker_ids
        if (!Array.isArray(ids) || ids.some(id => id !== 'release:retained-findings') || ids.length > 1) return error('Only the release exception may be overridden.', 400)
        patch(d => { const state = d.remediation; state.overrideIds = ids; state.overrideReason = str(b.override_reason); state.scenario.preview = { token: crypto.randomUUID(), expiresAt: new Date(Date.now() + 600000).toISOString(), reason: str(b.reason) } })
        return json(remediationPreview(s.remediation))
      }
      if (action === '/closure-commits' && method === 'POST') {
        if (!r.scenario.preview || r.scenario.closure || !remediationPreview(r).policy.commit_allowed || b.preview_token !== r.scenario.preview.token || Date.parse(r.scenario.preview.expiresAt) <= Date.now() || request.headers.get('If-Match')?.replaceAll('"', '') !== String(remediationCycle(r).version) || b.reason !== r.scenario.preview.reason || JSON.stringify(b.override_blocker_ids) !== JSON.stringify(r.overrideIds) || b.override_reason !== r.overrideReason) return error('Refresh the authoritative preview and review coverage and the exception.')
        patch(d => { const r = d.remediation; r.scenario.closure = { at: at(), reason: r.scenario.preview!.reason, token: r.scenario.preview!.token } }); return json({ cycle: remediationCycle(s.remediation), manifest: remediationManifest(s.remediation), report_job_id: 'learn-remediation-report' })
      }
      if (action.endsWith('/report') && method === 'GET') { if (!r.scenario.closure) return error('Close the cycle first.'); return new HttpResponse(JSON.stringify({ demo: true, notice: 'Synthetic release exception; no real verification or signature executed.', manifest: remediationManifest(r), comparison: remediationSummary(r, true) }, null, 2), { headers: { 'Content-Type': 'application/json' } }) }
    }
  }
  if (mode === 'intelligence') {
    const i = s.intelligence
    if (path === '/vulnerability/sources' && method === 'GET') return json(intelSources(i))
    if (path === '/playground/intelligence/failure' && method === 'POST') { patch(d => { const i = d.intelligence; if (!i.failureAt) { i.failureAt = at(); i.runs.push({ id: 'learn-intel-failed', sourceId: 'learn-source', mode: 'incremental', startedAt: at(), finishedAt: at(), state: 'failed' }) } }); return json({ simulation: true, state: 'failed' }) }
    const source = path.match(/^\/vulnerability\/sources\/(learn-source|learn-osv-secondary)\/(sync|test)$/)
    if (source && method === 'POST') {
      if (source[2] === 'test') return new HttpResponse(null, { status: 204 })
      if (!['full', 'incremental'].includes(str(b.mode)) || !i.failureAt || i.runs.some(r => !r.finishedAt)) return error('Review the failed run and use Incremental or Full after the current run finishes.')
      const id = `learn-intel-run-${i.runs.length + 1}`
      patch(d => d.intelligence.runs.push({ id, sourceId: source[1], mode: b.mode as 'full' | 'incremental', startedAt: at(), finishedAt: null, state: 'running' }))
      return json({ run_id: id, source_id: source[1], mode: b.mode, state: 'running', created: true }, 202)
    }
    if (path === '/vulnerability/sync-runs') { let rows = [...i.runs].reverse(); for (const [query, key] of [['source_id', 'sourceId'], ['state', 'state'], ['mode', 'mode']] as const) if (url.searchParams.get(query)) rows = rows.filter(r => r[key] === url.searchParams.get(query)); return json({ items: rows.map(r => intelRunWire(r, i)), next: null }) }
    if (path === '/vulnerability/overview') return json({ enabled_sources: 2, stale_or_failed_sources: intelSources(i).filter(s => s.health.stale || s.health.state === 'failed').length, last_successful_sync: i.reconciledAt ?? i.recoveredAt, changed_advisories_24_hours: i.reconciledAt ? 4 : 0, newly_disclosed_24_hours: i.reconciledAt ? 4 : 0, newly_ingested_24_hours: i.reconciledAt ? 4 : 0, newly_affected_assets_24_hours: i.reconciledAt ? 1 : 0, open_high_critical_exposure: i.reconciledAt ? 2 : 0, pending_risk_actions: i.reconciledAt ? 4 : 0, queue_depth: i.runs.filter(r => !r.finishedAt).length, dead_letters: 0 })
    if (path === '/vulnerability/advisories' && method === 'GET') { let items = intelAdvisories(i); if (url.searchParams.get('search')) items = items.filter(a => JSON.stringify(a).toLowerCase().includes(url.searchParams.get('search')!.toLowerCase())); return json({ items, next: '' }) }
    const advisory = path.match(/^\/vulnerability\/advisories\/(DEMO-CHECKOUT-004|DEMO-ECOSYSTEM-[1-3])(?:\/(revisions))?$/)
    if (advisory && method === 'GET') { const result = intelAdvisories(i).find(a => a.canonical.Advisory.ID === advisory[1]); if (!result) return error('Reconcile the advisory batch first.', 404); return json(advisory[2] ? { items: [result], next: 0 } : result) }
    if (path === '/vulnerability/occurrences' && method === 'GET') return json({ items: intelOccurrences(i, url.searchParams.get('advisory_id') ?? '') })
    if (path === '/vulnerability/actions' && method === 'GET') return json({ items: intelActions(i).filter(a => !url.searchParams.get('advisory_id') || a.AdvisoryID === url.searchParams.get('advisory_id')) })
    const occurrence = path.match(/^\/vulnerability\/occurrences\/(learn-token-occurrence|learn-occurrence-[479])\/(assessments|transitions)$/)
    if (occurrence && method === 'GET') { const c = INTEL_CASES.find(c => intelOccurrences(i, c.id)[0]?.ID === occurrence[1]); if (!c) return error('The retained occurrence does not exist.', 404); if (occurrence[2] === 'assessments') patch(d => { d.intelligence.scenario.monitorInvestigated = true }); return json({ items: occurrence[2] === 'assessments' ? [{ ID: `learn-risk-${c.packageIndex}`, OccurrenceID: occurrence[1], AdvisoryRevision: 1, Severity: c.score >= 9 ? 'critical' : c.score >= 7 ? 'high' : c.score >= 4 ? 'medium' : 'low', CVSSScore: c.score, KEV: false, Scope: 'in_scope', Reachability: 'unknown', FixedVersion: c.fixed, OccurrenceState: 'detected', RiskScore: c.score, Priority: c.score >= 9 ? 1 : c.score >= 7 ? 2 : c.score >= 4 ? 3 : 4, ReasonCodes: ['matching_recorded_inventory'], AssessedAt: i.reconciledAt }] : [] }) }

  }
  if (mode === 'policy') {
    const p = s.policy
    if (path === '/quality-profiles' && method === 'GET') return json(policyProfiles(p))
    if (path === '/quality-profiles/default-typescript/copy' && method === 'POST') { if (p.profileCopied || b.key !== PROFILE_KEY || b.name !== 'Checkout TypeScript') return error('Use the training profile name and key.'); patch(d => { d.policy.profileCopied = true }); return json(policyProfiles(s.policy).find(p => p.key === PROFILE_KEY), 201) }
    if (path === `/quality-profiles/${PROFILE_KEY}/severity` && method === 'POST') { if (!p.profileCopied || b.rule !== 'typescript:checkout-1' || b.severity !== 'high') return error('Raise the first TypeScript rule to High.'); patch(d => { d.policy.ruleSeverity = 'high' }); return json(policyProfiles(s.policy).find(p => p.key === PROFILE_KEY)) }
    if (path === '/rules' && method === 'GET') return json(QUALITY_ISSUES.filter(r => !url.searchParams.getAll('language').length || url.searchParams.getAll('language').includes(r.language)).map((r) => ({ key: `${r.language}:checkout-${QUALITY_ISSUES.indexOf(r) + 1}`, name: r.title, description: r.description, language: r.language, default_severity: r.severity, type: r.type, finding_kind: r.type, cwe: r.cwe ? [r.cwe] : [], engine: 'codequality', status: 'ready' })))
    if (path === '/quality-gates') {
      if (method === 'GET') return json([{ key: 'default', name: 'Synapse Way', built_in: true, conditions: gateConditions }, ...(p.gate ? [{ ...p.gate, built_in: false }] : [])])
      if (method === 'POST') { if (p.gate || b.key !== GATE_KEY || b.name !== 'Checkout Release' || JSON.stringify(b.conditions) !== JSON.stringify(gateConditions)) return error('Use the three recorded release conditions.'); patch(d => { d.policy.gate = { key: GATE_KEY, name: 'Checkout Release', conditions: gateConditions } }); return json(s.policy.gate, 201) }
    }
    if (path === `/projects/${PROJECT_KEY}/profiles/typescript` && method === 'PUT') { if (!p.profileCopied || b.profile !== PROFILE_KEY) return error('Copy the project profile first.'); patch(d => { d.policy.profileAssigned = true }); return new HttpResponse(null, { status: 204 }) }
    if (path === `/projects/${PROJECT_KEY}/gate` && method === 'PUT') { if (!p.gate || b.gate_id !== GATE_KEY) return error('Create the release gate first.'); patch(d => { d.policy.quality.project!.gateId = GATE_KEY }); return json(policyProject(s.policy)) }
    if (path === `/projects/${PROJECT_KEY}/decoration` && method === 'PUT') { if (typeof b.enabled !== 'boolean') return error('Choose a decoration state.', 400); patch(d => { d.policy.decoration = b.enabled as boolean }); return json(policyProject(s.policy)) }
    if (method === 'GET') {
      if (path === '/projects') return json([policyProject(p)])
      if (path === `/projects/${PROJECT_KEY}`) return json(policyProject(p))
      if (path === `/projects/${PROJECT_KEY}/overview`) return json(policyOverview(p, url.searchParams.get('branch') ?? ''))
      if (path === `/projects/${PROJECT_KEY}/analyses`) return json({ items: p.quality.analyses.filter(a => a.finishedAt && (!url.searchParams.get('branch') || a.ref === url.searchParams.get('branch'))).map(a => policyAnalysis(p, a)).reverse(), next: null })
      const match = path.match(new RegExp(`^/projects/${PROJECT_KEY}/analyses/(learn-quality-analysis-(main|improved))$`))
      if (match) { const a = p.quality.analyses.find(a => a.id === match[1] && a.finishedAt); return a ? json(policyAnalysis(p, a)) : error('The analysis is not complete.', 404) }
      if (path === `/projects/${PROJECT_KEY}/analysis`) { const a = [...p.quality.analyses].reverse().find(a => a.finishedAt && (!url.searchParams.get('branch') || a.ref === url.searchParams.get('branch'))); if (a) return json({ analysis: policyAnalysis(p, a), result: { target: p.quality.project!.source, scan_mode: 'full', languages: LANGUAGES, sbom: { Components: [] }, code_quality: { available: true, files_analyzed: 28, rules_evaluated: 96, issues_found: a.ref === 'improved' ? 0 : QUALITY_ISSUES.length, inventory: { languages: LANGUAGES.map((l, i) => ({ language: l.Name, files: [10, 7, 5, 3, 3][i], code_lines: l.Percent * 10, comment_lines: l.Percent, blank_lines: l.Percent })) } } } }) }
    }
  }
  // Only Inbox commands use the shared mutation adapter. Prevent an unrelated
  // scan/asset command from replacing the retained advanced evidence dataset.
  const inboxCommand = mode === 'intelligence' && (path === '/me/notification-preferences' && method === 'PUT' || ['/me/inbox/learn-monitor-message/read', '/me/inbox/read'].includes(path) && method === 'POST')
  if (method !== 'GET' && !inboxCommand) return error('This action is outside the active advanced chapter.', 422)
})
const scenarioBackend = {
  getSnapshot: (): Scenario => { const m = readDemoMode('overview'); if (m !== 'remediation' && m !== 'intelligence') return emptyScenario(); const current = advancedStore.getSnapshot()[m], s = structuredClone(current.scenario); s.enabled = true; if (m === 'remediation') { if (!s.assessments[1].findings.length) s.assessments[1].findings = emptyRemediation().scenario.assessments[1].findings; if (advancedStore.getSnapshot().remediation.verificationAt) s.assessments.push(verifiedAssessment(advancedStore.getSnapshot().remediation)) }; return s },
  update: (change: (s: Scenario) => void) => { const m = readDemoMode('overview'); if (m === 'remediation' || m === 'intelligence') updateAdvanced(d => change(d[m].scenario)) },
  settle: settleAdvanced,
}
const qualityBackend = {
  getSnapshot: (): Workflows => { const s = emptyWorkflows(); if (readDemoMode('overview') === 'policy') { s.mode = 'quality'; s.quality = advancedStore.getSnapshot().policy.quality }; return s },
  update: (change: (s: Workflows) => void) => updateAdvanced(d => { const s = emptyWorkflows(); s.mode = 'quality'; s.quality = d.policy.quality; change(s); d.policy.quality = s.quality }),
  settle: settleAdvanced,
}
export const advancedHandlers = [advancedRoutes, ...createScenarioHandlers(scenarioBackend), ...createWorkflowHandlers(qualityBackend)]
