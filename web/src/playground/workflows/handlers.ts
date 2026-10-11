import { http, HttpResponse } from 'msw'
import { AGENT_ID, AI_ENG, DEMO_TOKEN, HOST_ID, INCIDENT_ID, PROJECT_KEY, PROJECT_TARGET, REVIEWER, RUNTIME_ENG, isWorkflow, settleWorkflows, updateWorkflows, workflowStore } from './store'
import { agent, aiFinding, analysis, coverage, detection, engagement, host, incident, job, observability, overview, project, qualityIssue, response, review, stamp } from './data'
import { AI_CASES, DETECTIONS, LANGUAGES, QUALITY_HOTSPOTS, QUALITY_ISSUES, RUNTIME_PACKAGES, WORKLOADS, counts } from './catalog'
import { qualityBehavioralHotspots, qualityCodeDiff, qualityCodeFile, qualityCodeIndex, qualityDependencyExport, qualityDependencyGraph, qualityMeasures } from './quality-data'

const json = (value: unknown, status = 200) => new HttpResponse(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const error = (message: string, status = 409) => json({ error: message, message }, status)
const str = (value: unknown, max = 2000) => typeof value === 'string' ? value.trim().slice(0, max) : ''
const noContent = () => new HttpResponse(null, { status: 204 })
// Only the playground imports these handlers. Every effect is a browser-local state transition.
export function createWorkflowHandlers(backend = { getSnapshot: workflowStore.getSnapshot, update: updateWorkflows, settle: settleWorkflows }) {
const workflowStore = backend, updateWorkflows = backend.update, settleWorkflows = backend.settle
return [http.all('/api/v1/*', async ({ request }) => {
  settleWorkflows()
  let s = workflowStore.getSnapshot()
  if (!isWorkflow(s.mode)) return
  const url = new URL(request.url), path = decodeURIComponent(url.pathname.slice(7)), method = request.method
  let b: Record<string, unknown> = {}
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    try { const raw = await request.text(); b = raw ? JSON.parse(raw) : {} } catch { return error('Submit a JSON form.', 400) }
    if (!b || typeof b !== 'object' || Array.isArray(b)) return error('Submit a JSON object.', 400)
  }
  const patch = (fn: Parameters<typeof updateWorkflows>[0]) => { updateWorkflows(fn); s = workflowStore.getSnapshot() }
  if (path === '/engagements' && method === 'GET') return json([engagement(s.mode === 'runtime' ? RUNTIME_ENG : AI_ENG)])
  if (path === '/projects' && method === 'GET') return json(s.mode === 'quality' && s.quality.project ? [project(s.quality)] : [])
  if (path === '/users/picker' && method === 'GET') return json({ items: [{ id: REVIEWER, name: 'Admin User', username: 'admin', display_name: 'Admin User', role: 'admin', active: true }], next: '' })

  if (s.mode === 'runtime') {
    const r = s.runtime
    if (path === '/agents/rollout' && method === 'GET') return json({ configured: false, channel: 'stable', reason: 'No rollout is configured for the training agent.' })
    if (path === '/agents/enrolment-tokens' && method === 'POST') {
      const ttl = Number(b.ttl_seconds)
      if (!Number.isInteger(ttl) || ttl < 60 || ttl > 3600 || r.enrolledAt) return error('Use a token lifetime of 1–60 minutes before enrolment.')
      patch(d => { d.runtime.tokenAt = stamp(); d.runtime.tokenExpiresAt = new Date(Date.now() + ttl * 1000).toISOString() })
      return json({ enrolment_token: DEMO_TOKEN })
    }
    if (path === '/playground/runtime/enroll' && method === 'POST') {
      if (!r.tokenAt || !r.tokenExpiresAt || Date.parse(r.tokenExpiresAt) <= Date.now() || r.enrolledAt) return error('Mint a current enrolment token first.')
      patch(d => { d.runtime.enrolledAt = stamp() }); return json(agent(s.runtime))
    }
    if (path === '/playground/runtime/telemetry' && method === 'POST') {
      if (!r.enrolledAt) return error('Enrol the demo agent first.')
      patch(d => { d.runtime.telemetryAt ??= stamp() }); return json(coverage(s.runtime))
    }
    if (path === '/playground/runtime/detect' && method === 'POST') {
      if (!r.telemetryAt) return error('Record telemetry and coverage first.')
      patch(d => { d.runtime.detectedAt ??= stamp() }); return json(detection(s.runtime))
    }
    if (path === '/fleet/agents' && method === 'GET') return json(r.enrolledAt ? [agent(r)] : [])
    if (path === `/fleet/agents/${AGENT_ID}` && method === 'GET') return json({ agent: agent(r), recent_work: [] })
    if (path === '/assets/hosts' && method === 'GET') return json(r.telemetryAt ? [host(r)] : [])
    if (path === `/assets/${HOST_ID}/packages`) return json({ asset_id: HOST_ID, engagement_id: RUNTIME_ENG, recorded_at: r.telemetryAt, packages: RUNTIME_PACKAGES })
    if (path === `/assets/${HOST_ID}/vulnerabilities`) return json({ ...host(r), findings: [] })
    if (path === '/fleet/workloads') return json({ workloads: r.telemetryAt ? WORKLOADS : [] })
    if (path === '/fleet/coverage-windows') return json({ coverage_windows: r.telemetryAt ? [coverage(r)] : [] })
    if (path === '/fleet/coverage') return json(r.telemetryAt ? ['scan.host', 'detect.runtime'].map(capability => ({ asset_id: HOST_ID, capability, verdict: 'covered', detail: 'Recorded training telemetry', last_run: r.telemetryAt, agent_id: AGENT_ID })) : [])
    if (path === '/fleet/coverage/summary') return json({ agents_by_state: r.enrolledAt ? { healthy: 1 } : {}, rows_by_verdict: r.telemetryAt ? { covered: 2 } : {}, assets: r.telemetryAt ? 1 : 0 })
    if (path === `/engagements/${RUNTIME_ENG}/detections`) return json({ detections: r.detectedAt ? DETECTIONS.map((_, i) => detection(r, i)) : [], field_scope: 'full' })
    if (path === `/fleet/engagements/${RUNTIME_ENG}/correlate` && method === 'POST') {
      if (!r.detectedAt) return error('Record a detection first.')
      const created = !r.incidentAt
      patch(d => { d.runtime.incidentAt ??= stamp() }); return json({ created: created ? DETECTIONS.map((_, i) => incident(s.runtime, i)) : [], reassessed: 0, reassess_failed: 0 })
    }
    if (path === '/fleet/incidents') return json({ incidents: r.incidentAt ? DETECTIONS.map((_, i) => incident(r, i)) : [], truncated: false })
    if (path === `/fleet/incidents/${INCIDENT_ID}`) return r.incidentAt ? json(incident(r)) : error('Correlate the detection first.', 404)
    const extraIncident = path.match(/^\/fleet\/incidents\/learn-runtime-incident-([2-5])$/)
    if (extraIncident && method === 'GET' && r.incidentAt) return json(incident(r, Number(extraIncident[1]) - 1))
    const action = path.match(new RegExp(`^/fleet/incidents/${INCIDENT_ID}/(owner|status|disposition|comments)$`))?.[1]
    if (action && method === 'POST') {
      if (!r.incidentAt) return error('Correlate the detection first.')
      if (action === 'owner' && str(b.owner) !== REVIEWER || action === 'status' && !['investigating', 'resolved'].includes(str(b.to)) || action === 'disposition' && b.disposition !== 'true_positive' || action === 'comments' && str(b.text).length < 3) return error('Use the example analyst action.', 400)
      if (action === 'status' && b.to === 'resolved' && !r.revertedAt) return error('Verify and revert the simulated response before resolving this incident.')
      patch(d => { if (action === 'owner') d.runtime.owner = REVIEWER; if (action === 'status') d.runtime.incidentStatus = str(b.to); if (action === 'disposition') d.runtime.disposition = 'true_positive'; if (action === 'comments') d.runtime.comment = str(b.text) })
      return json(incident(s.runtime))
    }
    if (path === '/blueteam/response') return json({ responses: r.appliedAt ? [response(r)] : [] })
    const operation = path.match(new RegExp(`^/blueteam/engagements/${RUNTIME_ENG}/response/(plan|apply)$`))?.[1]
    if (operation && method === 'POST') {
      if (b.target !== HOST_ID || b.kind !== 'isolate_host' || !r.owner || r.incidentStatus !== 'investigating' || r.disposition !== 'true_positive') return error('Investigate and assign the demo incident, then select the scoped demo host.')
      if (operation === 'plan') { patch(d => { d.runtime.planAt = stamp() }); return json({ kind: 'isolate_host', target: HOST_ID, steps: [{ label: 'Simulate scoped host isolation and verify its state', argv: [], blast_radius: 'One training host; no host effect' }] }) }
      if (!r.planAt) return error('Review the dry-run plan first.')
      patch(d => { d.runtime.appliedAt ??= stamp() }); return json(response(s.runtime))
    }
    if (path === '/blueteam/response/learn-response-1/revert' && method === 'POST') {
      if (!r.appliedAt || b.target !== HOST_ID) return error('Apply the scoped demo response first.')
      patch(d => { d.runtime.revertedAt ??= stamp() }); return json(response(s.runtime))
    }
  }

  if (s.mode === 'ai') {
    const a = s.ai
    if (path === '/playground/ai/proposals' && method === 'POST') { patch(d => { d.ai.proposalsAt ??= stamp() }); return json(s.ai.reviews.map((_, i) => review(s.ai, i))) }
    if (path === '/ai-triage/reviews' && method === 'GET') {
      const items = a.proposalsAt ? a.reviews.map((_, i) => review(a, i)).filter(row => !url.searchParams.get('state') || row.state === url.searchParams.get('state')).filter(row => ['owner', 'severity', 'cwe', 'project'].every(key => !url.searchParams.get(key) || (key === 'project' ? row.project_id : row[key as 'owner' | 'severity' | 'cwe']) === url.searchParams.get(key))) : []
      return json({ reviews: items, next: null, total: items.length })
    }
    if (path === '/ai-triage/observability') return json(observability(a))
    const match = path.match(/^\/ai-triage\/reviews\/(learn-review-[1-5])\/(claim|decision)$/)
    if (match && method === 'POST') {
      const i = Number(match[1].split('-').at(-1)) - 1, row = a.reviews[i]
      if (!a.proposalsAt || b.version !== row.version || row.state !== 'pending') return error('This review changed. Reload the pending review.')
      if (match[2] === 'claim') { if (row.owner) return error('The review already has an owner.'); patch(d => { d.ai.reviews[i].owner = REVIEWER; d.ai.reviews[i].version++ }) }
      else {
        if (row.owner !== REVIEWER || str(b.rationale).length < 3 || !['accept', 'reject'].includes(str(b.decision)) || i < 2 && b.decision !== (i === 0 ? 'accept' : 'reject')) return error('Claim the review and provide the example human decision and rationale.')
        patch(d => { const r = d.ai.reviews[i]; r.state = b.decision === 'accept' ? 'accepted' : 'rejected'; r.rationale = str(b.rationale); r.decidedAt = stamp(); r.version++; if (i === 1) d.ai.findingStatus = 'open' })
      }
      return json(review(s.ai, i))
    }
    const f = path.match(new RegExp(`^/engagements/${AI_ENG}/findings/(learn-ai-finding-[1-5])(?:/(assignee|comments|ownership(?:/history)?))?$`))
    if (f) {
      const i = Number(f[1].split('-').at(-1)) - 1
      if (!f[2] && method === 'GET') return json(aiFinding(a, i))
      if (!f[2] && method === 'PATCH') {
        if (i !== 1 || a.reviews[1].state !== 'rejected' || b.version !== a.findingVersion || b.status !== 'confirmed') return error('Confirm the retained finding with its current version.')
        patch(d => { d.ai.findingStatus = 'confirmed'; d.ai.findingVersion++ }); return json(aiFinding(s.ai, i))
      }
      if (f[2] === 'assignee' && method === 'PUT') {
        if (i !== 1 || a.reviews[1].state !== 'rejected' || b.version !== a.findingVersion || b.assignee !== REVIEWER) return error('Assign the confirmed finding to the demo reviewer using its current version.')
        patch(d => { d.ai.assignedTo = REVIEWER; d.ai.findingVersion++ }); return json(aiFinding(s.ai, i))
      }
      if (f[2] === 'comments') {
        if (method === 'POST') { if (i !== 1 || !a.assignedTo || str(b.body).length < 3) return error('Assign the finding and enter a remediation note.'); patch(d => { d.ai.comment = str(b.body) }); return json({ ID: 'learn-ai-comment-1', FindingID: f[1], Body: s.ai.comment, Author: 'Admin User', CreatedAt: stamp() }, 201) }
        return json(a.comment && i === 1 ? [{ ID: 'learn-ai-comment-1', FindingID: f[1], Body: a.comment, Author: 'Admin User', CreatedAt: a.proposalsAt }] : [])
      }
      if (f[2]?.startsWith('ownership')) return json(f[2].endsWith('history') ? { items: [] } : { assignment: { team_id: '', assignee_id: a.assignedTo, mode: 'manual', revision: 1, manual_generation: 0 }, finding_version: a.findingVersion, finding_assignee: a.assignedTo, resolution: a.assignedTo ? 'resolved' : 'unresolved', reason: 'Training finding assignment', updated_at: a.proposalsAt })
    }
  }

  if (s.mode === 'quality') {
    const q = s.quality
    if (path === '/projects' && method === 'POST') {
      const source = b.source_binding as Record<string, unknown> | undefined
      if (q.project) return error('This project already exists.')
      if (b.key !== PROJECT_KEY || !str(b.name, 100) || source?.kind !== 'git' || source.value !== PROJECT_TARGET || source.ref !== 'main' || b.gate_id !== 'default') return error('Use the training Git repository, main branch and Synapse Way policy.', 400)
      patch(d => { d.quality.project = { key: PROJECT_KEY, name: str(b.name, 100), source: PROJECT_TARGET, ref: 'main', gateId: 'default', createdAt: stamp() } }); return json(project(s.quality), 201)
    }
    if (path === '/playground/quality/improve' && method === 'POST') {
      if (!q.project || !q.analyses[0]?.finishedAt || q.issueStatus !== 'accepted' || q.hotspotStatus !== 'safe') return error('Analyze the baseline and review the issue and hotspot first.')
      patch(d => { d.quality.improvedAt ??= stamp(); d.quality.project!.ref = 'improved' }); return json(project(s.quality))
    }
    const p = path.match(new RegExp(`^/projects/${PROJECT_KEY}(?:/(.+))?$`))
    if (p) {
      if (!q.project) return error('Create the training project first.', 404)
      const tab = p[1]
      if (!tab && method === 'GET') return json(project(q))
      if (tab === 'analyses' && method === 'POST') {
        if (q.analyses.some(a => a.ref === q.project!.ref)) return error('This revision already has a retained analysis.')
        patch(d => { d.quality.analyses.push({ id: `learn-quality-analysis-${q.project!.ref}`, ref: q.project!.ref as 'main' | 'improved', startedAt: stamp(), finishedAt: null }) }); return json(job(s.quality.analyses.at(-1)!))
      }
      if (tab === 'analysis-status') return q.analyses.length ? json(job(q.analyses.at(-1)!)) : error('No analysis yet.', 404)
      const branch = url.searchParams.get('branch') ?? ''
      if (tab === 'analyses') return json({ items: q.analyses.filter(a => a.finishedAt && (!branch || a.ref === branch)).map(analysis).reverse(), next: null })
      if (tab === 'branches') return json({ branches: q.analyses.filter(a => a.finishedAt).map(a => ({ name: a.ref, kind: a.ref === 'main' ? 'long_lived' : 'short_lived' })) })
      if (tab === 'overview') return json(overview(q, url.searchParams.get('branch') ?? ''))
      const latest = q.analyses.filter(a => a.finishedAt && (!branch || a.ref === branch)).at(-1)
      if (tab === 'analysis') return latest ? json({ analysis: analysis(latest), result: { target: PROJECT_TARGET, scan_mode: 'full', languages: LANGUAGES, sbom: { Components: [] }, code_quality: { available: true, files_analyzed: 28, rules_evaluated: 96, issues_found: latest.ref === 'improved' ? 0 : QUALITY_ISSUES.length } } }) : error('Analysis is running.', 404)
      const retained = tab?.match(/^analyses\/([^/]+)(?:\/(code\/(files|file|diff)|behavioral-hotspots))?$/)
      if (retained && method === 'GET') {
        const a = q.analyses.find(a => a.id === retained[1] && a.finishedAt)
        if (!a) return error('This analysis has no retained results.', 404)
        if (!retained[2]) return json(analysis(a))
        const path = url.searchParams.get('path') ?? ''
        if (retained[2] === 'behavioral-hotspots') return json(qualityBehavioralHotspots(q, a, path))
        if (retained[3] === 'files') return json(qualityCodeIndex(q, a))
        if (retained[3] === 'file') {
          const from = Number(url.searchParams.get('from_line') ?? '1')
          if (!Number.isSafeInteger(from) || from < 1) return error('Choose a positive source line.', 400)
          const result = qualityCodeFile(q, a, path, from)
          if (!result) return error('This source path is not retained.', 404)
          if (from > result.total_lines) return error('The source window is outside this file.', 400)
          return json(result)
        }
        if (url.searchParams.get('view') !== 'unified') return error('Only the retained unified diff is available.', 422)
        const diff = qualityCodeDiff(a, path)
        return diff ? json(diff) : error('No retained comparison for this file and revision.', 404)
      }
      if (method === 'GET' && ['dependency-graph', 'dependency-graph/export', 'measures'].includes(tab ?? '')) {
        if (!latest) return error('Complete an analysis to explore its results.', 404)
        const result = tab === 'dependency-graph' ? qualityDependencyGraph(latest) : tab === 'dependency-graph/export' ? qualityDependencyExport(latest, url.searchParams.get('root') ?? '') : qualityMeasures(q, latest, url.searchParams.get('path') ?? '')
        return result ? json(result) : error('This result path is not retained.', 404)
      }
      if (tab === 'issues' || tab === 'hotspots') {
        const hotspot = tab === 'hotspots'
        const all = !latest || !hotspot && latest.ref === 'improved' ? [] : (hotspot ? QUALITY_HOTSPOTS : QUALITY_ISSUES).map((_, i) => qualityIssue(q, i, hotspot, latest))
        const items = all.filter(row => ['status', 'type', 'severity', 'language'].every(key => !url.searchParams.get(key) || row[key as 'status' | 'type' | 'severity' | 'language'] === url.searchParams.get(key)))
          .filter(row => !url.searchParams.get('rule') || row.rule_key === url.searchParams.get('rule'))
          .filter(row => !url.searchParams.get('path') || row.file === url.searchParams.get('path'))
          .filter(row => url.searchParams.get('new_code') !== 'true' || row.is_new)
          .filter(row => !url.searchParams.get('search') || `${row.title} ${row.file}`.toLowerCase().includes(url.searchParams.get('search')!.toLowerCase()))
        const reviewed = items.filter(row => row.status !== 'to_review').length
        const reviewedPct = items.length ? reviewed / items.length * 100 : 100
        return json({ items, next: null, facets: { statuses: counts(items, 'status'), types: counts(items, 'type'), severities: counts(items, 'severity'), languages: counts(items, 'language'), rule_keys: counts(items, 'rule_key') }, summary: hotspot ? { total: items.length, reviewed, reviewed_pct: reviewedPct, grade: reviewedPct === 100 ? 'A' : reviewedPct >= 80 ? 'B' : reviewedPct >= 70 ? 'C' : reviewedPct >= 50 ? 'D' : 'E' } : { total: items.length, open: items.filter(row => row.status === 'open').length, resolved: items.filter(row => row.status !== 'open').length } })
      }
      const item = tab?.match(/^(issues|hotspots)\/(learn-issue-(?:[1-9]|10)|learn-hotspot-[1-3])(?:\/(history|transitions))?$/)
      if (item) {
        const hotspot = item[1] === 'hotspots', i = Number(item[2].split('-').at(-1)) - 1
        if (!item[3]) return json(qualityIssue(q, i, hotspot, latest))
        if (item[3] === 'history') return json(i === 0 ? [{ actor: REVIEWER, status: hotspot ? q.hotspotStatus : q.issueStatus, rationale: hotspot ? q.hotspotRationale : q.issueRationale, version: hotspot ? q.hotspotVersion : q.issueVersion, created_at: q.analyses[0]?.finishedAt }] : hotspot && latest?.ref === 'improved' ? [{ actor: REVIEWER, status: 'fixed', rationale: 'Verified the remediated pattern in the improved revision.', version: 2, created_at: latest.finishedAt }] : [])
        if (method === 'POST') {
          if (i !== 0) return error('Review this additional case after the guided example.', 422)
          if (b.expected_version !== (hotspot ? q.hotspotVersion : q.issueVersion) || str(b.rationale).length < 3 || b.to !== (hotspot ? 'safe' : 'accepted')) return error('Use the current version and record the reviewed rationale.')
          patch(d => { if (hotspot) { d.quality.hotspotStatus = 'safe'; d.quality.hotspotRationale = str(b.rationale); d.quality.hotspotVersion++ } else { d.quality.issueStatus = 'accepted'; d.quality.issueRationale = str(b.rationale); d.quality.issueVersion++ } })
          const wire = qualityIssue(s.quality, i, hotspot)
          return json(hotspot ? { hotspot: wire, event: { actor: REVIEWER, status: 'safe', rationale: s.quality.hotspotRationale, version: s.quality.hotspotVersion, created_at: stamp() } } : wire)
        }
      }
      return error('This project view is outside the guided exercise.', 404)
    }
  }

  const eng = path.match(/^\/engagements\/(learn-runtime-assessment|learn-ai-assessment)(?:\/(.+))?$/)
  if (eng && method === 'GET') {
    if (!eng[2]) return json(engagement(eng[1]))
    if (eng[2] === 'findings') return json(eng[1] === AI_ENG && s.ai.proposalsAt ? AI_CASES.map((_, i) => aiFinding(s.ai, i)) : [])
    if (eng[2] === 'evidence') return json([])
    if (eng[2] === 'summary') { const findings = eng[1] === AI_ENG && s.ai.proposalsAt ? AI_CASES.map((_, i) => aiFinding(s.ai, i)) : []; return json({ total: findings.length, by_severity: counts(findings, 'Severity'), by_status: counts(findings, 'Status') }) }
    if (eng[2] === 'lifecycle' || eng[2] === 'scan-status') return error('No scan lifecycle in this exercise.', 404)
    return json([])
  }
  if (path.startsWith('/playground/')) return error('Unknown training action.', 404)
  // Unknown mutations in an active walkthrough must not silently succeed through fixture fallbacks.
  if (method !== 'GET' && /^(\/fleet|\/blueteam|\/ai-triage|\/projects|\/agents)/.test(path)) return error('This action is outside the active walkthrough.', 422)
  if (method === 'DELETE') return noContent()
})]
}
export const workflowHandlers = createWorkflowHandlers()
