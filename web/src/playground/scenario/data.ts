import { COMPARISON_ID, CYCLE_ID, DEMO_ADVISORY, EVENT_TYPE, INITIAL_ID, RETEST_ID, TARGET, initial, retest, type DemoAssessment, type DemoFinding, type Scenario } from './store'

import { CORE_PHASES, DEMO_ISSUES, DEMO_PACKAGES, PHASE_DURATION, SCAN_DURATION, SEVERITY_RISK } from './catalog'

export const PACKAGES = DEMO_PACKAGES.map(p => p.name)
const DEMO_HASH = 'DEMO-NOT-A-CRYPTOGRAPHIC-DIGEST'
export const ACTOR = 'admin@synapse.local'
export const snapshotId = (a: DemoAssessment) => `${a.id}-snapshot-1`
export const runId = (a: DemoAssessment) => `${a.id}-run-1`
export { COMPARISON_ID } from './store'
export const MANIFEST_ID = 'learn-checkout-closure'

export function findingWire(a: DemoAssessment, f: DemoFinding) {
  const issue = DEMO_ISSUES[Number(f.id.split('-').at(-1)) - 1]
  const pkg = issue.packageIndex === undefined ? undefined : DEMO_PACKAGES[issue.packageIndex]
  const title = issue.advisory ? `${pkg!.name}: ${issue.title} (${issue.advisory})` : `DEMO: ${issue.title}`
  return {
    ID: f.id, EngagementID: a.id, Title: title,
    Description: `Training data only. ${issue.location}. ${issue.remediation} No real vulnerability or usable credential is included.`,
    Severity: issue.severity, Status: f.status, Version: f.version, CWE: issue.cwe ?? '',
    Assignee: f.assignee, assignee_user_id: f.assignee || undefined,
    DedupKey: issue.advisory ? `vuln:${issue.advisory}:${pkg!.name}:${pkg!.version}` : `demo:${issue.kind}:${f.id}`,
    Kind: issue.kind, Class: pkg ? 'third_party' : 'first_party', Scope: 'in_scope', Reachability: 'unknown', Confidence: 'high',
    Priority: issue.severity === 'critical' ? 1 : issue.severity === 'high' ? 2 : issue.severity === 'medium' ? 3 : 4,
    RiskScore: SEVERITY_RISK[issue.severity], EvidenceScore: 80, KEV: false,
    Sources: [issue.advisory ? 'demo-feed' : `demo-${issue.kind}`], AdvisoryID: issue.advisory ?? '', FixedVersion: pkg?.fixed ?? '',
    DetectionState: 'detected', EvaluatedAt: a.scan?.finishedAt, compliance_controls: [],
  }
}
export function engagementWire(a: DemoAssessment, s: Scenario) {
  const fs = a.findings.map(f => findingWire(a, f))
  return {
    id: a.id, name: a.name, client: a.client, status: a.status, created_at: a.createdAt,
    scope: { in_scope: a.scope, out_of_scope: a.outOfScope },
    authorized_from: a.authorizedFrom, authorized_to: a.authorizedTo, timezone: a.timezone,
    roe: { allowed_tool_classes: a.tools, blackouts: [] }, live_recon_enabled: false,
    business_asset_id: s.asset?.id, assessment_project_id: '',
    requires_explicit_execution_authorization: true,
    findings_count: { total: fs.length, critical: fs.filter(f => f.Severity === 'critical').length, high: fs.filter(f => f.Severity === 'high').length, medium: fs.filter(f => f.Severity === 'medium').length, low: fs.filter(f => f.Severity === 'low').length, info: fs.filter(f => f.Severity === 'info').length },
    last_scan_date: a.scan?.finishedAt, last_scan_status: a.scan?.finishedAt ? 'succeeded' : a.scan ? 'running' : '',
  }
}
export function components(a: DemoAssessment) {
  return DEMO_PACKAGES.map((p, i) => {
    const Version = a.id === RETEST_ID ? p.fixed : p.version
    const license = a.id === RETEST_ID && i >= 10 ? 'MIT' : p.license
    return { Name: p.name, Version, PURL: `pkg:${p.ecosystem}/${p.name}@${Version}`, Location: p.location, FirstParty: false,
      Licenses: license ? [{ SPDXID: license, Name: license, Category: license.startsWith('GPL') ? 'copyleft' : 'permissive', RawValue: license }] : [],
      LicenseSource: 'demo-manifest', LicenseConfidence: license ? 'high' : 'unknown' }
  })
}
const engines = [...new Set(CORE_PHASES.map(p => p.engine).filter(Boolean))]
const coverage = { status: 'complete', required: engines.length, completed: engines.length }
const outcomeCounts = (a: DemoAssessment, engine: string) => {
  if (engine === 'inventory') return { files: 28, languages: 5, manifests: 4 }
  if (engine === 'dependency_resolution') return { components: DEMO_PACKAGES.length, dependency_edges: DEMO_PACKAGES.reduce((sum, p) => sum + p.dependencies.length, 0) }
  const kind = { sca: 'vulnerability', sast: 'sast', secrets: 'secret', iac: 'misconfig', licenses: 'license' }[engine]
  return { findings: a.id === INITIAL_ID ? DEMO_ISSUES.filter(issue => issue.kind === kind).length : 0 }
}
const outcomes = engines.map(engine => ({ engine, execution: 'completed', coverage: 'complete', required: true, reason: 'Simulated complete coverage of the demo repository', counts: {} }))
export function phaseCompleted(a: DemoAssessment | undefined, index: number) {
  return Boolean(a?.scan && (a.scan.finishedAt || Date.now() - Date.parse(a.scan.startedAt) >= (index + 1) * PHASE_DURATION))
}
export function jobWire(a: DemoAssessment, now = Date.now()) {
  const scan = a.scan!
  const finished = Boolean(scan.finishedAt)
  const elapsed = finished ? SCAN_DURATION : Math.max(0, Math.min(SCAN_DURATION - 1, now - Date.parse(scan.startedAt)))
  const phase = Math.min(CORE_PHASES.length - 1, Math.floor(elapsed / PHASE_DURATION))
  const counts = (index: number) => index === 2 ? { components: DEMO_PACKAGES.length, dependency_edges: 4 } : index === 3 ? { advisories: a.id === INITIAL_ID ? 8 : 0 } : index === 4 ? { findings: a.id === INITIAL_ID ? 4 : 0 } : [5, 6, 7].includes(index) ? { findings: a.id === INITIAL_ID ? 2 : 0 } : index === 9 ? { findings: a.id === INITIAL_ID ? DEMO_ISSUES.length : 0 } : { files: 28 }
  const engineOutcomes = engines.map(engine => {
    const last = CORE_PHASES.map(p => p.engine).lastIndexOf(engine)
    const completed = finished || elapsed >= (last + 1) * PHASE_DURATION
    const started = CORE_PHASES.findIndex(p => p.engine === engine) <= phase
    return { engine, execution: completed ? 'completed' : started ? 'running' : 'not_run', coverage: completed ? 'complete' : 'unknown', required: true, reason: 'Simulated training execution', counts: completed ? outcomeCounts(a, engine) : {} }
  })
  return {
    id: `${a.id}-job`, engagement_id: a.id, target: scan.target, kind: scan.kind,
    status: finished ? 'succeeded' : 'running', stage: finished ? 'complete' : CORE_PHASES[phase].stage, progress: finished ? 100 : Math.floor(elapsed / SCAN_DURATION * 100),
    started_at: scan.startedAt, finished_at: scan.finishedAt, error: '',
    engine_outcomes: engineOutcomes, engine_coverage: finished ? coverage : { status: 'unknown', required: engines.length, completed: engineOutcomes.filter(e => e.coverage === 'complete').length },
    debug_events: CORE_PHASES.slice(0, phase + 1).map((p, i) => {
      const complete = finished || i < phase
      return { stage: p.stage, step: p.title, status: complete ? 'completed' : 'running', message: p.why, tool: p.engine ? `demo-${p.engine}` : 'playground', counts: complete ? counts(i) : {}, started_at: new Date(Date.parse(scan.startedAt) + i * PHASE_DURATION).toISOString(), finished_at: complete ? new Date(Date.parse(scan.startedAt) + (i + 1) * PHASE_DURATION).toISOString() : null, duration_ms: complete ? PHASE_DURATION : elapsed - i * PHASE_DURATION }
    }),
  }
}
const manifest = { demo: true, tool_versions: Object.fromEntries(engines.map(e => [`demo-${e}`, '1'])), vuln_db_snapshot: 'DEMO-FEED-baseline', correlation_version: 1, sbom_sha256: DEMO_HASH, repro_score: 100, pinned_inputs: ['demo-repository', 'demo-feed'], unpinned_inputs: [] }
export function scanWire(a: DemoAssessment) {
  const comps = components(a)
  const unknown = comps.filter(c => !c.Licenses.length).length
  const licenses = [...new Set(comps.flatMap(c => c.Licenses.map(l => l.SPDXID)))].map(license => ({ license, category: license.startsWith('GPL') ? 'copyleft' : 'permissive', verdict: license.startsWith('GPL') ? 'review' : 'allow', severity: license.startsWith('GPL') ? 'medium' : 'info', components: comps.filter(c => c.Licenses.some(l => l.SPDXID === license)).map(c => c.Name) }))
  if (unknown) licenses.push({ license: 'Unknown', category: 'unknown', verdict: 'review', severity: 'info', components: comps.filter(c => !c.Licenses.length).map(c => c.Name) })
  return {
    target: a.scan!.target, scan_mode: a.scan!.mode, execution_mode: 'playground-simulation', engine_outcomes: outcomes.map(o => ({ ...o, counts: outcomeCounts(a, o.engine) })), engine_coverage: coverage,
    languages: [{ Name: 'TypeScript', Percent: 35 }, { Name: 'Go', Percent: 25 }, { Name: 'Python', Percent: 20 }, { Name: 'Java', Percent: 10 }, { Name: 'JavaScript', Percent: 10 }],
    sbom: { Components: comps, Dependencies: comps.map((c, i) => ({ Ref: c.PURL, DependsOn: DEMO_PACKAGES[i].dependencies.map(name => comps.find(x => x.Name === name)!.PURL) })) },
    vulnerabilities: a.id === INITIAL_ID ? DEMO_ISSUES.filter(x => x.advisory).map(issue => {
      const c = comps[issue.packageIndex!]
      return { ID: issue.advisory, Source: 'demo-feed', Sources: ['demo-feed'], Severity: issue.severity, Component: c.Name, Version: c.Version, Ecosystem: DEMO_PACKAGES[issue.packageIndex!].ecosystem, PackagePURL: c.PURL, FixedVersion: DEMO_PACKAGES[issue.packageIndex!].fixed, Description: `Synthetic advisory: ${issue.title}. ${issue.remediation}`, Direct: issue.direct, Confidence: 'high', Path: issue.direct ? [c.Name] : [issue.packageIndex === 8 ? 'checkout-http' : 'checkout-parser', c.Name], FixStatus: 'fix_available', VersionStatus: 'resolved', CVSSScore: SEVERITY_RISK[issue.severity] }
    }) : [],
    findings: a.findings.map(f => findingWire(a, f)), licenses,
    component_licenses: comps.map(c => ({ component: c.Name, version: c.Version, version_status: 'resolved', purl: c.PURL, license: c.Licenses[0]?.SPDXID ?? '', raw_license: c.Licenses[0]?.SPDXID ?? '', category: c.Licenses[0]?.Category ?? 'unknown', verdict: !c.Licenses.length || c.Licenses[0].Category === 'copyleft' ? 'review' : 'allow', location: c.Location, license_source: 'demo-manifest', license_confidence: c.LicenseConfidence })),
    completeness: { lockfiles: 4, components_total: comps.length, components_resolved: comps.length, confident: true, warning: '' }, license_coverage: { total: comps.length, detected: comps.length - unknown, unknown, pct: (comps.length - unknown) / comps.length * 100 },
    finding_quality: { raw_findings: a.findings.length, actionable: a.findings.length, by_priority: {} },
    manifest, tool_versions: manifest.tool_versions, vuln_db_snapshot: manifest.vuln_db_snapshot, debug_events: jobWire(a).debug_events,
  }
}
export function runWire(a: DemoAssessment) {
  return { id: runId(a), engagement_id: a.id, created_at: a.scan!.finishedAt, manifest, finding_keys: a.findings.map(f => findingWire(a, f).DedupKey), provenance: 'native', terminal_status: 'succeeded', sealed_at: a.scan!.finishedAt, manifest_hash: DEMO_HASH, lane_count: engines.length, complete_coverage: true, target_kind: 'git', target: a.scan!.target }
}
export function snapshotWire(a: DemoAssessment, s: Scenario) {
  return {
    id: snapshotId(a), cycle_id: CYCLE_ID, assessment_id: a.id, snapshot_number: 1, lifecycle: 'finalized', provenance: 'native',
    boundary: { boundary_kind: 'business_asset', business_asset_id: s.asset?.id, project_id: '' },
    run_references: [{ run_id: runId(a), manifest_hash: DEMO_HASH, lane_refs: outcomes.map(o => ({ lane_key: o.engine, manifest_hash: DEMO_HASH })) }],
    dimensions: outcomes.map(o => ({ run_id: runId(a), lane_key: o.engine, lane_manifest_hash: DEMO_HASH, producer: o.engine, finding_kind: o.engine === 'sast' ? 'sast' : o.engine === 'secrets' ? 'secret' : o.engine === 'iac' ? 'misconfig' : o.engine === 'licenses' ? 'license' : 'vulnerability', target: { kind: 'repository', schema_version: 1, canonical: TARGET, evaluated_revision: a.scan!.ref }, state: 'complete', reason_code: 'demo_complete', included_scope: [TARGET], excluded_scope: [], versions: [{ kind: 'tool', name: o.engine, version: '1' }] })),
    schema_version: 1, content_hash: DEMO_HASH, created_at: a.snapshotAt, finalized_at: a.snapshotAt, created_by: ACTOR, finalized_by: ACTOR, superseded_at: null,
  }
}
export function members(s: Scenario) {
  return s.assessments.map(a => ({ assessment_id: a.id, assessment_status: a.status, assessment_type: a.id === INITIAL_ID ? 'initial' : 'retest', predecessor_assessment_id: a.id === RETEST_ID ? INITIAL_ID : '', retest_number: a.id === RETEST_ID ? 1 : 0, relationship_version: 1, created_at: a.createdAt, created_by: ACTOR, archived_at: null }))
}
export function cycleWire(s: Scenario) {
  return { id: CYCLE_ID, name: `${s.asset?.name ?? 'Checkout API'} · assessment cycle`, boundary_kind: 'business_asset', business_asset_id: s.asset?.id, project_id: '', status: s.closure ? 'completed' : 'open', root_assessment_id: INITIAL_ID, selected_head_assessment_id: retest(s) ? RETEST_ID : INITIAL_ID, active_closure_manifest_id: s.closure ? MANIFEST_ID : '', active_closure_cycle_version: s.closure ? 3 : 0, next_retest_number: retest(s) ? 2 : 1, version: s.closure ? 3 : retest(s) ? 2 : 1, created_at: initial(s)?.createdAt, updated_at: s.closure?.at ?? retest(s)?.createdAt ?? initial(s)?.createdAt, created_by: ACTOR, updated_by: ACTOR }
}
export function lifecycleWire(s: Scenario) {
  const ms = members(s)
  return { cycle: cycleWire(s), members: ms, branch_heads: ms.slice(-1) }
}
// Mirror the core comparison scopes, including the core's misconfig finding kind.
export function inComparisonScope(kind: string, scope: string | null) {
  return !scope || scope === 'all' || scope === 'vulnerability' && kind === 'vulnerability' || scope === 'security' && ['vulnerability', 'sast', 'secret', 'misconfig'].includes(kind)
}
export function summaryWire(s: Scenario, scope: string | null = 'all') {
  const issues = DEMO_ISSUES.filter(issue => inComparisonScope(issue.kind, scope))
  const count = issues.length
  const risk = issues.reduce((sum, f) => sum + SEVERITY_RISK[f.severity], 0)
  const severity = Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map(level => [level, issues.filter(f => f.severity === level).length]))
  return { comparison_id: COMPARISON_ID, baseline_snapshot_id: `${INITIAL_ID}-snapshot-1`, current_snapshot_id: `${RETEST_ID}-snapshot-1`, risk_model_version: 1,
    fixed_rate: { numerator: count, denominator: count }, count_reduction: { numerator: count, denominator: count }, risk_reduction: { numerator: risk, denominator: risk }, fixed_count: count, baseline_count: count, current_count: 0, baseline_risk: risk, current_risk: 0, new_count: 0, reopened_count: 0, still_detected_count: 0, not_evaluated_count: 0, review_count: 0, baseline_severity: severity, current_severity: {}, as_of_at: s.comparisonAt }
}
export function comparisonWire(s: Scenario) {
  return { id: COMPARISON_ID, cycle_id: CYCLE_ID, ...summaryWire(s), mode: 'lifecycle', status: 'complete', version: 1, attempts: 1, algorithm_version: 1, fingerprint_version: 1, risk_model_version: 1, coverage_policy_version: 1, input_hash: DEMO_HASH, content_hash: DEMO_HASH, summary: summaryWire(s), created_at: s.comparisonAt, updated_at: s.comparisonAt, completed_at: s.comparisonAt }
}
export function comparisonItems(s: Scenario) {
  return initial(s)!.findings.map((f, i) => {
    const issue = DEMO_ISSUES[i]
    const engine = issue.kind === 'vulnerability' ? 'sca' : issue.kind === 'secret' ? 'secrets' : issue.kind === 'misconfig' ? 'iac' : issue.kind === 'license' ? 'licenses' : 'sast'
    return { id: `learn-diff-${i}`, position: i, identity_id: f.id, producer_kind: engine, finding_kind: issue.kind, target_canonical: TARGET, baseline_observation_id: f.id, current_observation_id: '', baseline_observation: { observed_at: initial(s)!.scan!.finishedAt, severity: issue.severity, component_version: issue.packageIndex === undefined ? '' : DEMO_PACKAGES[issue.packageIndex].version, location: issue.location, reachability: 'unknown', evidence_digest: DEMO_HASH, scanner: { scan_run_id: runId(initial(s)!), lane_key: engine, tool_name: `demo-${engine}`, tool_version: '1', rule_id: issue.advisory ?? `DEMO-RULE-${i + 1}` } }, current_observation: null, presence: 'not_detected_under_comparable_coverage', change_flags: ['evidence_changed'], coverage_decision: 'comparable', match_methods: ['stable_issue_identity'], verification_state: 'clear', fixed_basis: 'comparable_coverage', baseline_actionable: true, current_actionable: false, comparable_baseline: true, baseline_risk_milli: SEVERITY_RISK[issue.severity] * 1000, current_risk_milli: 0, review_candidate_ids: [] }
  })
}
export function closurePreview(s: Scenario) {
  return { cycle_id: CYCLE_ID, cycle_version: cycleWire(s).version, manifest_version: 1, final_assessment_id: RETEST_ID, initial_snapshot_id: `${INITIAL_ID}-snapshot-1`, final_snapshot_id: `${RETEST_ID}-snapshot-1`, comparison_id: COMPARISON_ID,
    path: members(s).map((m, i) => ({ ...m, path_position: i, snapshot_id: `${m.assessment_id}-snapshot-1` })),
    non_final_branches: [], policy: { policy_version: 'demo-policy-1', blockers: [], warnings: [{ code: 'playground_simulation', message: 'Training data only; hashes and policy evaluation are simulated.' }], coverage_decisions: { initial: [], final: [] }, commit_allowed: true }, references: [], scope_profile_changes: [], renderer_contract_version: 'demo-1', expires_at: s.preview?.expiresAt, preview_token: s.preview?.token }
}
export function closureManifest(s: Scenario) {
  return { ...closurePreview(s), demo: true, id: MANIFEST_ID, cycle_id: CYCLE_ID, lifecycle: 'active', cycle_version: 3, root_assessment_id: INITIAL_ID, reason: s.closure!.reason, created_at: s.closure!.at, as_of_at: s.closure!.at, sealed_at: s.closure!.at, created_by: ACTOR, sealed_by: ACTOR, content_hash: DEMO_HASH, initial_snapshot_hash: DEMO_HASH, final_snapshot_hash: DEMO_HASH, comparison_hash: DEMO_HASH, canonical_input_hash: DEMO_HASH, policy_version: 'demo-policy-1', algorithm_version: '1', fingerprint_version: '1', risk_version: '1', coverage_decisions: { initial: [], final: [] }, override_blocker_ids: [], override_reason: '', superseded_at: null }
}
export function syncWire(r: Scenario['syncs'][number], s: Scenario) {
  const inserted = Boolean(r.finishedAt && r.feedPublished && r.finishedAt === s.correlatedAt && s.syncs.find(x => x.feedPublished && x.finishedAt)?.id === r.id)
  return { id: r.id, source_id: s.source?.id, adapter_type: s.source?.adapter_type, mode: r.mode, trigger: 'manual', actor: ACTOR, durable_job_id: `${r.id}-job`, attempts: 1, dead_lettered: false, state: r.finishedAt ? 'succeeded' : 'running', created_at: r.startedAt, started_at: r.startedAt, updated_at: r.finishedAt ?? r.startedAt, finished_at: r.finishedAt, counts: { processed: r.finishedAt && r.feedPublished ? 1 : 0, inserted: inserted ? 1 : 0, updated: 0, unchanged: r.finishedAt && r.feedPublished && !inserted ? 1 : 0, skipped: 0, quarantined: 0 }, affected_revisions: inserted ? [{ advisory_id: DEMO_ADVISORY, revision: 1, changed_at: r.finishedAt }] : [], error_samples: [], checkpoint: {} }
}
export function sourceWire(s: Scenario) {
  const last = s.syncs.at(-1)
  const successful = [...s.syncs].reverse().find(r => r.finishedAt)
  return { ...s.source!, archived: false, adapter_config: {}, credential_configured: false, updated_at: s.source!.created_at, health: { state: successful ? 'healthy' : 'never_synced', stale: false, latest_run: last ? syncWire(last, s) : null, last_successful_at: successful?.finishedAt ?? null, fresh_until: successful ? new Date(Date.parse(successful.finishedAt!) + s.source!.stale_after_seconds * 1000).toISOString() : null } }
}
export function advisoryWire(s: Scenario) {
  return { canonical: { Advisory: { ID: DEMO_ADVISORY, Aliases: [], Summary: 'DEMO: newly published vulnerability in checkout-token@2.0.0; upgrade to 2.0.1.', CVSSScore: 7.5 }, Status: 'active', KEV: false, EPSS: null, PublicExploit: false, ActiveExploitation: false, Sources: ['checkout-demo'] }, revision: 1, changed_fields: ['advisory'], changed_at: s.correlatedAt, sync_run_ids: s.syncs.filter(r => r.feedPublished && r.finishedAt).map(r => r.id), active_affected_count: 1, affected_asset_count: 1, affected_component_count: 1, risk_priority: 2, risk_score: 7.5, risk_trend: 'increased', detection_states: ['detected'], action_states: ['open'], coverage_state: 'evaluated', coverage_reason: 'demo_inventory_match', last_evaluation: s.correlatedAt }
}
export function occurrenceWire(s: Scenario) {
  return { ID: 'learn-token-occurrence', EngagementID: RETEST_ID, AdvisoryID: DEMO_ADVISORY, AdvisoryRevision: 1, ComponentID: 'checkout-token', ComponentFingerprint: 'pkg:npm/checkout-token@2.0.0', Ecosystem: 'npm', Package: 'checkout-token', ComponentVersion: '2.0.0', FixedVersion: '2.0.1', MatchMethod: 'package_version', Confidence: 'high', Scope: 'in_scope', Reachability: 'unknown', State: 'detected', FirstDetectedAt: s.correlatedAt, LastDetectedAt: s.correlatedAt, LastEvaluatedAt: s.correlatedAt, UpdatedAt: s.correlatedAt }
}
export function actionWire(s: Scenario) {
  return { id: 'learn-monitor-action', engagement_id: RETEST_ID, occurrence_id: 'learn-token-occurrence', finding_id: '', type: 'new_exposure', status: 'open', title: 'DEMO: assess checkout-token@2.0.0 and plan remediation', reason_codes: ['new_advisory', 'matching_recorded_inventory', 'reachability_unknown'], created_at: s.correlatedAt, updated_at: s.correlatedAt }
}
export function inboxItems(s: Scenario) {
  return s.notificationDeliveredAt ? [{ id: 'learn-monitor-message', event_id: 'learn-monitor-event', event_type: EVENT_TYPE, title: 'DEMO: new vulnerability affects Checkout API', summary: `${DEMO_ADVISORY} matches checkout-token@2.0.0 in the retained Re-test inventory. A fix is available in 2.0.1. Historical snapshots and the closure report are unchanged.`, link_path: `/vulnerability-intelligence/advisories/${DEMO_ADVISORY}`, created_at: s.notificationDeliveredAt, read_at: s.notificationReadAt ?? undefined }] : []
}
