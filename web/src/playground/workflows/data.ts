import { AGENT_ID, AI_ENG, HOST_ID, INCIDENT_ID, PROJECT_KEY, REVIEWER, RUNTIME_ENG, type AIState, type QualityAnalysis, type QualityState, type RuntimeState } from './store'
import { AI_CASES, DETECTIONS, LANGUAGES, QUALITY_HOTSPOTS, QUALITY_ISSUES, RUNTIME_PACKAGES, counts } from './catalog'

export const stamp = () => new Date().toISOString()
export function engagement(id: string) {
  return { id, name: id === RUNTIME_ENG ? 'Checkout Runtime · Training' : 'Checkout AI Review · Training', client: 'Demo Company', status: 'active', scope: { in_scope: [{ kind: id === RUNTIME_ENG ? 'host' : 'repo', value: id === RUNTIME_ENG ? HOST_ID : 'https://checkout.example/checkout-api.git' }], out_of_scope: [] }, created_at: stamp(), roe: { allowed_tool_classes: [] } }
}
export const agent = (s: RuntimeState) => ({ id: AGENT_ID, name: 'checkout-demo-agent', platform: 'linux/amd64', agent_version: '0.9.4', state: 'healthy', last_seen: s.telemetryAt ?? s.enrolledAt, capabilities: ['scan.host', 'detect.runtime'], current_work: 0 })
export const host = (s: RuntimeState) => ({ asset: { ID: HOST_ID, Kind: 'host', Key: 'hostname/checkout-demo', Name: 'checkout-demo', Tags: ['training'], Audit: { CreatedAt: s.telemetryAt } }, engagement_id: RUNTIME_ENG, packages: RUNTIME_PACKAGES.length, recorded_at: s.telemetryAt, last_scan: null, summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, fixable: 0, kev: 0 } })
export const coverage = (s: RuntimeState) => ({ asset_id: HOST_ID, agent_id: AGENT_ID, host_id: HOST_ID, since: s.telemetryAt, until: s.telemetryAt, created_at: s.telemetryAt, input_digest: 'demo-telemetry', revision: 'training-1', states: ['process', 'network', 'file', 'privilege'].map(c => ({ class: c, host_id: HOST_ID, agent_id: AGENT_ID, state: 'covered', reason: '', since: s.telemetryAt })), sampled_count: 96, truncated_count: 0, dropped_count: 0, gap_count: 0, batch_count: 4, coverage: { process: 1, network: 1, file: 1, privilege: 1, reasons: [] } })
export function detection(s: RuntimeState, i = 0) {
  const d = DETECTIONS[i]
  return { ID: `learn-detection-${i + 1}`, AssetID: HOST_ID, AgentID: AGENT_ID, RecordedAt: s.detectedAt, Detection: { RuleID: `demo.${d.rule}`, RuleVersion: 1, Class: d.class, Severity: d.severity, Evidence: [d.evidence], Truncated: false, ObservedCount: d.count, Observed: s.detectedAt } }
}
export const response = (s: RuntimeState) => ({ id: 'learn-response-1', kind: 'isolate_host', target: HOST_ID, state: s.revertedAt ? 'reverted' : 'applied', approver: REVIEWER, verification: 'Simulation verified; no host was changed.', evidence_id: 'learn-response-evidence' })
export function incident(s: RuntimeState, i = 0) {
  const d = DETECTIONS[i], selected = i === 0
  return { ID: selected ? INCIDENT_ID : `learn-runtime-incident-${i + 1}`, AssetID: HOST_ID, Title: `Checkout demo · ${d.title.toLowerCase()}`, Severity: d.severity, State: selected ? s.incidentStatus : 'open', Disposition: selected ? s.disposition : 'unknown', OwnerID: selected ? s.owner : '', DetectionIDs: [`learn-detection-${i + 1}`], Risk: { AssessmentID: `learn-risk-${i + 1}`, IncidentRevision: 1, ScorerVersion: 'training', PolicyVersion: 'training', Risk: d.risk, Confidence: d.confidence, Coverage: 100, CoverageVector: { Process: 1, Network: 1, File: 1, Privilege: 1, Reasons: [] }, FactorContributions: [{ Factor: 'behavior', Points: d.risk, Detail: d.evidence }], ReasonCodes: ['training_detection'], CreatedAt: s.incidentAt }, Comments: selected && s.comment ? [{ At: s.incidentAt, Actor: REVIEWER, Text: s.comment }] : [], Responses: selected && s.appliedAt ? [{ ActionID: 'learn-response-1', Verified: true }] : [], Revision: 1, CreatedAt: s.incidentAt, UpdatedAt: selected ? s.revertedAt ?? s.incidentAt : s.incidentAt }
}

export const AI_TITLES = AI_CASES.map(c => c.title)
export function review(s: AIState, index: number) {
  const r = s.reviews[index], c = AI_CASES[index]
  return { id: r.id, tenant_id: 'demo', engagement_id: AI_ENG, project_id: '', finding_id: `learn-ai-finding-${index + 1}`, dedup_key: `learn-ai-${index + 1}`, title: c.title, severity: c.severity, cwe: c.cwe, owner: r.owner, state: r.state, verdict: 'refuted', driver: c.driver, confidence: c.confidence, suspected_fp: true, proposer_model: 'demo/proposer', proposer_provider: 'simulation', proposer_model_family: 'proposer', verifier_model: 'demo/verifier', verifier_provider: 'simulation', verifier_model_family: 'verifier', independence_policy: 'model_family', prompt_version: 'training-v1', verified: true, verifier_verdict: c.agrees ? 'refuted' : 'sound', verifier_driver: c.agrees ? c.driver : '', verifier_confidence: c.verifierConfidence, policy_version: 'training-v1', policy_reason: c.agrees ? 'both_models_agree_refuted' : 'verifier_disagrees', shadow: false, would_gate_exempt: c.agrees, gate_exempt: r.state === 'accepted', review_required: true, evidence_ref: c.file, decided_by: r.decidedAt ? REVIEWER : '', decision_rationale: r.rationale, created_at: s.proposalsAt, updated_at: r.decidedAt ?? s.proposalsAt, decided_at: r.decidedAt, version: r.version }
}
export function aiFinding(s: AIState, index: number) {
  const c = AI_CASES[index]
  return { ID: `learn-ai-finding-${index + 1}`, EngagementID: AI_ENG, Title: c.title, Description: `${c.file}. ${c.description}`, Severity: c.severity, Status: s.reviews[index].state === 'accepted' ? 'false_positive' : index === 1 ? s.findingStatus : 'open', Version: index === 1 ? s.findingVersion : s.reviews[index].version, CWE: Number(c.cwe.slice(4)), Assignee: index === 1 ? s.assignedTo : '', assignee_user_id: index === 1 ? s.assignedTo : '', DedupKey: `learn-ai-${index + 1}`, Kind: 'vulnerability', Class: 'first_party', Scope: 'in_scope', Reachability: 'unknown', Confidence: 'high', Priority: c.severity === 'critical' ? 1 : c.severity === 'high' ? 2 : c.severity === 'medium' ? 3 : 4, RiskScore: c.risk, EvidenceScore: c.verifierConfidence, KEV: false, Sources: ['demo-sast'], AdvisoryID: '', FixedVersion: '', DetectionState: 'detected', EvaluatedAt: s.proposalsAt, compliance_controls: [] }
}
export function observability(s: AIState) {
  const cases = s.proposalsAt ? AI_CASES : []
  const metrics = (indices: number[]) => ({ request_count: indices.length * 2, average_latency_ms: 0, timeout_count: 0, parse_failure_count: 0, provider_failure_count: 0, circuit_open_count: 0, total_tokens: 0, estimated_cost_micro_usd: 0, comparisons: indices.length, disagreements: indices.filter(i => !AI_CASES[i].agrees).length, gate_exemptions: indices.filter(i => s.reviews[i].state === 'accepted').length, findings: indices.length })
  const all = cases.map((_, i) => i), total = metrics(all)
  const basisPoints = (key: 'language' | 'cwe') => Object.fromEntries(Object.entries(counts(cases, key)).map(([k, n]) => [k, Math.round(n / cases.length * 10000)]))
  return { generated_at: stamp(), totals: { value: 'all', ...total }, by_model: ['demo/proposer', 'demo/verifier'].map(value => ({ value, ...total, request_count: cases.length })), by_prompt_version: [{ value: 'training-v1', ...total }], by_cwe: [...new Set(cases.map(c => c.cwe))].map(value => ({ value, ...metrics(all.filter(i => AI_CASES[i].cwe === value)) })), by_project: [], distribution: { schema_version: '1', sample_size: cases.length, language_basis_points: basisPoints('language'), cwe_basis_points: basisPoints('cwe'), project_basis_points: {} }, alerts: [] }
}

export function analysis(a: QualityAnalysis) {
  const improved = a.ref === 'improved'
  const issues = improved ? [] : QUALITY_ISSUES
  const severities = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...counts(issues, 'severity') }
  return { id: a.id, created_at: a.finishedAt, source_ref: `refs/heads/${a.ref}`, source_commit: improved ? 'b2c3d4e' : 'a1b2c3d', gate: { passed: improved, results: [{ metric: 'coverage', condition: '>= 80', op: '>=', threshold: 80, actual: improved ? 86 : 64, passed: improved }, { metric: 'new_critical', condition: '<= 0', op: '<=', threshold: 0, actual: severities.critical, passed: improved }] }, gate_info: { key: 'default', name: 'Synapse Way', source: 'managed' }, issues: { total: issues.length, by_severity: severities, by_kind: counts(issues, 'type') }, new_code: { previous_id: improved ? 'learn-quality-analysis-main' : '', counts: { total: issues.length, ...severities }, rating: { security: improved ? 'A' : 'D', reliability: improved ? 'A' : 'C', maintainability: improved ? 'A' : 'C', lines_of_code: 1000, tech_debt_minutes: improved ? 0 : 120 } }, measures: { lines: 1200, ncloc: 1000, coverage: improved ? 86 : 64, duplicated_lines_density: improved ? 1 : 5 }, coverage: { covered_lines: improved ? 860 : 640, total_lines: 1000 }, duplication: { duplicated_lines: improved ? 10 : 50, total_lines: 1000, files: 12 }, rating: { security: improved ? 'A' : 'D', reliability: improved ? 'A' : 'C', maintainability: improved ? 'A' : 'C', lines_of_code: 1000, tech_debt_minutes: improved ? 0 : 120 } }
}
export function job(a: QualityAnalysis) { return { id: `${a.id}-job`, target: PROJECT_KEY, kind: 'git', mode: 'full', status: a.finishedAt ? 'succeeded' : 'running', stage: a.finishedAt ? 'done' : 'analyzing source', started_at: a.startedAt, finished_at: a.finishedAt, error: '' } }
export function project(s: QualityState) {
  if (!s.project) return null
  const a = s.analyses.filter(a => a.finishedAt).at(-1)
  return { id: 'learn-quality-project', tenant_id: 'demo', name: s.project.name, key: s.project.key, source_binding: { kind: 'git', value: s.project.source, ref: s.project.ref }, default_profile_by_lang: Object.fromEntries(LANGUAGES.map(l => [l.Name.toLowerCase(), 'default'])), gate_id: s.project.gateId, created_at: s.project.createdAt, updated_at: s.project.createdAt, latest_analysis: a ? { ...analysis(a), gate_passed: a.ref === 'improved', new_issues: a.ref === 'improved' ? 0 : QUALITY_ISSUES.length } : null, latest_job: s.analyses.length ? job(s.analyses.at(-1)!) : null }
}
export function overview(s: QualityState, branch = '') {
  const a = s.analyses.filter(a => a.finishedAt && (!branch || a.ref === branch)).at(-1)
  if (!a) {
    const unavailable = { availability: 'unavailable', value: null, grade: null, unavailable_reason: 'no_analysis' }
    const lens = { security: unavailable, reliability: unavailable, maintainability: unavailable, security_hotspots_reviewed: unavailable, coverage: unavailable, duplications: unavailable }
    return { state: 'not_analyzed', project: { key: PROJECT_KEY, name: s.project?.name ?? 'Checkout Quality' }, latest_analysis: null, gate: null, issue_summary: { new_code_total: unavailable, accepted_overall_total: unavailable }, lenses: { overall: lens, new_code: lens } }
  }
  const improved = a.ref === 'improved'
  const rating = (grade: string) => ({ availability: 'available', grade, unavailable_reason: null })
  const percent = (value: number) => ({ availability: 'available', value, unavailable_reason: null })
  const lens = { security: rating(improved ? 'A' : 'D'), reliability: rating(improved ? 'A' : 'C'), maintainability: rating(improved ? 'A' : 'C'), security_hotspots_reviewed: percent(improved ? 100 : s.hotspotStatus === 'safe' ? 100 / QUALITY_HOTSPOTS.length : 0), coverage: percent(improved ? 86 : 64), duplications: percent(improved ? 1 : 5) }
  return { state: 'analyzed', project: { key: PROJECT_KEY, name: s.project?.name }, latest_analysis: { id: a.id, created_at: a.finishedAt, source_ref: `refs/heads/${a.ref}`, source_commit: improved ? 'b2c3d4e' : 'a1b2c3d', new_code: { first_analysis: !improved, has_baseline: improved, baseline_analysis_id: improved ? 'learn-quality-analysis-main' : null } }, gate: { status: improved ? 'passed' : 'failed', key: 'default', name: 'Synapse Way', source: 'managed', failed_conditions: improved ? [] : [{ metric: 'new_critical', operator: '<=', threshold: 0, actual: counts(QUALITY_ISSUES, 'severity').critical }, { metric: 'coverage', operator: '>=', threshold: 80, actual: 64 }] }, issue_summary: { new_code_total: percent(improved ? 0 : QUALITY_ISSUES.length), accepted_overall_total: percent(!improved && s.issueStatus === 'accepted' ? 1 : 0) }, lenses: { overall: lens, new_code: lens } }
}
export function qualityIssue(s: QualityState, i = 0, hotspot = false, selected = s.analyses.filter(a => a.finishedAt).at(-1)) {
  const improved = selected?.ref === 'improved'
  const c = hotspot ? QUALITY_HOTSPOTS[i] : QUALITY_ISSUES[i]
  const type = hotspot ? 'security_hotspot' : QUALITY_ISSUES[i].type
  return { id: `learn-${hotspot ? 'hotspot' : 'issue'}-${i + 1}`, rule_key: `${c.language}:checkout-${hotspot ? 'hotspot-' : ''}${i + 1}`, rule_name: c.title, title: c.title, description: c.description, severity: c.severity, type, finding_kind: type, cwe: c.cwe, language: c.language, file: c.file, location: `${c.file}:${c.line}`, status: hotspot ? improved ? i === 0 && s.hotspotStatus === 'safe' ? 'safe' : 'fixed' : i === 0 ? s.hotspotStatus : 'to_review' : i === 0 ? s.issueStatus : 'open', version: i === 0 ? hotspot ? s.hotspotVersion : s.issueVersion : improved ? 2 : 1, is_new: !improved, first_seen_analysis_id: 'learn-quality-analysis-main', last_seen_analysis_id: hotspot && improved ? 'learn-quality-analysis-improved' : 'learn-quality-analysis-main', first_seen_at: s.analyses[0]?.finishedAt, last_seen_at: hotspot ? selected?.finishedAt : s.analyses[0]?.finishedAt }
}
