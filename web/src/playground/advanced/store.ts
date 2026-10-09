import { resetSetup } from '../setup/store'
import type { OwnershipAssignment, OwnershipDecision } from '@/lib/api/ownership'
import type { QualityGateCondition } from '@/lib/types'
import { readDemoMode } from '../demo-mode'
import { DEMO_ISSUES } from '../scenario/catalog'
import { emptyScenario, INITIAL_ID, RETEST_ID, TARGET, type Scenario } from '../scenario/store'
import { emptyQuality, PROJECT_KEY, type Progress, type QualityState } from '../workflows/store'

export type AdvancedMode = 'remediation' | 'intelligence' | 'policy' | 'ai-setup' | 'ci-setup'
export const ADVANCED_KEY = 'synapse.playground.advanced.v1'
export const GATE_KEY = 'checkout-release'
export const PROFILE_KEY = 'checkout-typescript'
export const CLOSURE_REASON = 'Comparable verification reviewed. Retained findings have an assigned owner and a time-limited release exception.'
export const OVERRIDE_REASON = 'Platform Security accepts the seven retained findings for this synthetic release. Review in seven days; ownership and remediation due dates remain active.'
export interface RemediationState extends Progress {
  scenario: Scenario; assignment: OwnershipAssignment; findingVersion: number; history: OwnershipDecision[]
  coverageRestored: boolean; verificationAt: string | null; overrideIds: string[]; overrideReason: string
}
export interface IntelRun { id: string; sourceId: string; mode: 'incremental' | 'full'; startedAt: string; finishedAt: string | null; state: 'running' | 'failed' | 'succeeded' }
export interface IntelligenceState extends Progress { scenario: Scenario; runs: IntelRun[]; failureAt: string | null; recoveredAt: string | null; reconciledAt: string | null }
export interface PolicyState extends Progress {
  quality: QualityState; profileCopied: boolean; profileAssigned: boolean; ruleSeverity: string; gate: { key: string; name: string; conditions: QualityGateCondition[] } | null
  decoration: boolean; coverageImported: boolean; ciImportedAt: string | null
}
export interface AdvancedState { version: 1; storageWarning: boolean; 'ai-setup': Progress; 'ci-setup': Progress; remediation: RemediationState; intelligence: IntelligenceState; policy: PolicyState }
const progress = (): Progress => ({ step: 0, open: false, complete: false, completed: [] })
export function seededScenario(): Scenario {
  const s = emptyScenario(), at = new Date().toISOString()
  s.asset = { id: 'learn-checkout-asset', key: 'checkout-api', name: 'Checkout API', owner: 'Platform Engineering', description: 'Synthetic polyglot checkout service', type: 'application', criticality: 'high', created_at: at }
  s.assessments = [INITIAL_ID, RETEST_ID].map((id, i) => ({ id, name: i ? 'Checkout API · Re-test #1' : 'Checkout API · Initial assessment', client: 'Demo Company', status: 'completed', createdAt: at, scope: [{ kind: 'repo', value: TARGET }], outOfScope: [], authorizedFrom: at, authorizedTo: new Date(Date.now() + 86400000).toISOString(), timezone: 'UTC', tools: ['sca'], scan: { target: TARGET, ref: i ? 'fixed' : 'main', mode: 'full', kind: 'git', startedAt: at, finishedAt: at }, snapshotAt: at, findings: i ? [] : DEMO_ISSUES.map((_, n) => ({ id: `learn-finding-${n + 1}`, status: 'confirmed', assignee: '', version: 1, comments: [] })) }))
  return s
}
export function emptyRemediation(): RemediationState { const scenario = seededScenario(); scenario.assessments[1].findings = [...scenario.assessments[0].findings.slice(10, 14), ...[0, 5, 14].map(i => ({ ...scenario.assessments[0].findings[i], id: `learn-added-${i + 1}` }))]; return { ...progress(), scenario, assignment: { team_id: 'team-platform', assignee_id: '', legacy_assignee: '', mode: 'auto', revision: 1, manual_generation: 0 }, findingVersion: 1, history: [], coverageRestored: false, verificationAt: null, overrideIds: [], overrideReason: '' } }
export function emptyIntelligence(): IntelligenceState {
  const scenario = seededScenario(), at = scenario.asset!.created_at
  scenario.source = { id: 'learn-source', key: 'checkout-osv', name: 'Checkout OSV feed', endpoint: 'https://checkout.example/advisories.json', adapter_type: 'osv', enabled: true, cadence_seconds: 3600, stale_after_seconds: 7200, sync_mode: 'incremental', version: 1, created_at: at }
  return { ...progress(), scenario, runs: [], failureAt: null, recoveredAt: null, reconciledAt: null }
}
export function emptyPolicy(): PolicyState {
  const quality = emptyQuality(), at = new Date().toISOString()
  quality.project = { name: 'Checkout Release Policy', key: PROJECT_KEY, source: TARGET, ref: 'main', gateId: 'default', createdAt: at }
  quality.analyses = [{ id: 'learn-quality-analysis-main', ref: 'main', startedAt: at, finishedAt: at }]
  return { ...progress(), quality, profileCopied: false, profileAssigned: false, ruleSeverity: 'medium', gate: null, decoration: false, coverageImported: false, ciImportedAt: null }
}
const empty = (): AdvancedState => ({ version: 1, storageWarning: false, 'ai-setup': progress(), 'ci-setup': progress(), remediation: emptyRemediation(), intelligence: emptyIntelligence(), policy: emptyPolicy() })
export function isAdvanced(mode: string): mode is AdvancedMode { return ['remediation', 'intelligence', 'policy', 'ai-setup', 'ci-setup'].includes(mode) }
const bounded = (v: unknown) => typeof v === 'string' && v.length <= 4096
const date = (v: unknown) => v === null || typeof v === 'string' && Number.isFinite(Date.parse(v))
function valid(s: AdvancedState): boolean {
  if (!s || s.version !== 1) return false
  for (const mode of ['remediation', 'intelligence', 'policy', 'ai-setup', 'ci-setup'] as const) {
    const p = s[mode]
    const count = mode === 'remediation' ? 26 : mode === 'intelligence' ? 18 : mode === 'ai-setup' ? 10 : mode === 'ci-setup' ? 34 : 21
    if (!p || !Number.isInteger(p.step) || p.step < 0 || p.step >= count || typeof p.open !== 'boolean' || typeof p.complete !== 'boolean' || !Array.isArray(p.completed) || p.completed.length > count || !p.completed.every(i => Number.isInteger(i) && i >= 0 && i < count)) return false
  }
  const r = s.remediation, i = s.intelligence, q = s.policy
  return [r.scenario, i.scenario].every(v => v?.version === 2 && Array.isArray(v.assessments) && v.assessments.length === 2 && v.assessments.every(a => [INITIAL_ID, RETEST_ID].includes(a.id) && Array.isArray(a.findings) && a.findings.length <= 30 && a.findings.every(f => bounded(f.id) && Array.isArray(f.comments))) && v.asset?.key === 'checkout-api') &&
    typeof r.coverageRestored === 'boolean' && date(r.verificationAt) && ['auto', 'manual'].includes(r.assignment?.mode) && Number.isInteger(r.assignment.revision) && r.assignment.revision > 0 && Number.isInteger(r.findingVersion) && r.findingVersion > 0 && Array.isArray(r.history) && r.history.length <= 100 && Array.isArray(r.overrideIds) && r.overrideIds.every(bounded) && bounded(r.overrideReason) &&
    Array.isArray(i.runs) && i.runs.length <= 100 && i.runs.every(v => bounded(v.id) && ['learn-source', 'learn-osv-secondary'].includes(v.sourceId) && ['incremental', 'full'].includes(v.mode) && ['running', 'failed', 'succeeded'].includes(v.state) && date(v.startedAt) && v.startedAt !== null && date(v.finishedAt)) && [i.failureAt, i.recoveredAt, i.reconciledAt, q.ciImportedAt].every(date) &&
    q.quality?.project?.key === PROJECT_KEY && Array.isArray(q.quality.analyses) && q.quality.analyses.length <= 2 && q.quality.analyses.every(a => ['main', 'improved'].includes(a.ref) && date(a.startedAt) && date(a.finishedAt)) && [q.profileCopied, q.profileAssigned, q.decoration, q.coverageImported].every(v => typeof v === 'boolean') && ['critical', 'high', 'medium', 'low', 'info'].includes(q.ruleSeverity) && (!q.gate || q.gate.key === GATE_KEY && bounded(q.gate.name) && Array.isArray(q.gate.conditions) && q.gate.conditions.length === 3 && q.gate.conditions.every(c => bounded(c.metric) && ['<=', '>='].includes(c.op) && Number.isFinite(c.threshold)))
}
function load(fallback?: AdvancedState): AdvancedState {
  try { const raw = localStorage.getItem(ADVANCED_KEY); if (!raw || raw.length > 300000) return empty(); const value = JSON.parse(raw); if (value?.version === 1) { value['ai-setup'] ??= progress(); value['ci-setup'] ??= progress() }; if (value?.policy && value.policy.profileAssigned === undefined) value.policy.profileAssigned = false; return valid(value) ? value : empty() } catch { return fallback ?? empty() }
}
let state = load()
const listeners = new Set<() => void>()
function latest() { const next = load(state); for (const m of ['remediation', 'intelligence', 'policy', 'ai-setup', 'ci-setup'] as const) next[m].open = state[m].open; return next }
window.addEventListener('storage', e => { if (e.key !== ADVANCED_KEY && e.key !== null) return; state = latest(); listeners.forEach(fn => fn()) })
export const advancedStore = { getSnapshot: () => state, subscribe: (fn: () => void) => { listeners.add(fn); return () => { listeners.delete(fn) } } }
export function updateAdvanced(change: (s: AdvancedState) => void) { const next = structuredClone(latest()); change(next); try { localStorage.setItem(ADVANCED_KEY, JSON.stringify(next)); next.storageWarning = false } catch { next.storageWarning = true }; state = next; listeners.forEach(fn => fn()) }
export function resetAdvanced(mode: AdvancedMode) { if (mode === 'ai-setup' || mode === 'ci-setup') resetSetup(mode); updateAdvanced(s => { if (mode === 'remediation') s.remediation = emptyRemediation(); if (mode === 'intelligence') s.intelligence = emptyIntelligence(); if (mode === 'policy') s.policy = emptyPolicy(); if (mode === 'ai-setup' || mode === 'ci-setup') s[mode] = progress(); s[mode].open = true }) }
export function settleAdvanced(now = Date.now()) {
  const mode = readDemoMode('overview')
  if (mode === 'policy' && state.policy.quality.analyses.some(a => !a.finishedAt && now - Date.parse(a.startedAt) >= 2400)) updateAdvanced(s => { s.policy.quality.analyses.forEach(a => { if (!a.finishedAt && now - Date.parse(a.startedAt) >= 2400) a.finishedAt = new Date(now).toISOString() }) })
  if (mode !== 'intelligence' || !state.intelligence.runs.some(r => !r.finishedAt && now - Date.parse(r.startedAt) >= 1800)) return
  updateAdvanced(s => { const i = s.intelligence; for (const r of i.runs) if (!r.finishedAt && now - Date.parse(r.startedAt) >= 1800) { r.finishedAt = new Date(now).toISOString(); r.state = 'succeeded'; if (r.sourceId === 'learn-source') i.recoveredAt ??= r.finishedAt; if (r.mode === 'full' && r.sourceId === 'learn-source') { i.reconciledAt ??= r.finishedAt; i.scenario.correlatedAt ??= r.finishedAt; if (i.scenario.notificationPreference !== 'disabled') i.scenario.notificationDeliveredAt ??= r.finishedAt } } })
}
