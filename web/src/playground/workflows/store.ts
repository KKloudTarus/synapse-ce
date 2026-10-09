import { AI_CASES } from './catalog'
import { scenarioStore, updateScenario } from '../scenario/store'
import { readDemoMode, saveDemoMode, type DemoMode } from '../demo-mode'
export { DEMO_MODE_KEY, type DemoMode } from '../demo-mode'

export type WorkflowMode = 'runtime' | 'ai' | 'quality'
export const WORKFLOW_KEY = 'synapse.playground.workflows.v1'
export const RUNTIME_ENG = 'learn-runtime-assessment'
export const AI_ENG = 'learn-ai-assessment'
export const HOST_ID = 'learn-host-checkout'
export const AGENT_ID = 'learn-agent-checkout'
export const INCIDENT_ID = 'learn-runtime-incident'
export const PROJECT_KEY = 'checkout-quality'
export const PROJECT_TARGET = 'https://checkout.example/checkout-api.git'
export const REVIEWER = 'user-001'
export const DEMO_TOKEN = 'DEMO-ONLY-NOT-A-VALID-ENROLMENT-TOKEN'

export interface Progress { step: number; open: boolean; complete: boolean; completed: number[] }
export interface RuntimeState extends Progress {
  tokenAt: string | null; tokenExpiresAt: string | null; enrolledAt: string | null; telemetryAt: string | null; detectedAt: string | null
  incidentAt: string | null; incidentStatus: string; disposition: string; owner: string; comment: string
  planAt: string | null; appliedAt: string | null; revertedAt: string | null
}
export interface AIReview { id: string; state: 'pending' | 'accepted' | 'rejected'; owner: string; version: number; rationale: string; decidedAt: string | null }
export interface AIState extends Progress {
  proposalsAt: string | null; reviews: AIReview[]; assignedTo: string; findingStatus: string; comment: string; findingVersion: number
}
export interface QualityAnalysis { id: string; ref: 'main' | 'improved'; startedAt: string; finishedAt: string | null }
export interface QualityState extends Progress {
  project: { name: string; key: string; source: string; ref: string; gateId: string; createdAt: string } | null
  analyses: QualityAnalysis[]; issueStatus: string; issueRationale: string; issueVersion: number
  hotspotStatus: string; hotspotRationale: string; hotspotVersion: number; improvedAt: string | null
}
export interface Workflows { version: 1; mode: DemoMode; overviewComplete: boolean; storageWarning: boolean; runtime: RuntimeState; ai: AIState; quality: QualityState }
const progress = (): Progress => ({ step: 0, open: false, complete: false, completed: [] })
export function emptyRuntime(): RuntimeState { return { ...progress(), tokenAt: null, tokenExpiresAt: null, enrolledAt: null, telemetryAt: null, detectedAt: null, incidentAt: null, incidentStatus: 'open', disposition: 'unknown', owner: '', comment: '', planAt: null, appliedAt: null, revertedAt: null } }
export function emptyAI(): AIState { return { ...progress(), proposalsAt: null, reviews: AI_CASES.map((_, i) => ({ id: `learn-review-${i + 1}`, state: 'pending', owner: '', version: 1, rationale: '', decidedAt: null })), assignedTo: '', findingStatus: 'open', comment: '', findingVersion: 1 } }
export function emptyQuality(): QualityState { return { ...progress(), project: null, analyses: [], issueStatus: 'open', issueRationale: '', issueVersion: 1, hotspotStatus: 'to_review', hotspotRationale: '', hotspotVersion: 1, improvedAt: null } }
export function emptyWorkflows(): Workflows { return { version: 1, mode: scenarioStore.getSnapshot().enabled ? 'code' : 'overview', overviewComplete: false, storageWarning: false, runtime: emptyRuntime(), ai: emptyAI(), quality: emptyQuality() } }
export function isWorkflow(mode: string): mode is WorkflowMode { return ['runtime', 'ai', 'quality'].includes(mode) }

const bounded = (value: unknown) => typeof value === 'string' && value.length <= 2000
const date = (value: unknown) => value === null || typeof value === 'string' && Number.isFinite(Date.parse(value))
const validProgress = (p: Progress, count: number) => p && Number.isInteger(p.step) && p.step >= 0 && p.step < count && typeof p.open === 'boolean' && typeof p.complete === 'boolean' && Array.isArray(p.completed) && p.completed.length <= count && p.completed.every(i => Number.isInteger(i) && i >= 0 && i < count)

function load(fallback?: Workflows): Workflows {
  const empty = emptyWorkflows()
  try {
    const raw = localStorage.getItem(WORKFLOW_KEY)
    const parsed = raw && raw.length < 100_000 ? JSON.parse(raw) as Workflows : null
    empty.mode = readDemoMode(empty.mode)
    if (!parsed || parsed.version !== 1 || parsed.overviewComplete !== undefined && typeof parsed.overviewComplete !== 'boolean' || !validProgress(parsed.runtime, 27) || !validProgress(parsed.ai, 19) || !validProgress(parsed.quality, 24)) return empty
    const r = parsed.runtime, a = parsed.ai, q = parsed.quality
    if (![r.tokenAt, r.tokenExpiresAt, r.enrolledAt, r.telemetryAt, r.detectedAt, r.incidentAt, r.planAt, r.appliedAt, r.revertedAt, a.proposalsAt, q.improvedAt].every(date) ||
      ![r.owner, r.comment, a.assignedTo, a.comment, q.issueRationale, q.hotspotRationale].every(bounded) ||
      !['open', 'investigating', 'resolved'].includes(r.incidentStatus) || !['unknown', 'true_positive'].includes(r.disposition) || !['open', 'confirmed'].includes(a.findingStatus) || !['open', 'accepted'].includes(q.issueStatus) || !['to_review', 'safe'].includes(q.hotspotStatus) ||
      ![a.findingVersion, q.issueVersion, q.hotspotVersion].every(v => Number.isInteger(v) && v > 0) ||
      !Array.isArray(a.reviews) || ![2, AI_CASES.length].includes(a.reviews.length) || !a.reviews.every((row, i) => row.id === `learn-review-${i + 1}` && ['pending', 'accepted', 'rejected'].includes(row.state) && Number.isInteger(row.version) && row.version > 0 && bounded(row.owner) && bounded(row.rationale) && date(row.decidedAt)) ||
      !Array.isArray(q.analyses) || q.analyses.length > 2 || !q.analyses.every(row => ['main', 'improved'].includes(row.ref) && row.id === `learn-quality-analysis-${row.ref}` && date(row.startedAt) && row.startedAt !== null && date(row.finishedAt)) || new Set(q.analyses.map(row => row.ref)).size !== q.analyses.length ||
      q.project && (q.project.key !== PROJECT_KEY || q.project.source !== PROJECT_TARGET || !bounded(q.project.name) || !['main', 'improved'].includes(q.project.ref) || q.project.gateId !== 'default' || !date(q.project.createdAt))) return empty
    return { ...empty, overviewComplete: parsed.overviewComplete ?? false, runtime: { ...empty.runtime, ...parsed.runtime }, ai: { ...empty.ai, ...parsed.ai, reviews: empty.ai.reviews.map((row, i) => parsed.ai.reviews[i] ?? row) }, quality: { ...empty.quality, ...parsed.quality } }
  } catch { return fallback ?? empty }
}
let state = load()
const listeners = new Set<() => void>()
function latestState() {
  const next = load(state)
  next.mode = state.mode
  for (const mode of ['runtime', 'ai', 'quality'] as const) next[mode].open = state[mode].open
  return next
}
window.addEventListener('storage', event => {
  if (event.key !== WORKFLOW_KEY && event.key !== null) return
  state = latestState()
  listeners.forEach(listener => listener())
})
export const workflowStore = { getSnapshot: () => state, subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener) } } }
export function updateWorkflows(change: (draft: Workflows) => void) {
  // Re-read before every edit so an older tab cannot replace another chapter's saved progress.
  const next = structuredClone(latestState()); change(next)
  saveDemoMode(next.mode)
  try { localStorage.setItem(WORKFLOW_KEY, JSON.stringify(next)); next.storageWarning = false } catch { next.storageWarning = true }
  state = next; listeners.forEach(listener => listener())
}
export function chooseMode(mode: DemoMode) {
  updateScenario(s => { s.enabled = mode === 'code'; s.open = mode === 'code' })
  updateWorkflows(s => { s.mode = mode; if (isWorkflow(mode)) s[mode].open = true })
}
export function resetWorkflow(mode: WorkflowMode) {
  updateWorkflows(s => { if (mode === 'runtime') s.runtime = emptyRuntime(); if (mode === 'ai') s.ai = emptyAI(); if (mode === 'quality') s.quality = emptyQuality(); s[mode].open = true })
}
export function settleWorkflows(now = Date.now()) {
  if (!state.quality.analyses.some(a => !a.finishedAt && now - Date.parse(a.startedAt) >= 4000)) return
  updateWorkflows(s => { for (const a of s.quality.analyses) if (!a.finishedAt && now - Date.parse(a.startedAt) >= 4000) a.finishedAt = new Date(now).toISOString() })
}
