import { DEMO_ISSUES, SCAN_DURATION } from './catalog'
import { readDemoMode } from '../demo-mode'
// One browser-local document owns both tutorial progress and the exercise data. Pausing a guide
// never discards a scan; reloading never resumes a checklist against unrelated seeded records.
export const SCENARIO_KEY = 'synapse.playground.scan.v1'
export const TARGET = 'https://checkout.example/checkout-api.git'
export const DEMO_ADVISORY = 'DEMO-CHECKOUT-004'
export const CYCLE_ID = 'learn-checkout-cycle'
export const INITIAL_ID = 'learn-checkout-initial'
export const RETEST_ID = 'learn-checkout-retest'
export const COMPARISON_ID = 'learn-checkout-comparison'
export const EVENT_TYPE = 'vulnerability_action.created'

export interface DemoAsset {
  id: string; key: string; name: string; owner: string; description: string
  type: string; criticality: string; created_at: string
}
export interface DemoFinding {
  id: string; status: string; assignee: string; version: number
  comments: { id: string; body: string; created_at: string }[]
}
export interface DemoAssessment {
  id: string; name: string; client: string; status: string; createdAt: string
  scope: { kind: string; value: string }[]; outOfScope: { kind: string; value: string }[]
  authorizedFrom: string; authorizedTo: string; timezone: string; tools: string[]
  scan: { target: string; ref: string; mode: string; kind: string; startedAt: string; finishedAt: string | null } | null
  snapshotAt: string | null; findings: DemoFinding[]
}
export interface DemoSource {
  id: string; key: string; name: string; endpoint: string; adapter_type: string
  enabled: boolean; cadence_seconds: number; stale_after_seconds: number; sync_mode: string
  version: number; created_at: string
}
export interface Scenario {
  version: 2; enabled: boolean; open: boolean; collapsed: boolean; step: number; microStep: number
  completed: string[]; skipped: string[]; storageWarning: boolean
  asset: DemoAsset | null; assessments: DemoAssessment[]
  comparisonAt: string | null; closure: { at: string; reason: string; token: string } | null
  preview: { token: string; expiresAt: string; reason: string } | null
  reportDownloaded: boolean; source: DemoSource | null; connectionTested: boolean
  syncs: { id: string; startedAt: string; finishedAt: string | null; feedPublished: boolean; mode: string }[]
  feedPublished: boolean; correlatedAt: string | null; notificationDeliveredAt: string | null; notificationReadAt: string | null
  notificationPreference: 'inherit' | 'enabled' | 'disabled'; preferenceRevision: number
  monitorInvestigated: boolean
}

export function emptyScenario(): Scenario {
  return {
    version: 2, enabled: false, open: false, collapsed: false, step: 0, microStep: 0, completed: [], skipped: [], storageWarning: false,
    asset: null, assessments: [], comparisonAt: null, closure: null, preview: null, reportDownloaded: false,
    source: null, connectionTested: false, syncs: [], feedPublished: false, correlatedAt: null,
    notificationDeliveredAt: null, notificationReadAt: null, notificationPreference: 'inherit', preferenceRevision: 1, monitorInvestigated: false,
  }
}

function load(resetForm = false, fallback?: Scenario): Scenario {
  try {
    const raw = localStorage.getItem(SCENARIO_KEY)
    if (!raw || raw.length > 200_000) return emptyScenario()
    const s = JSON.parse(raw) as Scenario
    if (s.version as number === 1) return { ...emptyScenario(), enabled: s.enabled === true, open: s.open === true }
    // Reject stale or malformed documents instead of mixing old progress into the new fixtures.
    if (s.version !== 2 || typeof s.enabled !== 'boolean' || typeof s.open !== 'boolean' ||
        !Number.isInteger(s.step) || s.step < 0 || s.step >= 26 || !Array.isArray(s.completed) ||
        !s.completed.every(x => typeof x === 'string') || !Array.isArray(s.skipped) ||
        !s.skipped.every(x => typeof x === 'string') || !Array.isArray(s.assessments) || s.assessments.length > 2 ||
        !s.assessments.every(a => [INITIAL_ID, RETEST_ID].includes(a.id) && typeof a.name === 'string' &&
          typeof a.authorizedFrom === 'string' && typeof a.authorizedTo === 'string' && Array.isArray(a.scope) &&
          Array.isArray(a.outOfScope) && Array.isArray(a.tools) && Array.isArray(a.findings) &&
          a.findings.every(f => typeof f.id === 'string' && Array.isArray(f.comments)) &&
          (!a.scan || typeof a.scan.startedAt === 'string')) || !Array.isArray(s.syncs) || s.syncs.length > 100 ||
        !s.syncs.every(r => typeof r.id === 'string' && typeof r.startedAt === 'string') ||
        !['inherit', 'enabled', 'disabled'].includes(s.notificationPreference) ||
        (s.asset && (typeof s.asset.key !== 'string' || typeof s.asset.name !== 'string')) ||
        (s.source && (typeof s.source.id !== 'string' || typeof s.source.enabled !== 'boolean'))) return emptyScenario()
    // Unsubmitted forms belong to the page, not the dataset. Re-enter their first action after
    // reload; completed API transitions are recovered by the guide's checkpoint predicates.
    return { ...emptyScenario(), ...s, enabled: readDemoMode(s.enabled ? 'code' : 'overview') === 'code', microStep: resetForm ? 0 : s.microStep }
  } catch { return fallback ?? emptyScenario() }
}

let state = load(true)
const listeners = new Set<() => void>()
function latestState() {
  const next = load(false, state)
  return { ...next, enabled: state.enabled, open: state.open, collapsed: state.collapsed, microStep: next.step === state.step ? state.microStep : 0 }
}
window.addEventListener('storage', event => {
  if (event.key !== SCENARIO_KEY && event.key !== null) return
  state = latestState()
  for (const listener of listeners) listener()
})
export const scenarioStore = {
  getSnapshot: () => state,
  subscribe: (listener: () => void) => {
    listeners.add(listener)
    return () => { listeners.delete(listener) }
  },
}
export function updateScenario(change: (draft: Scenario) => void) {
  const next = structuredClone(latestState())
  change(next)
  try { localStorage.setItem(SCENARIO_KEY, JSON.stringify(next)); next.storageWarning = false }
  catch { next.storageWarning = true }
  state = next
  for (const listener of listeners) listener()
}
export function resetScenario() {
  state = emptyScenario()
  try { localStorage.removeItem(SCENARIO_KEY) } catch { state.storageWarning = true }
  for (const listener of listeners) listener()
}
export const initial = (s: Scenario) => s.assessments.find(a => a.id === INITIAL_ID)
export const retest = (s: Scenario) => s.assessments.find(a => a.id === RETEST_ID)

// Jobs advance from recorded timestamps, so a refresh or a paused guide does not lose the run.
// Intelligence has a separate sync stage; publication alone cannot create an Inbox message.
export function settleScenario(now = Date.now()) {
  const pendingScans = state.assessments.some(a => a.scan && !a.scan.finishedAt && now - Date.parse(a.scan.startedAt) >= SCAN_DURATION)
  const pendingSyncs = state.syncs.some(r => !r.finishedAt && now - Date.parse(r.startedAt) >= 2400)
  if (!pendingScans && !pendingSyncs) return
  const hadNotification = Boolean(state.notificationDeliveredAt)
  updateScenario(s => {
    for (const a of s.assessments) {
      if (a.scan && !a.scan.finishedAt && now - Date.parse(a.scan.startedAt) >= SCAN_DURATION) {
        a.scan.finishedAt = new Date(now).toISOString()
        a.findings = a.id === INITIAL_ID ? DEMO_ISSUES.map((_, index) => ({ id: `learn-finding-${index + 1}`, status: 'open', assignee: '', version: 1, comments: [] })) : []
      }
    }
    for (const r of s.syncs) {
      if (r.finishedAt || now - Date.parse(r.startedAt) < 2400) continue
      r.finishedAt = new Date(now).toISOString()
      // Only the latest retained inventory with the matching version is evaluated. Never mutate
      // the completed assessment, its finalized snapshot, or its closure report.
      if (r.feedPublished && s.source?.enabled && retest(s)?.scan?.finishedAt && !s.correlatedAt) {
        s.correlatedAt = r.finishedAt
        if (s.notificationPreference !== 'disabled') s.notificationDeliveredAt = r.finishedAt
      }
    }
  })
  if (!hadNotification && state.notificationDeliveredAt && typeof document !== 'undefined') {
    document.dispatchEvent(new Event('visibilitychange')) // Refresh the existing notification bell.
  }
}

export function publishDemoAdvisory() {
  updateScenario(s => { if (s.source?.enabled && retest(s)?.scan?.finishedAt) s.feedPublished = true })
}
