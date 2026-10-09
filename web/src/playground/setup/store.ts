import { readDemoMode } from '../demo-mode'

export const SETUP_KEY = 'synapse.playground.setup.v1'
export const DEMO_SECRET = 'DEMO-ONLY-NOT-A-VALID-CREDENTIAL'
export const REVIEW_GOAL = 'Review retained evidence and summarize remediation priorities'
export interface Connection {
  id: string; provider: string; name: string; endpoint: string; config: Record<string, unknown>
  enabled: boolean; archived: boolean; version: number; connection_revision: number; credential_revision: number
  credential_configured: boolean; allow_private_network: boolean; poll_interval_seconds: number; created_at: string; updated_at: string
}
export interface Operation {
  id: string; integration_id: string; connection_revision: number; type: string; state: string; errors: string[]; created_at: string; updated_at: string; started_at: string; finished_at: string | null
  counts: { pipelines: number; runs: number; linked: number; unlinked: number; errors: number }
  pipelines: { external_key: string; name: string; full_name: string; kind: string; url: string }[]
}
export interface Binding { id: string; integration_id: string; project_id: string; external_key: string; external_name: string; version: number; created_at: string; updated_at: string }
export interface Connector { id: string; name: string; provider: string; host: string; username: string; auth_kind: string; created_at: string; updated_at: string }
export interface SetupData {
  version: 1; aiReady: boolean; aiRecordedAt: string | null; webhookReady: boolean; eventAt: string | null
  connectors: Connector[]; connections: Connection[]; operations: Operation[]; bindings: Binding[]; storageWarning: boolean
}
export const emptySetup = (): SetupData => ({ version: 1, aiReady: false, aiRecordedAt: null, webhookReady: false, eventAt: null, connectors: [], connections: [], operations: [], bindings: [], storageWarning: false })
function load(): SetupData {
  try {
    const raw = localStorage.getItem(SETUP_KEY)
    if (!raw || raw.length > 200000) return emptySetup()
    const s = JSON.parse(raw) as SetupData
    const next = emptySetup()
    if (s?.version !== 1) return next
    const date = (v: unknown) => v === null || typeof v === 'string' && Number.isFinite(Date.parse(v))
    if (typeof s.aiReady === 'boolean' && date(s.aiRecordedAt)) Object.assign(next, { aiReady: s.aiReady, aiRecordedAt: s.aiRecordedAt })
    if (typeof s.webhookReady === 'boolean' && date(s.eventAt) && [s.connectors, s.connections, s.operations, s.bindings].every(v => Array.isArray(v) && v.length <= 100 && v.every(r => r && typeof r.id === 'string'))) {
      Object.assign(next, { webhookReady: s.webhookReady, eventAt: s.eventAt, connectors: s.connectors, connections: s.connections, operations: s.operations, bindings: s.bindings })
    }
    return next
  } catch { return emptySetup() }
}
let state = load()
const listeners = new Set<() => void>()
export const setupStore = { getSnapshot: () => state, subscribe: (fn: () => void) => { listeners.add(fn); return () => { listeners.delete(fn) } } }
export function updateSetup(change: (s: SetupData) => void) {
  const next = structuredClone(state.storageWarning ? state : load()); change(next)
  next.storageWarning = false
  try { localStorage.setItem(SETUP_KEY, JSON.stringify(next)) } catch { next.storageWarning = true }
  state = next; listeners.forEach(fn => fn())
}
window.addEventListener('storage', e => { if (e.key === SETUP_KEY || e.key === null) { if (!state.storageWarning) state = load(); listeners.forEach(fn => fn()) } })
export function resetSetup(mode: 'ai-setup' | 'ci-setup') {
  updateSetup(s => { if (mode === 'ai-setup') { s.aiReady = false; s.aiRecordedAt = null } else { s.connectors = []; s.connections = []; s.operations = []; s.bindings = []; s.webhookReady = false; s.eventAt = null } })
}
export const aiReady = () => readDemoMode('overview') !== 'ai-setup' || setupStore.getSnapshot().aiReady
