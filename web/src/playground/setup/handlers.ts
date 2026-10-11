import { http, HttpResponse } from 'msw'
import { aiReady, DEMO_SECRET, REVIEW_GOAL, setupStore, updateSetup, type Operation } from './store'
import { providers } from './providers'

const json = (value: unknown, status = 200) => HttpResponse.json(value as never, { status })
const error = (message: string, status = 409) => json({ error: message, message }, status)
const now = () => new Date().toISOString()
const text = (v: unknown) => typeof v === 'string' ? v.trim().slice(0, 2000) : ''
export function agentReadiness(ready: boolean) {
  return { overall: ready ? 'ready' : 'blocked', target_kinds: ['repo'], suggested_goals: [REVIEW_GOAL],
    items: [
      { id: 'provider', label: 'Provider and model', ok: ready, blocking: true, detail: ready ? 'Simulated provider configuration verified. No model is contacted.' : 'Deployment configuration is missing. Review the setup preview before continuing.' },
      { id: 'policy', label: 'Human review policy', ok: true, blocking: true, detail: 'Manual review is retained. This example only summarizes existing evidence.' },
      { id: 'evidence', label: 'Retained evidence', ok: true, blocking: true, detail: 'A recorded assessment is available for the synthetic review.' },
    ], workflows: [{ id: 'review', label: 'Review retained evidence', description: 'Summarize existing findings and remediation priorities.', ready, blockers: ready ? [] : ['Provider configuration missing'], suggested_goal: REVIEW_GOAL }] }
}
const session = (id: string) => ({ ID: 'demo-evidence-review', EngagementID: id, InitiatedBy: 'user-001', Goal: REVIEW_GOAL, Model: 'simulated-review-model', Status: 'succeeded', Steps: 2, TokensUsed: 0, CreatedAt: setupStore.getSnapshot().aiRecordedAt, UpdatedAt: setupStore.getSnapshot().aiRecordedAt })
export const setupHandlers = [http.all('/api/v1/*', async ({ request }) => {
  const path = new URL(request.url).pathname.slice(7), method = request.method
  let s = setupStore.getSnapshot()
  const patch = (change: Parameters<typeof updateSetup>[0]) => { updateSetup(change); s = setupStore.getSnapshot() }
  const handled = /^\/(integration-providers|integrations(?:\/|$)|integration-operations\/|connectors(?:\/|$)|playground\/setup\/|engagements\/[^/]+\/agent\/)/.test(path)
  if (!handled) return
  let b: Record<string, unknown> = {}
  if (method !== 'GET' && method !== 'DELETE') { try { b = await request.json() as Record<string, unknown> } catch { return error('A JSON request is required.', 400) } }
  if (path === '/playground/setup/ai-ready' && method === 'POST') { patch(d => { d.aiReady = true }); return json({ simulation: true }) }
  if (path === '/playground/setup/webhook' && method === 'POST') {
    if (!s.connections.some(c => c.provider === 'github')) return error('Create the GitHub inbound connection first.')
    patch(d => { d.webhookReady = true }); return json({ simulation: true, path: '/api/v1/hooks/demo-github' })
  }
  if (path === '/playground/setup/event' && method === 'POST') {
    const c = s.connections.find(c => c.provider === 'github')
    if (!s.webhookReady || !c?.enabled || !s.bindings.some(v => v.integration_id === c.id)) return error('Provision the webhook, bind one Project and enable the connection first.')
    patch(d => { d.eventAt = now() }); return json({ simulation: true, delivery_id: 'demo-pr-42', commit: 'a1b2c3d', analysis_id: 'an-001' })
  }
  const agent = path.match(/^\/engagements\/([^/]+)\/agent\/(.+)$/)
  if (agent) {
    const [, id, action] = agent
    if (method === 'GET') {
      if (action === 'readiness') return json(agentReadiness(aiReady()))
      if (action === 'approvals') return json([])
      if (action === 'sessions') return json(s.aiRecordedAt ? [session(id)] : [])
      if (action === 'sessions/demo-evidence-review') return json({ session: session(id), transcript: [
        { role: 'user', content: REVIEW_GOAL },
        { role: 'assistant', content: 'Synthetic review of retained evidence. Prioritize Critical and High findings, assign owners and require comparable re-test coverage before closure. No tools, network requests or model calls were executed. Human review remains required.' },
      ] })
      if (action.endsWith('/decisions')) return json({ decisions: [] })
      if (action.endsWith('/plan')) return json({ plan: null })
      if (action.endsWith('/stream')) return new HttpResponse('event: done\ndata: {"status":"succeeded"}\n\n', { headers: { 'Content-Type': 'text/event-stream' } })
    }
    if (action === 'sessions' && method === 'POST') {
      if (!aiReady()) return error('Complete the simulated readiness check first.')
      if (text(b.goal) !== REVIEW_GOAL) return error('This demo supports only the supplied retained-evidence review.', 422)
      patch(d => { d.aiRecordedAt = now() }); return json(session(id), 201)
    }
    return error('This agent action is not simulated. Use the retained-evidence review example.', 422)
  }
  if (path === '/integration-providers' && method === 'GET') return json(providers)
  if (path === '/connectors') {
    if (method === 'GET') return json({ connectors: s.connectors })
    if (method === 'POST') {
      if (b.token !== DEMO_SECRET) return error('Use the supplied demo credential. Do not enter a real token.', 400)
      if (!text(b.name) || !text(b.host)) return error('Name and host are required.', 400)
      const row = { id: `demo-connector-${crypto.randomUUID()}`, name: text(b.name), provider: text(b.provider), host: text(b.host), username: text(b.username), auth_kind: 'pat', created_at: now(), updated_at: now() }
      patch(d => { d.connectors.push(row) }); return json(row, 201)
    }
  }
  if (/^\/connectors\/[^/]+$/.test(path) && method === 'DELETE') { patch(d => { d.connectors = d.connectors.filter(c => c.id !== path.split('/')[2]) }); return new HttpResponse(null, { status: 204 }) }
  if (path === '/integrations') {
    if (method === 'GET') return json(s.connections.filter(c => !c.archived))
    if (method === 'POST') {
      if (!providers.some(p => p.provider === b.provider) || !text(b.name)) return error('Select a supported provider and display name.', 400)
      try { const url = new URL(text(b.endpoint)); if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error() } catch { return error('Use an HTTPS origin without credentials, query or fragment.', 400) }
      const row = { id: `demo-${b.provider}-${crypto.randomUUID()}`, provider: text(b.provider), name: text(b.name), endpoint: text(b.endpoint), config: {}, enabled: false, archived: false, version: 1, connection_revision: 1, credential_revision: 0, credential_configured: false, allow_private_network: false, poll_interval_seconds: Number(b.poll_interval_seconds) || 300, created_at: now(), updated_at: now() }
      patch(d => { d.connections.push(row) }); return json(row, 201)
    }
  }
  const opMatch = path.match(/^\/integration-operations\/([^/]+)(?:\/(cancel))?$/)
  if (opMatch) {
    const op = s.operations.find(v => v.id === opMatch[1]); if (!op) return error('Operation not found.', 404)
    if (opMatch[2] && method === 'POST') patch(d => { const o = d.operations.find(v => v.id === op.id)!; o.state = 'cancelled'; o.finished_at = now() })
    else if (op.state === 'queued') patch(d => { const o = d.operations.find(v => v.id === op.id)!; o.state = 'succeeded'; o.finished_at = now(); o.updated_at = now() })
    return json(s.operations.find(v => v.id === op.id))
  }
  const match = path.match(/^\/integrations\/([^/]+)(?:\/(.+))?$/)
  if (match) {
    const c = s.connections.find(v => v.id === match[1]); if (!c) return error('Integration not found.', 404)
    const action = match[2], descriptor = providers.find(p => p.provider === c.provider)!, polling = descriptor.capabilities.includes('read_runs')
    if (!action && method === 'GET') return json(c)
    if (!action && method === 'PUT') {
      try { const url = new URL(text(b.endpoint)); if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error() } catch { return error('Use a valid HTTPS endpoint.', 400) }
      if (!text(b.name) || b.version !== c.version) return error('Reload the current connection before saving changes.')
      patch(d => { const row = d.connections.find(v => v.id === c.id)!; row.name = text(b.name); row.endpoint = text(b.endpoint); row.poll_interval_seconds = Number(b.poll_interval_seconds) || 300; row.allow_private_network = b.allow_private_network === true; row.version++; row.connection_revision++; row.enabled = false; row.updated_at = now() })
      return json(s.connections.find(v => v.id === c.id))
    }
    if (action === 'inbound-webhook' && method === 'POST' && !polling) {
      if (text(b.secret) !== DEMO_SECRET) return error('Use the supplied demo credential; no real secret is required.', 400)
      if (!s.bindings.some(v => v.integration_id === c.id)) return error('Bind one Git Project first.')
      patch(d => { d.webhookReady = true }); return json({ path: `/api/v1/hooks/demo-${c.provider}`, version: 1, rotated: false })
    }
    if (action === 'credentials' && ['PUT', 'DELETE'].includes(method)) {
      if (method === 'PUT') { const secrets = b.secrets as Record<string, unknown> | undefined; if (!secrets || !descriptor.secret_fields.every(f => text(secrets[f.name]) && (f.kind !== 'password' || secrets[f.name] === DEMO_SECRET))) return error('Use the supplied example username and demo credential.', 400) }
      patch(d => { const row = d.connections.find(v => v.id === c.id)!; row.credential_configured = method === 'PUT'; row.credential_revision++; row.connection_revision++; row.version++; row.enabled = false }); return new HttpResponse(null, { status: 204 })
    }
    if (['enable', 'disable', 'archive'].includes(action) && method === 'POST') {
      if (action === 'enable' && polling && !s.operations.some(o => o.integration_id === c.id && o.type === 'test' && o.state === 'succeeded' && o.connection_revision === c.connection_revision)) return error('Test the connection successfully before enabling it.')
      if (action === 'enable' && !polling && (!s.webhookReady || !s.bindings.some(v => v.integration_id === c.id))) return error('Provision the simulated webhook and bind a Project before enabling inbound delivery.')
      patch(d => { const row = d.connections.find(v => v.id === c.id)!; row.enabled = action === 'enable'; row.archived = action === 'archive'; row.version++; row.updated_at = now() }); return json(s.connections.find(v => v.id === c.id))
    }
    if (action === 'operations') {
      if (method === 'GET') return json(s.operations.filter(v => v.integration_id === c.id).reverse())
      if (method === 'POST') {
        const type = text(b.type)
        if (!polling || !['test', 'discover', 'poll'].includes(type)) return error('This provider does not support this operation.', 422)
        if (!c.credential_configured || type === 'poll' && (!c.enabled || !s.bindings.some(v => v.integration_id === c.id))) return error('Configure credentials, test, bind and enable before polling.')
        const op: Operation = { id: crypto.randomUUID(), integration_id: c.id, connection_revision: c.connection_revision, type, state: 'queued', errors: [], created_at: now(), updated_at: now(), started_at: now(), finished_at: null, counts: { pipelines: type === 'discover' ? 1 : 0, runs: type === 'poll' ? 3 : 0, linked: type === 'poll' ? 1 : 0, unlinked: type === 'poll' ? 2 : 0, errors: 0 }, pipelines: type === 'discover' ? [{ external_key: '/job/synapse-ce/', name: 'Synapse CE', full_name: 'Synapse CE / main', kind: 'pipeline', url: 'https://ci.example/job/synapse-ce/' }] : [] }
        patch(d => { d.operations.push(op) }); return json(op, 202)
      }
    }
    if (action === 'bindings') {
      if (method === 'GET') return json(s.bindings.filter(v => v.integration_id === c.id))
      if (method === 'POST') {
        if (!text(b.project_id) || !text(b.external_key) || !polling && s.bindings.some(v => v.integration_id === c.id)) return error('Select one Project and a valid pipeline binding.', 400)
        const row = { id: crypto.randomUUID(), integration_id: c.id, project_id: text(b.project_id), external_key: text(b.external_key), external_name: text(b.external_name), version: 1, created_at: now(), updated_at: now() }
        patch(d => { d.bindings.push(row) }); return json(row, 201)
      }
    }
    if (action?.startsWith('bindings/') && method === 'DELETE') { patch(d => { d.bindings = d.bindings.filter(v => !(v.integration_id === c.id && v.id === action.split('/')[1])) }); return new HttpResponse(null, { status: 204 }) }
    if (action === 'external-runs' && method === 'GET') {
      const recorded = polling ? s.operations.some(o => o.integration_id === c.id && o.type === 'poll' && o.state === 'succeeded') : Boolean(s.eventAt)
      return json(!recorded ? [] : (polling ? ['linked', 'missing', 'ambiguous'] : ['linked']).map((correlation, i) => ({ id: `demo-run-${c.id}-${i}`, integration_id: c.id, binding_id: s.bindings.find(v => v.integration_id === c.id)?.id, provider_key: `demo-build-${42 + i}`, pipeline_key: '/job/synapse-ce/', number: String(42 + i), url: '', lifecycle: 'completed', result: i === 1 ? 'failure' : 'success', revision: i === 1 ? 'b2c3d4e' : 'a1b2c3d', branch: 'main', analysis_id: correlation === 'linked' ? 'an-001' : '', correlation, started_at: s.eventAt ?? now(), finished_at: s.eventAt ?? now(), provider_updated_at: s.eventAt ?? [...s.operations].reverse().find(o => o.integration_id === c.id && o.type === 'poll')?.finished_at ?? now() })))
    }
  }
  return error('This setup action is not available in the playground.', 422)
})]
