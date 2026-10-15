import { http, HttpResponse } from 'msw'

const now = '2026-10-14T09:00:00.000Z'
const integration = { id: 'demo-jira-cloud', provider: 'jira-cloud', name: 'Demo Jira Cloud', endpoint: 'https://jira.demo.invalid', config: {}, allow_private_network: false, poll_interval_seconds: 300, enabled: true, archived: false, version: 1, connection_revision: 1, credential_revision: 1, credential_configured: true, created_at: now, updated_at: now }
const mapping = { id: 'demo-jira-mapping', integration_id: integration.id, scope: 'engagement', scope_id: 'eng-001', project_key: 'SEC', issue_type: '10001', component: '42', labels: ['synapse-demo'], priority_map: { critical: '1', high: '2' }, security_level: 'security-1', waiver_reason: '', data_class: 'summary', locale: 'en', summary_template: '', description_template: '', field_values: { customfield_101: 'team-blue' }, transition_id: '', version: 1 }
const links = new Map<string, Array<Record<string, string>>>()
const intentByFinding: Record<string, Record<string, unknown>[]> = {
  'finding-001': [{ id: 'demo-intent-pending', finding_id: 'finding-001', mapping_id: mapping.id, state: 'pending', version: 1, attempts: 0, error_code: '', created_at: now }],
  'finding-002': [{ id: 'demo-intent-in-flight', finding_id: 'finding-002', mapping_id: mapping.id, state: 'in_flight', version: 2, attempts: 1, error_code: '', created_at: now }],
  'finding-003': [{ id: 'demo-intent-failed', finding_id: 'finding-003', mapping_id: mapping.id, state: 'failed', version: 2, attempts: 1, error_code: 'http_400', created_at: now }],
  'finding-004': [{ id: 'demo-intent-uncertain', finding_id: 'finding-004', mapping_id: mapping.id, state: 'uncertain', version: 3, attempts: 1, error_code: 'zero_matches', created_at: now }],
  'finding-005': [{ id: 'demo-intent-done', finding_id: 'finding-005', mapping_id: mapping.id, state: 'done', version: 2, attempts: 1, error_code: '', remote_id: 'SEC-105', remote_url: 'https://jira.demo.invalid/browse/SEC-105', created_at: now }],
}

const metadata = { projects: [{ id: 'SEC', name: 'Security Demo' }], issue_types: [{ id: '10001', name: 'Bug' }], priorities: [{ id: '1', name: 'Highest' }, { id: '2', name: 'High' }], security_levels: [{ id: 'security-1', name: 'Internal' }], components: [{ id: '42', name: 'Platform' }], transitions: [], fields: [{ id: 'customfield_101', name: 'Owning team', required: false, values: [{ id: 'team-blue', name: 'Blue team' }], type: 'option', item_type: '', has_default: false }] }
const existingIssueMetadata = { ...metadata, transitions: [{ id: '21', name: 'Start progress' }, { id: '31', name: 'Resolve' }] }

const findingURL = (finding: string) => `https://console.demo.invalid/engagements/eng-001/findings/${encodeURIComponent(finding)}`
const newIntent = (finding: string) => ({ id: `demo-intent-${finding}`, finding_id: finding, mapping_id: mapping.id, state: 'pending', version: 1, attempts: 0, error_code: '', created_at: now })

/** Explicit playground-only Jira responses. They are synthetic fixtures and never contact Jira. */
export const ticketingHandlers = [
  http.get('/api/v1/integration-providers', () => HttpResponse.json([{ provider: 'jira-cloud', name: 'Demo Jira Cloud', description: 'Synthetic playground ticket destination; no Jira connection is used.', self_hosted: false, capabilities: ['test_connection'], config_fields: [], secret_fields: [{ name: 'email', label: 'Demo account email', description: 'Playground-only placeholder.', kind: 'text', required: true }, { name: 'api_token', label: 'Demo API token', description: 'Playground-only placeholder.', kind: 'password', required: true }] }, { provider: 'jira-dc', name: 'Demo Jira Data Center', description: 'Synthetic playground ticket destination; no Jira connection is used.', self_hosted: true, capabilities: ['test_connection'], config_fields: [], secret_fields: [{ name: 'pat', label: 'Demo personal access token', description: 'Playground-only placeholder.', kind: 'password', required: true }] }])),
  http.get('/api/v1/integrations', () => HttpResponse.json([integration])),
  http.get('/api/v1/ticket-mappings', ({ request }) => { const url = new URL(request.url); return HttpResponse.json(url.searchParams.get('scope') === 'engagement' && url.searchParams.get('scope_id') === 'eng-001' ? [mapping] : []) }),
  http.post('/api/v1/ticket-mappings', async ({ request }) => {
    const input = await request.json() as Record<string, unknown>
    return HttpResponse.json({ ...input, id: 'demo-jira-mapping-created', version: 1 }, { status: 201 })
  }),
  http.put('/api/v1/ticket-mappings/:mappingId', async ({ params, request }) => {
    const input = await request.json() as Record<string, unknown>
    return HttpResponse.json({ ...input, id: params.mappingId, version: Number(input.version ?? 1) + 1 })
  }),
  http.delete('/api/v1/ticket-mappings/:mappingId', () => new HttpResponse(null, { status: 204 })),
  http.get('/api/v1/integrations/:id/jira-metadata', ({ request }) => {
    const issueKey = new URL(request.url).searchParams.get('issue_key')
    return HttpResponse.json(issueKey ? existingIssueMetadata : metadata)
  }),
  http.post('/api/v1/integrations/:id/operations', ({ params }) => HttpResponse.json({ id: `demo-operation-${params.id}`, integration_id: params.id, type: 'test', state: 'queued', checkpoint: 'playground', counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [], job_id: '', actor: 'demo-admin', started_at: null, finished_at: null, created_at: now, updated_at: now }, { status: 202 })),
  http.get('/api/v1/engagements/:engagementId/findings/:findingId/tickets', ({ params }) => { const finding = String(params.findingId); return HttpResponse.json({ links: links.get(finding) ?? [], intents: intentByFinding[finding] ?? [], mappings: String(params.engagementId) === 'eng-001' ? [mapping] : [] }) }),
  http.post('/api/v1/engagements/:engagementId/findings/:findingId/ticket-preview', ({ params }) => { const finding = String(params.findingId); return HttpResponse.json({ fields: { project: { key: 'SEC' }, issuetype: { id: '10001' }, components: [{ id: '42' }], priority: { id: '1' }, security: { id: 'security-1' }, labels: ['synapse-demo'], customfield_101: { id: 'team-blue' } }, summary: `Demo ticket for ${finding}`, description: 'This is a **synthetic playground preview**. No Jira ticket will be created.', links: [{ label: 'Open finding in demo console', url: findingURL(finding) }], security_waived: false, marker_required: true, marker_format: 'synapse-intent-{intent_id}', data_class: 'summary', digest: `demo-digest-${finding}`, mapping_version: 1 }) }),
  http.post('/api/v1/engagements/:engagementId/findings/:findingId/ticket-submit', ({ params }) => { const finding = String(params.findingId); const intent = newIntent(finding); intentByFinding[finding] = [intent, ...(intentByFinding[finding] ?? [])]; return HttpResponse.json(intent, { status: 202 }) }),
  http.post('/api/v1/engagements/:engagementId/findings/:findingId/tickets', async ({ params, request }) => { const body = await request.json() as { url?: string }; const finding = String(params.findingId); const link = { id: `demo-link-${finding}-${(links.get(finding)?.length ?? 0) + 1}`, external_url: body.url ?? '', external_id: 'DEMO-1', integration_id: integration.id, created_at: now }; links.set(finding, [link, ...(links.get(finding) ?? [])]); return HttpResponse.json(link, { status: 201 }) }),
  http.delete('/api/v1/engagements/:engagementId/findings/:findingId/tickets/:linkId', ({ params }) => { const finding = String(params.findingId); links.set(finding, (links.get(finding) ?? []).filter((link) => link.id !== params.linkId)); return new HttpResponse(null, { status: 204 }) }),
  http.post('/api/v1/engagements/:engagementId/tickets/bulk', async ({ request }) => { const body = await request.json() as { items?: Array<{ finding_id?: string }> }; return HttpResponse.json((body.items ?? []).map((item) => { const intent = newIntent(item.finding_id ?? 'unknown'); intentByFinding[item.finding_id ?? 'unknown'] = [intent]; return { finding_id: item.finding_id ?? '', intent } }), { status: 202 }) }),
  http.post('/api/v1/ticket-intents/:intentId/reconcile', ({ params }) => HttpResponse.json({ id: params.intentId, state: 'uncertain', error_code: 'zero_matches', version: 4, attempts: 1, created_at: now })),
  http.post('/api/v1/ticket-intents/:intentId/retry', ({ params }) => HttpResponse.json({ id: params.intentId, state: 'pending', error_code: '', version: 5, attempts: 2, created_at: now }, { status: 202 })),
]
