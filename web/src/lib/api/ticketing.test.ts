import { afterEach, describe, expect, it, vi } from 'vitest'
import { ticketingApi } from './ticketing'

afterEach(() => vi.unstubAllGlobals())

describe('ticketing API contract', () => {
  it('reads proposal context and external comments without interpreting content', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ observations: [{ remote_id: 'SEC-1', status_category: 'done', deleted_or_unreadable: false }], proposals: [{ id: 'proposal', remote_id: 'SEC-1', state: 'pending', resolution_context: 'Fixed' }], comments: [{ id: 'comment', remote_id: 'SEC-1', origin: 'external', body: '@admin <b>Đã kiểm tra</b>' }] }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const view = await ticketingApi.ticketObservations('eng 1', 'finding 1')
    expect(view.proposals[0]).toMatchObject({ remoteId: 'SEC-1', resolutionContext: 'Fixed', state: 'pending' })
    expect(view.comments[0]).toMatchObject({ origin: 'external', body: '@admin <b>Đã kiểm tra</b>' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/eng%201/findings/finding%201/ticket-observations', expect.anything())
  })
  it('retains the resolved DC reporter while preserving required metadata flags', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ resolved_reporter: 'sandbox-admin', fields: [{ id: 'reporter', name: 'Reporter', required: true, schema: {}, type: 'user', has_default: false, values: [] }] }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const metadata = await ticketingApi.jiraMetadata('dc-1', 'SEC', '10003')
    expect(metadata.resolvedReporter).toBe('sandbox-admin')
    expect(metadata.fields[0]).toMatchObject({ id: 'reporter', required: true, type: 'user', hasDefault: false })
  })

  it('sends the mapping contract in snake case with its optimistic version', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'map-1', integration_id: 'jira-1', scope: 'engagement', scope_id: 'eng-1', project_key: 'SEC', issue_type: 'Bug', version: 3 }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const current = { id: 'map-1', integrationId: 'jira-1', scope: 'engagement' as const, scopeId: 'eng-1', projectKey: 'SEC', issueType: 'Bug', component: '', labels: ['security'], priorityMap: { high: '1' }, securityLevel: '', waiverReason: 'approved', dataClass: 'summary' as const, locale: 'vi' as const, summaryTemplate: '', descriptionTemplate: '', fieldValues: { custom_1: 'value' }, transitionId: '31', statusTransitions: { remediated: '31', reopen: '41' }, groupingMode: 'finding' as const, autoPushEnabled: true, autoPushMinSeverity: 'high' as const, version: 2 }
    await ticketingApi.updateTicketMapping(current, current)
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/ticket-mappings/map-1', expect.objectContaining({ method: 'PUT' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({ integration_id: 'jira-1', scope_id: 'eng-1', project_key: 'SEC', issue_type: 'Bug', priority_map: { high: '1' }, waiver_reason: 'approved', data_class: 'summary', summary_template: '', description_template: '', transition_id: '31', status_transitions: { remediated: '31', reopen: '41' }, grouping_mode: 'finding', auto_push_enabled: true, auto_push_min_severity: 'high', version: 2 })
  })

  it('defaults old mappings to manual creation without enabling automatic writes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'legacy-map' }]), { status: 200, headers: { 'content-type': 'application/json' } })))
    const [mapping] = await ticketingApi.listTicketMappings('engagement', 'eng-1')
    expect(mapping).toMatchObject({ statusTransitions: {}, groupingMode: 'finding' as const, autoPushEnabled: false, autoPushMinSeverity: 'high' })
  })

  it('does not turn a bulk request into an outbound write until all preview digests are supplied', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await ticketingApi.bulkTickets('eng 1', 'map 1', [{ findingId: 'f 1', previewDigest: 'digest', requestKey: 'request' }])
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/eng%201/tickets/bulk', expect.objectContaining({ method: 'POST' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ mapping_id: 'map 1', items: [{ finding_id: 'f 1', preview_digest: 'digest', request_key: 'request' }] })
  })

  it('keeps Project source-finding ticket preview and submit paths Project-scoped', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ links: [], intents: [], mappings: [] }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ digest: 'preview', data_class: 'summary' }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'intent', state: 'queued', version: 1 }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await ticketingApi.projectSourceFindingTickets('payments source', 'finding 1')
    await ticketingApi.previewProjectSourceFindingTicket('payments source', 'finding 1', 'mapping 1')
    await ticketingApi.submitProjectSourceFindingTicket('payments source', 'finding 1', 'mapping 1', 'preview', 'request')

    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      '/api/v1/projects/payments%20source/source-findings/finding%201/tickets',
      '/api/v1/projects/payments%20source/source-findings/finding%201/ticket-preview',
      '/api/v1/projects/payments%20source/source-findings/finding%201/ticket-submit',
    ])
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ mapping_id: 'mapping 1', preview_digest: 'preview', request_key: 'request' })
  })
})
