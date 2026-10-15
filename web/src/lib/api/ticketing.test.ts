import { afterEach, describe, expect, it, vi } from 'vitest'
import { ticketingApi } from './ticketing'

afterEach(() => vi.unstubAllGlobals())

describe('ticketing API contract', () => {
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
    const current = { id: 'map-1', integrationId: 'jira-1', scope: 'engagement' as const, scopeId: 'eng-1', projectKey: 'SEC', issueType: 'Bug', component: '', labels: ['security'], priorityMap: { high: '1' }, securityLevel: '', waiverReason: 'approved', dataClass: 'summary' as const, locale: 'vi' as const, summaryTemplate: '', descriptionTemplate: '', fieldValues: { custom_1: 'value' }, transitionId: '31', version: 2 }
    await ticketingApi.updateTicketMapping(current, current)
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/ticket-mappings/map-1', expect.objectContaining({ method: 'PUT' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({ integration_id: 'jira-1', scope_id: 'eng-1', project_key: 'SEC', issue_type: 'Bug', priority_map: { high: '1' }, waiver_reason: 'approved', data_class: 'summary', summary_template: '', description_template: '', transition_id: '31', version: 2 })
  })

  it('does not turn a bulk request into an outbound write until all preview digests are supplied', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await ticketingApi.bulkTickets('eng 1', 'map 1', [{ findingId: 'f 1', previewDigest: 'digest', requestKey: 'request' }])
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/eng%201/tickets/bulk', expect.objectContaining({ method: 'POST' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ mapping_id: 'map 1', items: [{ finding_id: 'f 1', preview_digest: 'digest', request_key: 'request' }] })
  })
})
