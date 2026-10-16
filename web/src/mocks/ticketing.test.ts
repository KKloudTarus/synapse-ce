import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { setupServer } from 'msw/node'
import { ticketingHandlers } from './ticketing'

const server = setupServer(...ticketingHandlers)
const request = (path: string, init?: RequestInit) => fetch(new URL(`/api/v1${path}`, window.location.origin), init)

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())

describe('playground Jira ticketing fixtures', () => {
  it('uses stable snake-case ticket contracts without a Jira connection', async () => {
    const providers = await request('/integration-providers')
    expect(await providers.json()).toEqual(expect.arrayContaining([expect.objectContaining({ provider: 'jira-cloud' })]))

    const preview = await request('/engagements/eng-001/findings/finding-002/ticket-preview', { method: 'POST', body: JSON.stringify({ mapping_id: 'demo-jira-mapping' }) })
    expect(await preview.json()).toEqual(expect.objectContaining({
      data_class: 'summary',
      digest: 'demo-digest-finding-002',
      fields: expect.objectContaining({ issuetype: { id: '10001' } }),
      links: [expect.objectContaining({ url: expect.stringMatching(/^https:\/\/console\.demo\.invalid\//) })],
      security_waived: false,
    }))

    const created = await request('/ticket-mappings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ integration_id: 'demo-jira-cloud', scope: 'engagement', scope_id: 'eng-001', project_key: 'SEC', issue_type: '10001', data_class: 'summary' }) })
    expect(await created.json()).toEqual(expect.objectContaining({ id: 'demo-jira-mapping-created', integration_id: 'demo-jira-cloud', project_key: 'SEC' }))
  })

  it('returns synthetic ticket states for engagement findings and read-only transitions for an existing issue', async () => {
    const ticketState = await request('/engagements/eng-001/findings/finding-002/tickets')
    expect(await ticketState.json()).toEqual(expect.objectContaining({
      intents: [expect.objectContaining({ finding_id: 'finding-002', state: 'in_flight' })],
    }))

    const metadata = await request('/integrations/demo-jira-cloud/jira-metadata?project_key=SEC&issue_type=10001&issue_key=SEC-105')
    expect(await metadata.json()).toEqual(expect.objectContaining({
      transitions: expect.arrayContaining([expect.objectContaining({ id: '21', name: 'Start progress' })]),
    }))
  })
})
