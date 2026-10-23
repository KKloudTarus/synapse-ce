import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { TicketsPanel } from './TicketsPanel'

const mapping = { id: 'mapping-1', integration_id: 'jira-1', scope: 'engagement', scope_id: 'eng-1', project_key: 'SEC', issue_type: 'Bug', component: '', labels: [], priority_map: {}, security_level: 'security-1', waiver_reason: '', data_class: 'summary', locale: 'en', summary_template: '', description_template: '', field_values: {}, transition_id: '', version: 1 }
let linked = false

const server = setupServer(
  http.get('/api/v1/integrations', () => HttpResponse.json([{ id: 'jira-1', provider: 'jira-cloud', name: 'Security Jira', endpoint: 'https://team.atlassian.net' }])),
  http.get('/api/v1/integration-providers', () => HttpResponse.json([{ provider: 'jira-cloud', name: 'Jira Cloud' }])),
  http.get('/api/v1/me', () => HttpResponse.json({ id: 'operator-1', role: 'admin' })),
  http.get('/api/v1/engagements/:engagementId/findings/:findingId/ticket-observations', () => HttpResponse.json({ observations: [], proposals: [], comments: [] })),
  http.get('/api/v1/engagements/:engagementId/findings/:findingId/tickets', () => HttpResponse.json({
    links: linked ? [{ id: 'link-1', external_url: 'https://team.atlassian.net/browse/SEC-1', external_id: 'SEC-1', integration_id: 'jira-1', created_at: '' }] : [],
    intents: [{ id: 'intent-uncertain', state: 'uncertain', error_code: 'zero_matches', version: 1, created_at: '' }],
    mappings: [mapping],
  })),
  http.post('/api/v1/engagements/:engagementId/findings/:findingId/ticket-preview', () => HttpResponse.json({ provider: 'jira-cloud', endpoint: 'https://team.atlassian.net', fields: { project: { key: 'SEC' }, issuetype: { id: '10001' }, security: { id: 'security-1' }, labels: ['security'] }, summary: 'SEC: SQL injection', description: 'Rendered preview', links: [{ label: 'Open finding', url: 'https://console.example/findings/finding-1' }], security_waived: true, marker_required: true, marker_format: 'synapse-intent-{intent_id}', data_class: 'summary', digest: 'digest-1', mapping_version: 1 })),
  http.post('/api/v1/engagements/:engagementId/findings/:findingId/ticket-submit', () => { linked = true; return HttpResponse.json({ id: 'intent-new', state: 'queued', error_code: '', version: 1, created_at: '' }, { status: 202 }) }),
  http.post('/api/v1/ticket-intents/:intentId/reconcile', () => { linked = true; return HttpResponse.json({ id: 'intent-uncertain', state: 'done', error_code: '', version: 2, created_at: '' }) }),
)

beforeAll(() => server.listen({ onUnhandledFrame: 'error' }))
afterEach(() => { linked = false; server.resetHandlers() })
afterAll(() => server.close())

describe('TicketsPanel with the real ticketing client', () => {
  it('previews, submits, reloads a linked ticket, and reconciles an uncertain request', async () => {
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Preview ticket' }))
    expect(await screen.findByText('SEC: SQL injection')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open finding' })).toHaveAttribute('href', 'https://console.example/findings/finding-1')
    expect(screen.getByText(/recorded administrator waiver/)).toBeInTheDocument()
    expect(screen.getByText('security')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Submit ticket' }))
    expect(await screen.findByText(/Ticket request recorded/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Refresh tickets' }))
    expect(await screen.findByRole('link', { name: /SEC-1/ })).toHaveAttribute('href', 'https://team.atlassian.net/browse/SEC-1')

    fireEvent.click(screen.getByRole('button', { name: 'Reconcile' }))
    await waitFor(() => expect(screen.getByText(/Reconciliation completed/)).toBeInTheDocument())
    expect(await screen.findByRole('link', { name: /SEC-1/ })).toHaveAttribute('href', 'https://team.atlassian.net/browse/SEC-1')
  })

  it('surfaces a provider preview rejection without issuing a ticket request', async () => {
    server.use(http.post('/api/v1/engagements/:engagementId/findings/:findingId/ticket-preview', () => HttpResponse.json({ error: 'Jira metadata is unavailable' }, { status: 422 })))
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Preview ticket' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Jira metadata is unavailable')
    expect(screen.queryByRole('button', { name: 'Submit ticket' })).not.toBeInTheDocument()
  })
})
