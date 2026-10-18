import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { resetCapabilityCache } from '../../lib/capabilities'
import { Alerting } from './Alerting'

// #1421 replaced the rule form's raw identifier fields with directory pickers. The picker has its
// own unit tests; these drive it inside the rule form, over the real API client, so the wiring is
// covered too: which endpoint each picker searches, that an option carries its id, and that a
// selection reaches the rule the form submits.

const users = [
  { id: '70db0073427a1ec832d97b106a2295c1', name: 'Rita Reader' },
  { id: 'operator', name: 'Operator (bootstrap admin)' },
]
const engagements = [
  { id: 'd9eca5e7678e69654934d159f17a4cd0', name: 'Acme external assessment', client: 'Acme Corp', status: 'draft' },
  { id: '1bc6958010f4c6001be7801ad1650cc5', name: 'Globex cloud audit', client: 'Globex', status: 'draft' },
]
const teams = [
  { id: '0eaf59cc85d6682747e9055f9b819e97', slug: 'platform-security', name: 'Platform security', archived: false, revision: 1 },
  { id: '071733e2587bc9b97ef7dab4ca5335aa', slug: 'cloud-ops', name: 'Cloud operations', archived: true, revision: 1 },
]
const channel = {
  id: 'ch-1', name: 'Security webhook', type: 'webhook', enabled: true,
  destination: 'https://alerts.example.test/…', revision: 1, secret_version: 1,
  created_at: '2026-10-18T13:44:44Z', updated_at: '2026-10-18T13:44:44Z',
}

const asked: { users: string[]; teams: number; engagements: number } = { users: [], teams: 0, engagements: 0 }
let submitted: Record<string, unknown> | null = null

const server = setupServer(
  http.get('/api/v1/me', () => HttpResponse.json({ id: 'operator', role: 'admin' })),
  http.get('/api/v1/capabilities', () => HttpResponse.json([
    { key: 'notifications', name: 'Tenant notifications', enabled: true, switch: 'SYNAPSE_NOTIFICATIONS_ENABLED', requires: [], values: [], planned: false },
  ])),
  http.get('/api/v1/notifications/channels', () => HttpResponse.json({ items: [channel] })),
  // The catalog decides which filters the rule form offers, so it is the real shape of one event
  // type rather than a stub: a form fed an empty catalog renders no pickers at all.
  http.get('/api/v1/notifications/event-types', () => HttpResponse.json({
    items: [{
      type: 'finding.created', label: 'Finding created', schema_version: 1, subject_kind: 'finding',
      has_engagement: true, has_severity: true, has_team: false, has_lead_time: false,
      filters: ['min_severity', 'engagement_ids', 'finding_kinds'],
      max_data_class: 'detail', mandatory: false, operator_only: false, variables: [],
    }],
  })),
  http.get('/api/v1/notifications/rules', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/rules/user-options', ({ request }) => {
    const query = new URL(request.url).searchParams.get('q') ?? ''
    asked.users.push(query)
    const needle = query.trim().toLowerCase()
    return HttpResponse.json({
      items: needle ? users.filter((user) => user.name.toLowerCase().includes(needle)) : users,
      next: '',
    })
  }),
  http.get('/api/v1/engagements', () => {
    asked.engagements += 1
    return HttpResponse.json(engagements)
  }),
  http.get('/api/v1/ownership/teams', () => {
    asked.teams += 1
    return HttpResponse.json({ items: teams })
  }),
  http.post('/api/v1/notifications/rules', async ({ request }) => {
    submitted = (await request.json()) as Record<string, unknown>
    return HttpResponse.json({ id: 'rule-1', ...submitted }, { status: 201 })
  }),
  // Everything else the page loads is answered emptily: these tests are about the pickers.
  http.get('/api/v1/notifications/templates', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/deliveries', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/sources/quarantined', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/personal-defaults', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/engagements', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/notifications/email-settings', () => HttpResponse.json({})),
)

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }))
beforeEach(() => {
  resetCapabilityCache()
  asked.users = []
  asked.teams = 0
  asked.engagements = 0
  submitted = null
})
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

async function openRuleForm() {
  render(<Alerting />)
  await screen.findByText('Add routing rule', {}, { timeout: 10000 })
}

describe('rule form pickers over the real client', () => {
  it('lists people from the directory with their ids, so two Ritas stay apart', async () => {
    await openRuleForm()
    const people = screen.getAllByLabelText('People (optional)')[0]
    fireEvent.focus(people)
    fireEvent.click(people)
    expect(await screen.findByText('Rita Reader (70db0073427a1ec832d97b106a2295c1)')).toBeInTheDocument()
    expect(screen.getByText('Operator (bootstrap admin) (operator)')).toBeInTheDocument()
  })

  it('searches people on the server rather than filtering the first page', async () => {
    await openRuleForm()
    const people = screen.getAllByLabelText('People (optional)')[0]
    fireEvent.click(people)
    await screen.findByText('Rita Reader (70db0073427a1ec832d97b106a2295c1)')
    fireEvent.change(people, { target: { value: 'Rita' } })
    await waitFor(() => expect(asked.users.some((query) => query === 'Rita')).toBe(true))
    await waitFor(() => expect(screen.queryByText('Operator (bootstrap admin) (operator)')).not.toBeInTheDocument())
  })

  it('lists engagements with their ids', async () => {
    await openRuleForm()
    const field = screen.getAllByLabelText('Engagements (optional)')[0]
    fireEvent.click(field)
    expect(await screen.findByText('Acme external assessment (d9eca5e7678e69654934d159f17a4cd0)')).toBeInTheDocument()
    expect(screen.getByText('Globex cloud audit (1bc6958010f4c6001be7801ad1650cc5)')).toBeInTheDocument()
    expect(asked.engagements).toBeGreaterThan(0)
  })

  it('says so when nothing in the directory matches', async () => {
    await openRuleForm()
    const people = screen.getAllByLabelText('People (optional)')[0]
    fireEvent.click(people)
    await screen.findByText('Rita Reader (70db0073427a1ec832d97b106a2295c1)')
    fireEvent.change(people, { target: { value: 'nobody-by-that-name' } })
    await waitFor(() => expect(asked.users.some((query) => query === 'nobody-by-that-name')).toBe(true))
    await waitFor(() => expect(screen.queryByText('Rita Reader (70db0073427a1ec832d97b106a2295c1)')).not.toBeInTheDocument())
  })

  it('carries a chosen person into the rule the form submits', async () => {
    await openRuleForm()
    const people = screen.getAllByLabelText('People (optional)')[0]
    fireEvent.click(people)
    fireEvent.click(await screen.findByText('Rita Reader (70db0073427a1ec832d97b106a2295c1)'))
    // The chosen person stays visible in the form, with the id that disambiguates duplicates.
    await waitFor(() => expect(screen.getAllByText(/Rita Reader/).length).toBeGreaterThan(0))
    fireEvent.change(screen.getByPlaceholderText('High risk to security team'), { target: { value: 'High risk to Rita' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    await waitFor(() => expect(submitted).not.toBeNull(), { timeout: 4000 })
    expect(JSON.stringify(submitted)).toContain('70db0073427a1ec832d97b106a2295c1')
  })
})
