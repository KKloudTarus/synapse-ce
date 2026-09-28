import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationEventSpec, NotificationRuleFilter } from '../../lib/api'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', async (original) => ({
  ...(await original<typeof import('../../lib/api')>()),
  api: {
    me: vi.fn(),
    testAlert: vi.fn(),
    listNotificationChannels: vi.fn(),
    listNotificationRules: vi.fn(),
    listNotificationEventTypes: vi.fn(),
    notificationDeliveryPage: vi.fn(),
    listNotificationAttempts: vi.fn(),
    createNotificationChannel: vi.fn(),
    updateNotificationChannel: vi.fn(),
    createNotificationRule: vi.fn(),
    updateNotificationRule: vi.fn(),
    testNotificationChannel: vi.fn(),
    listEngagements: vi.fn(),
    ownershipTeams: vi.fn(),
  },
}))
const channel = {
  id: 'c',
  name: 'Security hook',
  type: 'webhook' as const,
  enabled: true,
  destination: 'https://example.com/…',
  revision: 3,
  secret_version: 1,
  created_at: '',
  updated_at: '',
}
function eventSpec(
  type: string,
  label: string,
  filters: NotificationRuleFilter[],
  operator_only = false,
): NotificationEventSpec {
  return {
    type, label, filters, operator_only,
    schema_version: 1, subject_kind: 'subject', max_data_class: 'summary', mandatory: false,
    has_engagement: filters.includes('engagement_ids'), has_severity: filters.includes('min_severity'),
    has_team: filters.includes('team_ids'), has_lead_time: filters.includes('lead_time_seconds'),
    variables: [],
  }
}
// Mirrors the server catalog so the form is exercised the way GET /notifications/event-types drives it.
const catalog = [
  eventSpec('finding.ownership_changed', 'Finding ownership changed', ['engagement_ids', 'team_ids']),
  eventSpec('fleet.agent.offline', 'Fleet agent offline', []),
  eventSpec('incident.created', 'Incident created', ['min_severity', 'engagement_ids']),
  eventSpec('notification.test', 'Channel test', [], true),
  eventSpec('sla.approaching_deadline', 'SLA approaching deadline', ['engagement_ids', 'lead_time_seconds']),
  eventSpec('vulnerability_action.created', 'Vulnerability risk action', ['min_severity', 'action_types', 'engagement_ids']),
]

describe('notification settings', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: vi.fn(),
    })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.listNotificationRules).mockResolvedValue([])
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue(catalog)
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({
      items: [
        { id: 'pay', slug: 'pay', name: 'Payments', archived: false, revision: 1, created_at: '', updated_at: '' },
        { id: 'ops', slug: 'ops', name: 'Operations', archived: false, revision: 1, created_at: '', updated_at: '' },
      ],
    })
  })
  it('creates a signed webhook with write-only fields', async () => {
    vi.mocked(api.createNotificationChannel).mockResolvedValue(channel)
    render(<Alerting />)
    await screen.findByRole('button', { name: 'Edit channel' })
    fireEvent.change(screen.getAllByLabelText('Name')[0], {
      target: { value: 'New hook' },
    })
    fireEvent.change(screen.getByLabelText('Webhook URL'), {
      target: { value: 'https://example.com/secret' },
    })
    fireEvent.change(screen.getByLabelText(/HMAC secret/), {
      target: { value: '1234567890abcdef' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add channel' }))
    await waitFor(() =>
      expect(api.createNotificationChannel).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'webhook',
          name: 'New hook',
          url: 'https://example.com/secret',
          secret: '1234567890abcdef',
        }),
      ),
    )
    await waitFor(() =>
      expect(screen.getByLabelText(/HMAC secret/)).toHaveValue(''),
    )
  })
  it('edits metadata without prefilling or replacing secrets', async () => {
    vi.mocked(api.updateNotificationChannel).mockResolvedValue(channel)
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit channel' }))
    expect(screen.getByLabelText('Webhook URL')).toHaveValue('')
    expect(screen.getByLabelText(/HMAC secret/)).toHaveValue('')
    fireEvent.change(screen.getAllByLabelText('Name')[0], {
      target: { value: 'Renamed' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save channel' }))
    await waitFor(() =>
      expect(api.updateNotificationChannel).toHaveBeenCalledWith(
        'c',
        expect.objectContaining({
          name: 'Renamed',
          revision: 3,
          url: '',
          secret: '',
        }),
      ),
    )
  })
  it('shows pending tests and attempt history without claiming acknowledgement', async () => {
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({
      items: [
        {
          id: 'd',
          channel_id: 'c',
          channel_type: 'webhook',
          event_id: 'e',
          state: 'retrying',
          attempts: 1,
          created_at: '2026-09-10T00:00:00Z',
          updated_at: '',
          matched_rule_ids: [],
        },
      ],
    })
    vi.mocked(api.listNotificationAttempts).mockResolvedValue([
      {
        id: 'a',
        delivery_id: 'd',
        number: 1,
        started_at: '2026-09-10T00:00:00Z',
        outcome: 'retrying',
        response_code: 503,
        error_code: 'http_503',
      },
    ])
    render(<Alerting />)
    fireEvent.click(
      await screen.findByRole('button', { name: 'View 1 attempts' }),
    )
    expect(await screen.findByText(/http_503/)).toBeInTheDocument()
    expect(screen.queryByText('Acknowledged')).not.toBeInTheDocument()
  })
  it('does not call administrator APIs for a member', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    render(<Alerting />)
    expect(
      await screen.findByText('Administrator access required'),
    ).toBeInTheDocument()
    expect(api.listNotificationChannels).not.toHaveBeenCalled()
    expect(api.notificationDeliveryPage).not.toHaveBeenCalled()
  })
  it('requires explicit scope before subscribing to ownership changes', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Finding ownership changed' }))
    fireEvent.change(screen.getAllByLabelText('Name')[1], {
      target: { value: 'Ownership alerts' },
    })
    expect(screen.getByLabelText('All teams in this tenant')).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    expect(await screen.findByText('Choose at least one team or select all teams.')).toBeInTheDocument()
    expect(api.createNotificationRule).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByRole('button', { name: 'Payments (pay)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Operations (ops)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    await waitFor(() => expect(api.createNotificationRule).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: 'finding.ownership_changed', team_ids: ['pay', 'ops'], all_teams: false }),
    ))
  })
  it('clears the team filter when an administrator explicitly chooses all teams', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Finding ownership changed' }))
    fireEvent.change(screen.getAllByLabelText('Name')[1], {
      target: { value: 'Tenant ownership alerts' },
    })
    fireEvent.click(await screen.findByRole('button', { name: 'Payments (pay)' }))
    fireEvent.click(screen.getByLabelText('All teams in this tenant'))
    expect(screen.getByRole('searchbox', { name: 'Team IDs' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    await waitFor(() => expect(api.createNotificationRule).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: 'finding.ownership_changed', all_teams: true, team_ids: undefined }),
    ))
  })
  it('preserves team scope and revision when editing an ownership rule', async () => {
    vi.mocked(api.listNotificationRules).mockResolvedValue([{
      id: 'rule', name: 'Scoped ownership', enabled: true,
      event_type: 'finding.ownership_changed', channel_ids: ['c'],
      team_ids: ['pay', 'ops'], all_teams: false, revision: 4,
      created_at: '', updated_at: '',
    }])
    render(<Alerting />)
    expect(await screen.findByText('Teams: pay, ops')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Edit rule' }))
    expect(await screen.findByRole('button', { name: 'Remove Payments (pay)' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove Operations (ops)' })).toBeInTheDocument()
    expect(screen.getByLabelText('All teams in this tenant')).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule',
      expect.objectContaining({ revision: 4, team_ids: ['pay', 'ops'], all_teams: false }),
    ))
  })
  it('offers rule events from the catalog and hides operator-only types', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Event' }))
    const options = (await screen.findAllByRole('option')).map((o) => o.textContent)
    expect(options).toEqual([
      'Finding ownership changed',
      'Fleet agent offline',
      'Incident created',
      'SLA approaching deadline',
      'Vulnerability risk action',
    ])
  })
  it('renders only the filters the selected event type declares', async () => {
    render(<Alerting />)
    // The default event accepts severity, action type and engagement filters.
    expect(await screen.findByLabelText('Action types (optional)')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Minimum severity' })).toBeInTheDocument()
    expect(screen.getByRole('searchbox', { name: 'Engagements (optional)' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Fleet agent offline' }))
    expect(screen.queryByLabelText('Action types (optional)')).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: 'Minimum severity' })).not.toBeInTheDocument()
    expect(screen.queryByRole('searchbox', { name: 'Engagements (optional)' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Lead time (hours)')).not.toBeInTheDocument()

    fireEvent.change(screen.getAllByLabelText('Name')[1], { target: { value: 'Agents down' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    await waitFor(() => expect(api.createNotificationRule).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'fleet.agent.offline',
        engagement_ids: [],
        min_severity: undefined,
        action_types: undefined,
        lead_time_seconds: undefined,
      }),
    ))
  })
  it('shows the lead time only for an event that declares it', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'SLA approaching deadline' }))
    expect(screen.getByLabelText('Lead time (hours)')).toHaveValue(24)
    expect(screen.queryByRole('combobox', { name: 'Minimum severity' })).not.toBeInTheDocument()
  })
  it('labels rules and history filters from the catalog', async () => {
    vi.mocked(api.listNotificationRules).mockResolvedValue([{
      id: 'rule', name: 'Incidents', enabled: true, event_type: 'incident.created',
      channel_ids: ['c'], revision: 1, created_at: '', updated_at: '',
    }])
    render(<Alerting />)
    expect(await screen.findByText(/Incident created →/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('combobox', { name: 'Event filter' }))
    expect(await screen.findByRole('option', { name: 'Channel test' })).toBeInTheDocument()
  })
  it('shows an error instead of the rule form when the catalog cannot load', async () => {
    vi.mocked(api.listNotificationEventTypes).mockRejectedValue(new Error('event catalog unavailable'))
    render(<Alerting />)
    expect(await screen.findByText('event catalog unavailable')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add rule' })).not.toBeInTheDocument()
  })
})
