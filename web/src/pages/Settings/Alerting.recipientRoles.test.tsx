import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel, NotificationEventSpec, NotificationRule, NotificationRuleFilter } from '../../lib/api'
import { loadCapabilities, useCapabilities } from '../../lib/capabilities'
import { Alerting } from './Alerting'

// #1415: a rule can also notify people by their relation to the event.

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    testAlert: vi.fn(),
    listNotificationEventTypes: vi.fn(),
    listNotificationChannels: vi.fn(),
    listNotificationRules: vi.fn(),
    updateNotificationRule: vi.fn(),
    createNotificationRule: vi.fn(),
    listEngagements: vi.fn(),
    ownershipTeams: vi.fn(),
    notificationDeliveryPage: vi.fn(),
  },
  AlertNotEnabledError: class AlertNotEnabledError extends Error {},
  ApiError: class ApiError extends Error {},
}))

vi.mock('../../lib/capabilities', async (original) => ({
  ...(await original<typeof import('../../lib/capabilities')>()),
  loadCapabilities: vi.fn(),
  useCapabilities: vi.fn(),
}))

function eventSpec(type: string, label: string, filters: NotificationRuleFilter[]): NotificationEventSpec {
  return {
    type, label, filters, operator_only: false,
    schema_version: 1, subject_kind: 'subject', max_data_class: 'summary', mandatory: false,
    has_engagement: filters.includes('engagement_ids'), has_severity: filters.includes('min_severity'),
    has_team: filters.includes('team_ids'), has_lead_time: filters.includes('lead_time_seconds'),
    variables: [],
  }
}

const catalog = [
  eventSpec('finding.ownership_changed', 'Finding ownership changed', ['engagement_ids', 'team_ids']),
  eventSpec('scan.completed', 'Scan completed', ['engagement_ids']),
  eventSpec('fleet.agent.offline', 'Agent offline', ['team_ids']),
]

const channel: NotificationChannel = {
  id: 'ch-1', name: 'SOC webhook', type: 'webhook', enabled: true, destination: 'https://hooks.example.test',
  revision: 1, secret_version: 1, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
}

function rule(eventType: string, roles: string[]): NotificationRule {
  return { id: 'rule-1', name: 'People', enabled: true, event_type: eventType, channel_ids: [channel.id], recipient_roles: roles, revision: 3 } as NotificationRule
}

async function editRule(r: NotificationRule) {
  vi.mocked(api.listNotificationRules).mockResolvedValue([r])
  render(<Alerting />)
  fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
  return screen.findByRole('button', { name: /Save rule/ })
}

describe('rule recipient roles (#1415)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(loadCapabilities).mockResolvedValue(null)
    vi.mocked(useCapabilities).mockReturnValue(new Map())
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue(catalog)
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.updateNotificationRule).mockResolvedValue(rule('scan.completed', []))
  })

  it('offers the roles the event supports and saves a role-only rule', async () => {
    const save = await editRule(rule('finding.ownership_changed', ['assignee']))
    const people = screen.getByRole('group', { name: 'Also notify people' })
    expect(within(people).getByRole('checkbox', { name: "The finding's assignee" })).toBeChecked()
    expect(within(people).getByRole('checkbox', { name: "Members of the finding's team" })).not.toBeChecked()
    fireEvent.click(within(people).getByRole('checkbox', { name: 'The engagement lead' }))
    // An ownership rule needs a team scope.
    fireEvent.click(screen.getByRole('checkbox', { name: 'All teams in this tenant' }))
    // Without a channel the roles alone keep the rule valid.
    fireEvent.click(screen.getByRole('checkbox', { name: 'SOC webhook' }))
    expect(save).toBeEnabled()
    fireEvent.click(save)
    await waitFor(() =>
      expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({ channel_ids: [], recipient_roles: ['assignee', 'engagement_lead'] })),
    )
  })

  it('drops roles an event cannot grant and needs a channel or a role', async () => {
    const save = await editRule(rule('fleet.agent.offline', ['engagement_lead']))
    expect(screen.queryByRole('group', { name: 'Also notify people' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'SOC webhook' }))
    expect(save).toBeDisabled()
  })

  it('lists the people a rule notifies', async () => {
    vi.mocked(api.listNotificationRules).mockResolvedValue([rule('scan.completed', ['engagement_lead'])])
    render(<Alerting />)
    expect(await screen.findByText(/People: engagement lead/)).toBeInTheDocument()
  })
})
