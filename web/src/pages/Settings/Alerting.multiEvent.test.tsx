import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel, NotificationEventSpec, NotificationRule } from '../../lib/api'
import { loadCapabilities, useCapabilities } from '../../lib/capabilities'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(), testAlert: vi.fn(), listNotificationEventTypes: vi.fn(),
    listNotificationChannels: vi.fn(), listNotificationRules: vi.fn(),
    updateNotificationRule: vi.fn(), createNotificationRule: vi.fn(),
    listEngagements: vi.fn(), ownershipTeams: vi.fn(), notificationUserChoices: vi.fn(),
    notificationDeliveryPage: vi.fn(), notificationSourceFailurePage: vi.fn(),
    listPersonalDefaults: vi.fn(), savePersonalDefault: vi.fn(), updateNotificationEngagementSetting: vi.fn(),
  },
  AlertNotEnabledError: class AlertNotEnabledError extends Error {},
  ApiError: class ApiError extends Error {},
}))

vi.mock('../../lib/capabilities', async (original) => ({
  ...(await original<typeof import('../../lib/capabilities')>()),
  loadCapabilities: vi.fn(),
  useCapabilities: vi.fn(),
}))

function event(type: string, label = type, filters: NotificationEventSpec['filters'] = []): NotificationEventSpec {
  return {
    type, label, filters, operator_only: false, schema_version: 1,
    subject_kind: 'subject', max_data_class: 'summary', mandatory: false,
    has_engagement: false, has_severity: false, has_team: false, has_lead_time: false,
    variables: [],
  }
}

const channel: NotificationChannel = {
  id: 'channel-1', name: 'Security chat', type: 'slack', enabled: true,
  destination: 'alerts', revision: 1, secret_version: 1,
  created_at: '2026-10-16T00:00:00Z', updated_at: '2026-10-16T00:00:00Z',
}

function rule(eventTypes?: string[]): NotificationRule {
  return {
    id: 'rule-1', name: 'Security lifecycle', enabled: true,
    event_type: 'finding.created', event_types: eventTypes,
    channel_ids: [channel.id], revision: 3, created_at: '', updated_at: '',
  }
}

async function openRule(initial: NotificationRule) {
  vi.mocked(api.listNotificationRules).mockResolvedValue([initial])
  render(<Alerting />)
  fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
  return screen.findByRole('button', { name: 'Save rule' })
}

describe('multi-event routing rules', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: vi.fn(),
    })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(loadCapabilities).mockResolvedValue(null)
    vi.mocked(useCapabilities).mockReturnValue(new Map())
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.created', 'Finding created'),
      event('finding.status_changed', 'Finding status changed'),
      event('scan.completed', 'Scan completed'),
    ])
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.notificationSourceFailurePage).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.listPersonalDefaults).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.notificationUserChoices).mockResolvedValue({ items: [] })
    vi.mocked(api.updateNotificationRule).mockResolvedValue(rule())
  })

  it('adds an event after the primary and retains that explicit order on save', async () => {
    const save = await openRule(rule())
    fireEvent.click(screen.getByRole('button', { name: 'No additional events' }))
    fireEvent.click(await screen.findByRole('option', { name: /Finding status changed/ }))
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      event_type: 'finding.created',
      event_types: ['finding.created', 'finding.status_changed'],
    })))
  })

  it('lists every selected event label for an existing multi-event rule', async () => {
    vi.mocked(api.listNotificationRules).mockResolvedValue([rule(['finding.created', 'finding.status_changed'])])
    render(<Alerting />)
    expect(await screen.findByText(/Finding created, Finding status changed/)).toBeInTheDocument()
  })

  it('clears an unsupported saved role when a legacy single-event rule changes primary event', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.created', 'Finding created'),
      event('incident.created', 'Incident created'),
    ])
    const save = await openRule({ ...rule(), recipient_roles: ['assignee'] })
    fireEvent.click(document.getElementById('notification-event')!)
    fireEvent.click(await screen.findByRole('option', { name: 'Incident created' }))
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      event_type: 'incident.created', recipient_roles: [],
    })))
  })

  it('keeps an explicit single-event array aligned with a changed primary event', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.created', 'Finding created'),
      event('incident.created', 'Incident created'),
    ])
    const save = await openRule(rule(['finding.created']))
    fireEvent.click(document.getElementById('notification-event')!)
    fireEvent.click(await screen.findByRole('option', { name: 'Incident created' }))
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      event_type: 'incident.created', event_types: ['incident.created'],
    })))
  })

  it('keeps a missing saved event id selected when the catalog no longer returns it', async () => {
    const save = await openRule(rule(['finding.created', 'removed.event']))
    fireEvent.click(screen.getByRole('button', { name: '1 additional event selected' }))
    expect(await screen.findByRole('option', { name: /removed\.event \(not available for new rules\)/ })).toHaveAttribute('aria-selected', 'true')
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      event_type: 'finding.created',
      event_types: ['finding.created', 'removed.event'],
    })))
  })

  it('limits the explicit selection to eight events', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.created', 'Finding created'),
      ...Array.from({ length: 8 }, (_, index) => event(`event.${index + 1}`, `Event ${index + 1}`)),
    ])
    await openRule(rule())
    fireEvent.click(screen.getByRole('button', { name: 'No additional events' }))
    for (let index = 1; index <= 8; index++) {
      fireEvent.click(await screen.findByRole('option', { name: `Event ${index}` }))
    }
    await waitFor(() => expect(document.body).toHaveTextContent('at most eight event types'))
    expect(screen.getByRole('option', { name: 'Event 8' })).toHaveAttribute('aria-selected', 'false')
  })

  it('sends an explicit empty event list when an existing multi-event rule returns to one event', async () => {
    const save = await openRule(rule(['finding.created', 'finding.status_changed']))
    fireEvent.click(screen.getByRole('button', { name: '1 additional event selected' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Finding status changed' }))
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      event_type: 'finding.created', event_types: [],
    })))
  })

  it('blocks an incidental save when a retained filter is not shared by every selected event', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.created', 'Finding created', ['min_severity']),
      event('scan.completed', 'Scan completed'),
    ])
    await openRule({
      ...rule(['finding.created', 'scan.completed']),
      min_severity: 'high',
    })
    expect(screen.getByText(/saved filters are not shared/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
  })

  it('requires a team scope for a team-scoped selection and rejects a blank mixed scope', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.ownership_changed', 'Finding ownership changed', ['team_ids']),
      event('scan.completed', 'Scan completed'),
    ])
    await openRule({ ...rule(['finding.ownership_changed', 'scan.completed']), event_type: 'finding.ownership_changed' })
    expect(screen.getByText(/must support the required team scope/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
  })

  it('requires an explicit team scope for a single team-scoped rule', async () => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([
      event('finding.ownership_changed', 'Finding ownership changed', ['team_ids']),
    ])
    await openRule({ ...rule(), event_type: 'finding.ownership_changed' })
    expect(screen.getByText(/Choose at least one team or select all teams/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
  })
})
