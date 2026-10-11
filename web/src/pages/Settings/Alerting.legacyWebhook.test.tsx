import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel, NotificationEventSpec, NotificationRule, NotificationRuleFilter } from '../../lib/api'
import { loadCapabilities, useCapabilities } from '../../lib/capabilities'
import { Alerting } from './Alerting'

// #1347: while the deprecated SYNAPSE_ALERT_WEBHOOK_URL is set, an incident.created rule delivers in
// addition to the legacy webhook. The rule form must say so and block saving until acknowledged.

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    testAlert: vi.fn(),
    listNotificationEventTypes: vi.fn(),
    listNotificationChannels: vi.fn(),
    listNotificationRules: vi.fn(),
    updateNotificationRule: vi.fn(),
    // incident.created declares engagement_ids, so the rule form mounts the engagement picker.
    listEngagements: vi.fn(),
    notificationDeliveryPage: vi.fn(),
  },
  AlertNotEnabledError: class AlertNotEnabledError extends Error {},
  ApiError: class ApiError extends Error {},
}))

// The page reads the catalog twice: loadCapabilities for whether notifications are on (#1350), and
// useCapabilities for the legacy webhook warning. The pure helpers stay real.
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
  eventSpec('incident.created', 'Incident created', ['min_severity', 'engagement_ids']),
  eventSpec('scan.completed', 'Scan completed', ['engagement_ids']),
]

const channel: NotificationChannel = {
  id: 'ch-1',
  name: 'SOC webhook',
  type: 'webhook',
  enabled: true,
  destination: 'https://hooks.example.test',
  revision: 1,
  secret_version: 1,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
}

function rule(eventType: NotificationRule['event_type']): NotificationRule {
  return {
    id: 'rule-1',
    name: 'Incidents to SOC',
    enabled: true,
    event_type: eventType,
    channel_ids: [channel.id],
    min_severity: 'high',
    revision: 3,
  } as NotificationRule
}

function legacyWebhook(enabled: boolean) {
  vi.mocked(useCapabilities).mockReturnValue(
    new Map([
      [
        'legacy_alert_webhook',
        {
          key: 'legacy_alert_webhook',
          name: 'Legacy incident alert webhook (deprecated)',
          enabled,
          switch: 'SYNAPSE_ALERT_WEBHOOK_URL',
          requires: [],
          values: [],
          planned: false,
        },
      ],
    ]),
  )
}

async function editRule(eventType: NotificationRule['event_type']) {
  vi.mocked(api.listNotificationRules).mockResolvedValue([rule(eventType)])
  render(<Alerting />)
  fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
  return screen.findByRole('button', { name: /Save rule/ })
}

describe('Alerting rule form with the legacy incident webhook', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(loadCapabilities).mockResolvedValue(null)
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue(catalog)
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.updateNotificationRule).mockResolvedValue(rule('incident.created'))
    vi.mocked(api.listEngagements).mockResolvedValue([])
  })

  it('blocks saving an incident.created rule until the overlap is acknowledged', async () => {
    legacyWebhook(true)
    const save = await editRule('incident.created')
    // Other controls in the form can raise their own alerts; pick the legacy-webhook one by its text.
    const warning = screen
      .getAllByRole('alert')
      .find((el) => el.textContent?.includes('The legacy incident webhook is also configured'))
    if (!warning) throw new Error('legacy webhook warning not shown')
    expect(warning).toHaveTextContent('The legacy incident webhook is also configured')
    expect(warning).toHaveTextContent('deprecated and will be removed in 0.4.0')
    expect(warning).not.toHaveTextContent('https://')
    expect(save).toBeDisabled()

    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /incidents will be delivered through both paths/,
      }),
    )
    expect(save).toBeEnabled()
    fireEvent.click(save)
    await waitFor(() =>
      expect(api.updateNotificationRule).toHaveBeenCalledWith(
        'rule-1',
        expect.objectContaining({ event_type: 'incident.created', revision: 3 }),
      ),
    )
  })

  it('shows no warning when the legacy webhook is not configured', async () => {
    legacyWebhook(false)
    const save = await editRule('incident.created')
    expect(screen.queryByText('The legacy incident webhook is also configured')).toBeNull()
    expect(save).toBeEnabled()
  })

  it('shows no warning when the deployment does not report capabilities', async () => {
    vi.mocked(useCapabilities).mockReturnValue(null)
    const save = await editRule('incident.created')
    expect(screen.queryByText('The legacy incident webhook is also configured')).toBeNull()
    expect(save).toBeEnabled()
  })

  it('does not warn on other event types', async () => {
    legacyWebhook(true)
    const save = await editRule('scan.completed')
    expect(screen.queryByText('The legacy incident webhook is also configured')).toBeNull()
    expect(save).toBeEnabled()
  })
})
