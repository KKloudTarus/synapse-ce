import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel, NotificationEventSpec, NotificationRule, NotificationRuleFilter } from '../../lib/api'
import { loadCapabilities, useCapabilities } from '../../lib/capabilities'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(), testAlert: vi.fn(), listNotificationEventTypes: vi.fn(),
    listNotificationChannels: vi.fn(), listNotificationRules: vi.fn(),
    updateNotificationRule: vi.fn(), createNotificationRule: vi.fn(),
    listEngagements: vi.fn(), ownershipTeams: vi.fn(), notificationDeliveryPage: vi.fn(),
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
    type, label, filters, operator_only: false, schema_version: 1, subject_kind: 'subject',
    max_data_class: 'summary', mandatory: false, has_engagement: false, has_severity: false,
    has_team: false, has_lead_time: false, variables: [],
  }
}

const catalog = [
  eventSpec('finding.status_changed', 'Finding status changed', ['finding_kinds', 'from_statuses', 'to_statuses']),
  eventSpec('finding.retest_completed', 'Finding retest completed', ['retest_results']),
  eventSpec('dast.run_finished', 'DAST run finished', ['scan_kinds', 'outcomes']),
  eventSpec('cspm.run_finished', 'CSPM run finished', ['providers', 'outcomes']),
]

const channel: NotificationChannel = {
  id: 'ch-1', name: 'Security webhook', type: 'webhook', enabled: true,
  destination: 'https://hooks.example.test', revision: 1, secret_version: 1,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
}

const savedRule: NotificationRule = {
  id: 'rule-1', name: 'Finding lifecycle', enabled: true, event_type: 'finding.status_changed',
  channel_ids: ['ch-1'], finding_kinds: ['manual'], from_statuses: ['open'],
  to_statuses: ['remediated'], revision: 3, created_at: '', updated_at: '',
}

describe('rule event filters', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: vi.fn(),
    })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(loadCapabilities).mockResolvedValue(null)
    vi.mocked(useCapabilities).mockReturnValue(new Map())
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue(catalog)
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.listNotificationRules).mockResolvedValue([savedRule])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] } as never)
    vi.mocked(api.updateNotificationRule).mockResolvedValue(savedRule)
  })

  it.each(['finding.created', 'finding.status_changed', 'finding.retest_completed', 'sla.breached', 'risk_acceptance.created', 'risk_acceptance.expiring', 'risk_acceptance.expired'])('preserves saved finding recipients for %s', async (event) => {
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([eventSpec(event, event, [])])
    vi.mocked(api.listNotificationRules).mockResolvedValue([{ ...savedRule, event_type: event, recipient_roles: ['assignee', 'team_member'] }])
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
    expect(screen.getByRole('checkbox', { name: "The finding's assignee" })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: "Members of the finding's team" })).toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({ recipient_roles: ['assignee', 'team_member'] })))
  })

  it.each([['finding.retest_completed', 'Retest results (optional)', 'Comma-separated retest results'], ['cspm.run_finished', 'Providers (optional)', 'Comma-separated cloud providers']])('describes %s filter for assistive technology', async (event, label, description) => {
    vi.mocked(api.listNotificationRules).mockResolvedValue([{ ...savedRule, event_type: event }])
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
    expect(screen.getByLabelText(label)).toHaveAccessibleDescription(description)
  })

  it('preserves supported saved filters and clears them when the event changes', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
    expect(screen.getByLabelText('Finding kinds (optional)')).toHaveValue('manual')
    expect(screen.getByLabelText('Finding kinds (optional)')).toHaveAccessibleDescription('Comma-separated finding kinds')
    expect(screen.getByLabelText('From statuses (optional)')).toHaveAccessibleDescription('Comma-separated statuses before the transition')
    expect(screen.getByLabelText('To statuses (optional)')).toHaveAccessibleDescription('Comma-separated statuses after the transition')
    expect(screen.getByLabelText('From statuses (optional)')).toHaveValue('open')
    expect(screen.getByLabelText('To statuses (optional)')).toHaveValue('remediated')

    fireEvent.click(document.getElementById('notification-event')!)
    fireEvent.click(await screen.findByRole('option', { name: 'DAST run finished' }))
    expect(screen.queryByLabelText('Finding kinds (optional)')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Scan kinds (optional)')).toHaveValue('')
    expect(screen.getByLabelText('Scan kinds (optional)')).toHaveAccessibleDescription('Comma-separated scan kinds')
    expect(screen.getByLabelText('Outcomes (optional)')).toHaveAccessibleDescription('Comma-separated outcomes')

    fireEvent.change(screen.getByLabelText('Scan kinds (optional)'), { target: { value: 'dast, api' } })
    fireEvent.change(screen.getByLabelText('Outcomes (optional)'), { target: { value: 'failed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      scan_kinds: ['dast', 'api'], outcomes: ['failed'], finding_kinds: undefined,
      from_statuses: undefined, to_statuses: undefined,
    })))
  })
})
