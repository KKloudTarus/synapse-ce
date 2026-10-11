import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel } from '../../lib/api'
import { resetCapabilityCache } from '../../lib/capabilities'
import type { Capability } from '../../lib/types'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', async (original) => ({
  ...(await original<typeof import('../../lib/api')>()),
  api: {
    me: vi.fn(),
    testAlert: vi.fn(),
    listCapabilities: vi.fn(),
    listNotificationChannels: vi.fn(),
    listNotificationRules: vi.fn(),
    listNotificationEventTypes: vi.fn(),
    notificationDeliveryPage: vi.fn(),
    listNotificationAttempts: vi.fn(),
    createNotificationChannel: vi.fn(),
    updateNotificationChannel: vi.fn(),
    testNotificationChannel: vi.fn(),
    listEngagements: vi.fn(),
    ownershipTeams: vi.fn(),
  },
}))

function channel(id: string, name: string, type: NotificationChannel['type'], enabled = true): NotificationChannel {
  return {
    id, name, type, enabled,
    destination: type === 'email' ? 'ops@example.com' : 'https://example.com/…',
    revision: 1, secret_version: 1, created_at: '', updated_at: '',
  }
}

// The catalog the server answers with SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED set: the disabled
// types are simply absent from notifications.channel_types.
function capabilities(channelTypes: string[]): Capability[] {
  return [
    {
      key: 'notifications', name: 'Tenant notifications', enabled: true,
      switch: 'SYNAPSE_NOTIFICATIONS_ENABLED', requires: [], values: [], planned: false,
    },
    {
      key: 'notifications.channel_types', name: 'Notification channel types', enabled: true,
      switch: 'SYNAPSE_NOTIFICATIONS_ENABLED', requires: ['notifications'], values: channelTypes, planned: false,
    },
  ]
}

function row(name: string): HTMLElement {
  const item = screen.getByText(name).closest('li')
  if (!item) throw new Error(`no channel row for ${name}`)
  return item
}

describe('operator kill switch in notification settings', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    resetCapabilityCache()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listNotificationRules).mockResolvedValue([])
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] })
  })

  it('does not offer a disabled type when creating a channel', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities(['webhook', 'email']))
    vi.mocked(api.listNotificationChannels).mockResolvedValue([])
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Type' }))
    expect(await screen.findByRole('option', { name: 'Signed webhook' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Email (SMTP)' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Slack incoming webhook' })).not.toBeInTheDocument()
  })

  it('says why no channel can be added when every type is disabled', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities([]))
    vi.mocked(api.listNotificationChannels).mockResolvedValue([])
    render(<Alerting />)
    expect(await screen.findByText(/disabled every notification channel type/)).toBeInTheDocument()
    expect(screen.getByText('SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: 'Type' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add channel' })).not.toBeInTheDocument()
  })

  it('marks an existing channel of a disabled type and blocks its test and enable actions', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities(['webhook', 'email']))
    vi.mocked(api.listNotificationChannels).mockResolvedValue([
      channel('s', 'Ops Slack', 'slack'),
      channel('p', 'Paused Slack', 'slack', false),
      channel('w', 'Security hook', 'webhook'),
    ])
    render(<Alerting />)
    await screen.findByText('Ops Slack')

    const slack = within(row('Ops Slack'))
    expect(slack.getByText('Disabled by operator')).toBeInTheDocument()
    expect(slack.getByText(/SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED/)).toBeInTheDocument()
    expect(slack.getByRole('button', { name: 'Test' })).toBeDisabled()
    // Switching it off, editing and deleting stay available.
    expect(slack.getByRole('button', { name: 'Disable' })).toBeEnabled()
    expect(slack.getByRole('button', { name: 'Edit channel' })).toBeEnabled()
    expect(slack.getByRole('button', { name: 'Delete Ops Slack' })).toBeEnabled()

    // A switched-off channel of a disabled type cannot be switched back on.
    expect(within(row('Paused Slack')).getByRole('button', { name: 'Enable' })).toBeDisabled()

    const hook = within(row('Security hook'))
    expect(hook.queryByText('Disabled by operator')).not.toBeInTheDocument()
    expect(hook.getByRole('button', { name: 'Test' })).toBeEnabled()
  })

  it('explains the kill switch when editing a channel of a disabled type', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities(['webhook', 'email']))
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel('s', 'Ops Slack', 'slack')])
    render(<Alerting />)
    await screen.findByText('Ops Slack')
    fireEvent.click(within(row('Ops Slack')).getByRole('button', { name: 'Edit channel' }))
    expect(await screen.findByText(/You can rename it or switch it\s+off/)).toBeInTheDocument()
  })

  it('marks nothing when the server does not report channel types', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue(null)
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel('s', 'Ops Slack', 'slack')])
    render(<Alerting />)
    await screen.findByText('Ops Slack')
    expect(screen.queryByText('Disabled by operator')).not.toBeInTheDocument()
    expect(within(row('Ops Slack')).getByRole('button', { name: 'Test' })).toBeEnabled()
  })
})
