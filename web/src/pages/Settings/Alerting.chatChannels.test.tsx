import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
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

const ALL_TYPES = ['webhook', 'slack', 'email', 'teams', 'telegram', 'google_chat', 'discord']

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

function channel(id: string, name: string, type: NotificationChannel['type'], destination: string): NotificationChannel {
  return { id, name, type, enabled: true, destination, revision: 3, secret_version: 1, created_at: '', updated_at: '' }
}

async function chooseType(label: string) {
  fireEvent.click(await screen.findByRole('combobox', { name: 'Type' }))
  fireEvent.click(await screen.findByRole('option', { name: label }))
}

function addForm() {
  const form = screen.getByRole('button', { name: 'Add channel' }).closest('form')
  if (!form) throw new Error('no channel form')
  return within(form)
}

describe('chat notification channels (#1378 to #1381)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    resetCapabilityCache()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities(ALL_TYPES))
    vi.mocked(api.listNotificationRules).mockResolvedValue([])
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] })
    vi.mocked(api.listNotificationChannels).mockResolvedValue([])
    vi.mocked(api.createNotificationChannel).mockResolvedValue(channel('n', 'new', 'teams', 'https://x/…'))
    vi.mocked(api.updateNotificationChannel).mockResolvedValue(channel('n', 'new', 'teams', 'https://x/…'))
  })

  it('offers every advertised chat type', async () => {
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Type' }))
    for (const label of ['Microsoft Teams (Workflows)', 'Telegram bot', 'Google Chat incoming webhook', 'Discord webhook']) {
      expect(await screen.findByRole('option', { name: label })).toBeInTheDocument()
    }
  })

  it.each([
    ['Microsoft Teams (Workflows)', 'teams', 'Teams Workflows webhook URL', 'https://prod-1.westus.logic.azure.com/workflows/a?sig=s'],
    ['Google Chat incoming webhook', 'google_chat', 'Google Chat webhook URL', 'https://chat.googleapis.com/v1/spaces/A/messages?key=k&token=t'],
    ['Discord webhook', 'discord', 'Discord webhook URL', 'https://discord.com/api/webhooks/1/tok'],
  ])('creates a %s channel from its full URL', async (label, type, urlLabel, url) => {
    render(<Alerting />)
    await chooseType(label)
    const form = addForm()
    const input = form.getByLabelText(urlLabel)
    // The URL is the credential, so it is never shown in clear text.
    expect(input).toHaveAttribute('type', 'password')
    expect(form.queryByLabelText('HMAC secret')).not.toBeInTheDocument()
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'Security chat' } })
    fireEvent.change(input, { target: { value: url } })
    fireEvent.click(form.getByRole('button', { name: 'Add channel' }))
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalled())
    const sent = vi.mocked(api.createNotificationChannel).mock.calls[0][0]
    expect(sent).toMatchObject({ name: 'Security chat', type, url })
    expect(sent.secret).toBeUndefined()
    expect(sent.chat_id).toBeUndefined()
  })

  it('creates a Telegram channel from a bot token, chat and topic', async () => {
    render(<Alerting />)
    await chooseType('Telegram bot')
    const form = addForm()
    expect(form.queryByLabelText(/webhook URL/i)).not.toBeInTheDocument()
    expect(form.getByLabelText('Bot token')).toHaveAttribute('type', 'password')
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'On-call' } })
    const add = form.getByRole('button', { name: 'Add channel' })
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: ' 123456789:AAH-token ' } })
    expect(add).toBeDisabled() // no chat yet
    fireEvent.change(form.getByLabelText('Chat ID'), { target: { value: 'not a chat' } })
    expect(add).toBeDisabled()
    fireEvent.change(form.getByLabelText('Chat ID'), { target: { value: '-1001234567890' } })
    fireEvent.change(form.getByLabelText('Topic ID (optional)'), { target: { value: '12x' } })
    expect(add).toBeDisabled()
    fireEvent.change(form.getByLabelText('Topic ID (optional)'), { target: { value: '12' } })
    expect(add).toBeEnabled()
    fireEvent.click(add)
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalled())
    expect(vi.mocked(api.createNotificationChannel).mock.calls[0][0]).toMatchObject({
      type: 'telegram', secret: '123456789:AAH-token', chat_id: '-1001234567890', thread_id: 12, url: undefined,
    })
  })

  it('lists chat channels by name with only the masked host', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([
      channel('t', 'Teams ops', 'teams', 'https://prod-1.westus.logic.azure.com/…'),
      channel('g', 'Telegram on-call', 'telegram', 'https://api.telegram.org/…'),
    ])
    render(<Alerting />)
    const teams = within((await screen.findByText('Teams ops')).closest('li') as HTMLElement)
    expect(teams.getByText('Microsoft Teams (Workflows)')).toBeInTheDocument()
    expect(teams.getByText('https://prod-1.westus.logic.azure.com/…')).toBeInTheDocument()
    const telegram = within(screen.getByText('Telegram on-call').closest('li') as HTMLElement)
    expect(telegram.getByText('Telegram bot')).toBeInTheDocument()
  })

  it('renames a Telegram channel without re-entering the token, and asks for it to change the chat', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([
      channel('g', 'Telegram on-call', 'telegram', 'https://api.telegram.org/…'),
    ])
    render(<Alerting />)
    const item = within((await screen.findByText('Telegram on-call')).closest('li') as HTMLElement)
    fireEvent.click(item.getByRole('button', { name: 'Edit channel' }))
    expect(await screen.findByText(/enter the bot token and chat ID again/)).toBeInTheDocument()
    const form = within(screen.getByRole('button', { name: 'Save channel' }).closest('form') as HTMLElement)
    expect(form.getByLabelText('Bot token')).toHaveValue('')
    const save = form.getByRole('button', { name: 'Save channel' })
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'Telegram SOC' } })
    expect(save).toBeEnabled()
    // A new chat alone is a partial destination; the token is required with it.
    fireEvent.change(form.getByLabelText('Chat ID'), { target: { value: '-100999' } })
    expect(save).toBeDisabled()
    fireEvent.change(form.getByLabelText('Chat ID'), { target: { value: '' } })
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationChannel).toHaveBeenCalled())
    const [id, sent] = vi.mocked(api.updateNotificationChannel).mock.calls[0]
    expect(id).toBe('g')
    expect(sent).toMatchObject({ name: 'Telegram SOC', revision: 3 })
    expect(sent.secret).toBe('')
    expect(sent.chat_id).toBeUndefined()
    expect(sent.thread_id).toBeUndefined()
  })

  it('tells an editor of a URL channel to paste the full URL to replace it', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([
      channel('d', 'Discord SOC', 'discord', 'https://discord.com/…'),
    ])
    render(<Alerting />)
    const item = within((await screen.findByText('Discord SOC')).closest('li') as HTMLElement)
    fireEvent.click(item.getByRole('button', { name: 'Edit channel' }))
    expect(await screen.findByText(/paste the full new URL/)).toBeInTheDocument()
    expect(screen.getByLabelText('Discord webhook URL')).toHaveValue('')
  })
})
