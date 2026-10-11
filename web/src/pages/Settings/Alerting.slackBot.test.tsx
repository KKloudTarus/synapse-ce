import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
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
    listSlackConversations: vi.fn(),
    listEngagements: vi.fn(),
    ownershipTeams: vi.fn(),
  },
}))

const TOKEN = 'xoxb' + '-1111111111-2222222222-uiSECRETtoken'

function capabilities(): Capability[] {
  return [
    {
      key: 'notifications', name: 'Tenant notifications', enabled: true,
      switch: 'SYNAPSE_NOTIFICATIONS_ENABLED', requires: [], values: [], planned: false,
    },
    {
      key: 'notifications.channel_types', name: 'Notification channel types', enabled: true,
      switch: 'SYNAPSE_NOTIFICATIONS_ENABLED', requires: ['notifications'], values: ['webhook', 'slack', 'slack_bot'], planned: false,
    },
  ]
}

function channel(id: string, name: string): NotificationChannel {
  return { id, name, type: 'slack_bot', enabled: true, destination: 'https://slack.com/…', revision: 2, secret_version: 1, created_at: '', updated_at: '' }
}

async function chooseSlackBot() {
  fireEvent.click(await screen.findByRole('combobox', { name: 'Type' }))
  fireEvent.click(await screen.findByRole('option', { name: 'Slack app (bot token)' }))
}

function addForm() {
  const form = screen.getByRole('button', { name: 'Add channel' }).closest('form')
  if (!form) throw new Error('no channel form')
  return within(form)
}

describe('Slack bot notification channel (#1383)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    resetCapabilityCache()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listCapabilities).mockResolvedValue(capabilities())
    vi.mocked(api.listNotificationRules).mockResolvedValue([])
    vi.mocked(api.listNotificationEventTypes).mockResolvedValue([])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] })
    vi.mocked(api.listNotificationChannels).mockResolvedValue([])
    vi.mocked(api.createNotificationChannel).mockResolvedValue(channel('n', 'new'))
    vi.mocked(api.updateNotificationChannel).mockResolvedValue(channel('n', 'new'))
    vi.mocked(api.listSlackConversations).mockResolvedValue({
      team_id: 'T0123',
      team_name: 'Acme',
      truncated: false,
      items: [
        { id: 'C0000000001', name: 'security', is_private: false, is_shared: false, is_archived: false, is_member: true },
        { id: 'C0000000002', name: 'partners', is_private: false, is_shared: true, is_archived: false, is_member: true },
        { id: 'G0000000003', name: 'incident', is_private: true, is_shared: false, is_archived: false, is_member: false },
      ],
    })
  })

  it('creates a channel from a bot token and a typed conversation ID', async () => {
    render(<Alerting />)
    await chooseSlackBot()
    const form = addForm()
    expect(form.queryByLabelText(/webhook URL/i)).not.toBeInTheDocument()
    expect(form.getByLabelText('Bot token')).toHaveAttribute('type', 'password')
    const add = form.getByRole('button', { name: 'Add channel' })
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'SOC' } })
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: 'xoxp' + '-1111111111-user-token' } })
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'C0000000001' } })
    // A user token cannot post as the app.
    expect(add).toBeDisabled()
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: ` ${TOKEN} ` } })
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: '#security' } })
    // A channel name is not an ID.
    expect(add).toBeDisabled()
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'C0000000001' } })
    expect(add).toBeEnabled()
    fireEvent.click(add)
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalled())
    const sent = vi.mocked(api.createNotificationChannel).mock.calls[0][0]
    expect(sent).toMatchObject({ type: 'slack_bot', secret: TOKEN, conversation_id: 'C0000000001', url: undefined })
    expect(sent.allow_shared_conversation).toBeUndefined()
  })

  it('lists the conversations of the typed token and warns about shared and uninvited ones', async () => {
    render(<Alerting />)
    await chooseSlackBot()
    const form = addForm()
    const load = form.getByRole('button', { name: 'Load channels' })
    expect(load).toBeDisabled()
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: TOKEN } })
    fireEvent.click(load)
    await waitFor(() => expect(api.listSlackConversations).toHaveBeenCalledWith({ bot_token: TOKEN }))
    expect(await form.findByText('3 channels in Acme')).toBeInTheDocument()
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'C0000000002' } })
    expect(await form.findByText(/is shared with another workspace/)).toBeInTheDocument()
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'G0000000003' } })
    expect(await form.findByText(/The app is not in #incident/)).toBeInTheDocument()
    // Allowing shared conversations is sent with the destination.
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'Partners' } })
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'C0000000002' } })
    fireEvent.click(form.getByRole('checkbox', { name: /Allow Slack Connect/ }))
    expect(form.queryByText(/is shared with another workspace/)).not.toBeInTheDocument()
    fireEvent.click(form.getByRole('button', { name: 'Add channel' }))
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalled())
    expect(vi.mocked(api.createNotificationChannel).mock.calls[0][0]).toMatchObject({ conversation_id: 'C0000000002', allow_shared_conversation: true })
  })

  it('drops a listing that arrives for a token the administrator already replaced', async () => {
    let resolveA: (value: unknown) => void = () => {}
    let rejectStale: (reason: unknown) => void = () => {}
    vi.mocked(api.listSlackConversations)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveA = resolve }) as never)
      .mockImplementationOnce(() => new Promise((_, reject) => { rejectStale = reject }) as never)
    render(<Alerting />)
    await chooseSlackBot()
    const form = addForm()
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: TOKEN } })
    fireEvent.click(form.getByRole('button', { name: 'Load channels' }))
    // The administrator switches to another app while A's listing is still on its way.
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: TOKEN + 'B' } })
    resolveA({ team_id: 'T0123', team_name: 'Acme', truncated: false, items: [{ id: 'C0000000001', name: 'security', is_private: false, is_shared: false, is_archived: false, is_member: true }] })
    await new Promise((r) => setTimeout(r, 0))
    expect(form.queryByText(/channels? in Acme/)).not.toBeInTheDocument()
    expect(form.queryByRole('combobox', { name: 'Slack channel' })).not.toBeInTheDocument()
    // A failed listing for a replaced token shows no error either.
    fireEvent.click(form.getByRole('button', { name: 'Load channels' }))
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: TOKEN } })
    rejectStale(new ApiError(400, 'invalid_auth'))
    await new Promise((r) => setTimeout(r, 0))
    expect(form.queryByRole('alert')).not.toBeInTheDocument()
    expect(form.getByRole('button', { name: 'Load channels' })).toBeEnabled()
  })

  it('shows a Slack error from the picker', async () => {
    vi.mocked(api.listSlackConversations).mockRejectedValue(new ApiError(400, 'Slack bot channel: the bot token was refused (invalid_auth)'))
    render(<Alerting />)
    await chooseSlackBot()
    const form = addForm()
    fireEvent.change(form.getByLabelText('Bot token'), { target: { value: TOKEN } })
    fireEvent.click(form.getByRole('button', { name: 'Load channels' }))
    expect(await form.findByRole('alert')).toHaveTextContent('invalid_auth')
  })

  it('renames without the token and lists conversations with the stored one', async () => {
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel('s', 'Slack SOC')])
    render(<Alerting />)
    const item = within((await screen.findByText('Slack SOC')).closest('li') as HTMLElement)
    expect(item.getByText('Slack app (bot token)')).toBeInTheDocument()
    fireEvent.click(item.getByRole('button', { name: 'Edit channel' }))
    expect(await screen.findByText(/enter the bot token and conversation ID again/)).toBeInTheDocument()
    const form = within(screen.getByRole('button', { name: 'Save channel' }).closest('form') as HTMLElement)
    fireEvent.click(form.getByRole('button', { name: 'Load channels' }))
    await waitFor(() => expect(api.listSlackConversations).toHaveBeenCalledWith({ channel_id: 's' }))
    const save = form.getByRole('button', { name: 'Save channel' })
    // A new conversation alone is a partial destination.
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: 'C0000000001' } })
    expect(save).toBeDisabled()
    fireEvent.change(form.getByLabelText('Conversation ID'), { target: { value: '' } })
    fireEvent.change(form.getByLabelText('Name'), { target: { value: 'Slack SecOps' } })
    expect(save).toBeEnabled()
    fireEvent.click(save)
    await waitFor(() => expect(api.updateNotificationChannel).toHaveBeenCalled())
    const [, sent] = vi.mocked(api.updateNotificationChannel).mock.calls[0]
    expect(sent).toMatchObject({ name: 'Slack SecOps', revision: 2 })
    expect(sent.secret).toBeUndefined()
    expect(sent.conversation_id).toBeUndefined()
    expect(sent.allow_shared_conversation).toBeUndefined()
  })
})
