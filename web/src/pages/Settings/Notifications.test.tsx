import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', async (original) => ({
  ...(await original<typeof import('../../lib/api')>()),
  api: {
    me: vi.fn(),
    testAlert: vi.fn(),
    listNotificationChannels: vi.fn(),
    listNotificationRules: vi.fn(),
    notificationDeliveryPage: vi.fn(),
    listNotificationAttempts: vi.fn(),
    createNotificationChannel: vi.fn(),
    updateNotificationChannel: vi.fn(),
    createNotificationRule: vi.fn(),
    updateNotificationRule: vi.fn(),
    testNotificationChannel: vi.fn(),
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
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
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
    expect(await screen.findByText('Enter at least one team ID or select all teams.')).toBeInTheDocument()
    expect(api.createNotificationRule).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(/^Team IDs/), {
      target: { value: 'pay, ops' },
    })
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
    fireEvent.change(screen.getByLabelText(/^Team IDs/), { target: { value: 'pay' } })
    fireEvent.click(screen.getByLabelText('All teams in this tenant'))
    expect(screen.getByLabelText(/^Team IDs/)).toBeDisabled()
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
    expect(screen.getByLabelText(/^Team IDs/)).toHaveValue('pay, ops')
    expect(screen.getByLabelText('All teams in this tenant')).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    await waitFor(() => expect(api.updateNotificationRule).toHaveBeenCalledWith('rule',
      expect.objectContaining({ revision: 4, team_ids: ['pay', 'ops'], all_teams: false }),
    ))
  })
})
