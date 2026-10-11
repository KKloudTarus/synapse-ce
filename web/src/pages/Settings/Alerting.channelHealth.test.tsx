import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { NotificationChannel } from '../../lib/api'
import { ChannelList } from './Alerting'

vi.mock('../../lib/api', async () => {
  const client = await vi.importActual<typeof import('../../lib/api/client')>('../../lib/api/client')
  return {
    ApiError: client.ApiError,
    AlertNotEnabledError: class AlertNotEnabledError extends Error {},
    api: {
      resumeNotificationChannel: vi.fn(),
      listNotificationChannelHealthEvents: vi.fn(),
      testNotificationChannel: vi.fn(),
      updateNotificationChannel: vi.fn(),
      deleteNotificationChannel: vi.fn(),
    },
  }
})

const base: NotificationChannel = {
  id: 'c1', name: 'Ops hook', type: 'webhook', enabled: true, destination: 'https://hooks.example.com/…',
  revision: 7, secret_version: 1, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
  health: { state: 'active', consecutive_failures: 0 },
}
const paused: NotificationChannel = {
  ...base,
  health: {
    state: 'paused', paused_at: '2026-09-29T08:00:00Z', paused_reason: 'consecutive_permanent_failures',
    consecutive_failures: 5, last_failure_code: 'destination_blocked', last_failure_at: '2026-09-29T08:00:00Z',
  },
}

function renderList(channels: NotificationChannel[], canAdmin = true) {
  const refresh = vi.fn()
  const notify = vi.fn()
  // types=null: the deployment does not report channel types, so no type is disabled by the operator.
  render(<ChannelList channels={channels} types={null} canAdmin={canAdmin} refresh={refresh} notify={notify} onEdit={vi.fn()} />)
  return { refresh, notify }
}

describe('Alerting channel health', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows a paused channel with its reason and resumes it with the current revision', async () => {
    vi.mocked(api.resumeNotificationChannel).mockResolvedValue({ ...base, revision: 8 })
    const { refresh, notify } = renderList([paused])
    expect(screen.getByText(/Paused: consecutive permanent failures/)).toBeInTheDocument()
    expect(screen.getByText(/after 5 consecutive permanent failures/)).toHaveTextContent('destination_blocked')
    expect(screen.getByRole('button', { name: /Test/ })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(api.resumeNotificationChannel).toHaveBeenCalledWith('c1', 7))
    await waitFor(() => expect(refresh).toHaveBeenCalled())
    expect(notify).toHaveBeenCalledWith(expect.stringContaining('Ops hook resumed'), 'success')
  })

  it('reports a failed resume, such as a stale revision, without refreshing', async () => {
    vi.mocked(api.resumeNotificationChannel).mockRejectedValue(new Error('notification channel revision is stale'))
    const { refresh, notify } = renderList([paused])
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(notify).toHaveBeenCalledWith('notification channel revision is stale', 'error'))
    expect(refresh).not.toHaveBeenCalled()
  })

  it('offers Resume only to administrators and only for a paused channel', () => {
    renderList([paused], false)
    expect(screen.queryByRole('button', { name: 'Resume' })).not.toBeInTheDocument()
    expect(screen.getByText(/Paused: consecutive permanent failures/)).toBeInTheDocument()
  })

  it('shows an active channel without a badge, and warns while failures accumulate', () => {
    renderList([base, { ...base, id: 'c2', name: 'Other', health: { state: 'active', consecutive_failures: 2, last_failure_code: 'http_404' } }])
    expect(screen.queryByText(/Paused/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resume' })).not.toBeInTheDocument()
    expect(screen.getByText(/2 consecutive permanent failures/)).toHaveTextContent('http_404')
  })

  it('loads the pause and resume history on demand', async () => {
    vi.mocked(api.listNotificationChannelHealthEvents).mockResolvedValue([
      { id: 'h2', channel_id: 'c1', action: 'resumed', failures: 5, failure_code: 'destination_blocked', actor: 'ada', occurred_at: '2026-09-29T09:00:00Z' },
      { id: 'h1', channel_id: 'c1', action: 'paused', reason: 'consecutive_permanent_failures', failures: 5, failure_code: 'destination_blocked', delivery_id: 'd1', attempt_id: 'a1', actor: 'system', occurred_at: '2026-09-29T08:00:00Z' },
    ])
    renderList([base])
    expect(api.listNotificationChannelHealthEvents).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'History' }))
    const history = await screen.findByRole('list', { name: 'Pause history' })
    expect(history).toHaveTextContent('Resumed by ada')
    expect(history).toHaveTextContent('Paused by the worker after 5 consecutive permanent failures')
    expect(api.listNotificationChannelHealthEvents).toHaveBeenCalledWith('c1')
  })

  it('says so when a channel has never been paused', async () => {
    vi.mocked(api.listNotificationChannelHealthEvents).mockResolvedValue([])
    renderList([base])
    fireEvent.click(screen.getByRole('button', { name: 'History' }))
    expect(await screen.findByText('This channel has never been paused.')).toBeInTheDocument()
  })
})
