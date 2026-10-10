import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api, ApiError } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import type { Engagement } from '../../lib/types'
import { ExternalNotificationCard, LifecycleCard, isTerminalStatus } from './SettingsTab'

vi.mock('../../lib/api', () => ({
  api: {
    transitionEngagement: vi.fn(),
    me: vi.fn(),
    getNotificationEngagementSetting: vi.fn(),
    updateNotificationEngagementSetting: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message)
    }
  },
}))

function engagement(status: string): Engagement {
  return {
    id: 'eng-1',
    name: 'Review NodeGoat',
    client: 'Review',
    status,
    inScope: [],
    outOfScope: [],
    authorizedFrom: null,
    authorizedTo: null,
    roe: { allowedToolClasses: [], blackouts: [] },
    liveReconEnabled: false,
    createdAt: '2026-09-01T00:00:00Z',
    businessAssetId: '',
  }
}

function renderCard(status = 'active') {
  const onUpdated = vi.fn()
  render(
    <MemoryRouter>
      <ToastProvider>
        <LifecycleCard eng={engagement(status)} onUpdated={onUpdated} />
      </ToastProvider>
    </MemoryRouter>,
  )
  return { onUpdated }
}

describe('isTerminalStatus', () => {
  it('treats archived as terminal and the rest as reachable', () => {
    expect(isTerminalStatus('archived')).toBe(true)
    expect(isTerminalStatus('active')).toBe(false)
    expect(isTerminalStatus('completed')).toBe(false)
  })
})

describe('LifecycleCard', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('does not archive on the first click; it asks first', () => {
    renderCard()
    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))

    expect(api.transitionEngagement).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText(/terminal state/i)).toBeInTheDocument()
  })

  it('archives only after the confirm, and announces the outcome', async () => {
    vi.mocked(api.transitionEngagement).mockResolvedValue(engagement('archived'))
    const { onUpdated } = renderCard()

    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Archive' }))

    await waitFor(() => expect(api.transitionEngagement).toHaveBeenCalledWith('eng-1', 'archived'))
    await waitFor(() => expect(onUpdated).toHaveBeenCalled())
    expect(await screen.findByRole('status')).toHaveTextContent('Engagement is now archived.')
  })

  it('cancelling leaves the engagement alone', () => {
    renderCard()
    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(api.transitionEngagement).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('keeps a non-terminal transition a single click', async () => {
    vi.mocked(api.transitionEngagement).mockResolvedValue(engagement('completed'))
    renderCard('active')
    fireEvent.click(screen.getByRole('button', { name: 'Complete' }))

    await waitFor(() => expect(api.transitionEngagement).toHaveBeenCalledWith('eng-1', 'completed'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('surfaces a failed transition in the dialog and as an alert', async () => {
    vi.mocked(api.transitionEngagement).mockRejectedValue(new Error('archive refused'))
    renderCard()

    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Archive' }))

    expect(await screen.findAllByText('archive refused')).not.toHaveLength(0)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})

describe('ExternalNotificationCard', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: vi.fn(),
    })
    vi.mocked(api.me).mockResolvedValue({ role: 'integration_admin' } as never)
    vi.mocked(api.getNotificationEngagementSetting).mockResolvedValue({
      engagement_id: 'eng-1',
      external_notifications: 'inherit',
      revision: 3,
    } as never)
  })

  it('lets an integration administrator lower an engagement notification limit with its revision', async () => {
    vi.mocked(api.updateNotificationEngagementSetting).mockResolvedValue({
      engagement_id: 'eng-1',
      external_notifications: 'signal',
      revision: 4,
    } as never)
    render(<ExternalNotificationCard eng={engagement('active')} />)

    const limit = await screen.findByRole('combobox', { name: 'External notification limit' })
    expect(limit).toHaveAccessibleDescription('You can lower this limit. Raising it requires a tenant administrator.')
    fireEvent.click(limit)
    fireEvent.click(await screen.findByRole('option', { name: /Signal — event/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save notification limit' }))

    await waitFor(() =>
      expect(api.updateNotificationEngagementSetting).toHaveBeenCalledWith('eng-1', {
        external_notifications: 'signal',
        revision: 3,
      }),
    )
  })

  it('does not offer an integration administrator a way to raise a signal cap', async () => {
    vi.mocked(api.getNotificationEngagementSetting).mockResolvedValue({
      engagement_id: 'eng-1',
      external_notifications: 'signal',
      revision: 3,
    } as never)
    render(<ExternalNotificationCard eng={engagement('active')} />)

    fireEvent.click(await screen.findByRole('combobox', { name: 'External notification limit' }))
    expect(screen.getByRole('option', { name: /Signal — event/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /None — keep/ })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /Inherit — use/ })).not.toBeInTheDocument()
  })

  it('keeps the conflict explanation after a newer setting reloads', async () => {
    vi.mocked(api.getNotificationEngagementSetting)
      .mockResolvedValueOnce({
        engagement_id: 'eng-1',
        external_notifications: 'inherit',
        revision: 3,
      } as never)
      .mockResolvedValueOnce({
        engagement_id: 'eng-1',
        external_notifications: 'signal',
        revision: 4,
      } as never)
    vi.mocked(api.updateNotificationEngagementSetting).mockRejectedValue(
      new ApiError(409, 'stale revision'),
    )
    render(<ExternalNotificationCard eng={engagement('active')} />)

    fireEvent.click(await screen.findByRole('combobox', { name: 'External notification limit' }))
    fireEvent.click(await screen.findByRole('option', { name: /None — keep/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save notification limit' }))

    await waitFor(() =>
      expect(api.getNotificationEngagementSetting).toHaveBeenCalledTimes(2),
    )
    expect(await screen.findByText(/changed elsewhere/i)).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'External notification limit' })).toHaveTextContent(
      /Signal — event/,
    )
  })
})
