import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import type { Engagement } from '../../lib/types'
import { LifecycleCard, isTerminalStatus } from './SettingsTab'

vi.mock('../../lib/api', () => ({
  api: { transitionEngagement: vi.fn() },
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
