import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import type { Engagement } from '../../lib/types'
import { LifecycleCard, OffensiveRoeEditorCard, isTerminalStatus } from './SettingsTab'

vi.mock('../../lib/api', () => ({
  api: { transitionEngagement: vi.fn(), setOffensiveRoE: vi.fn() },
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

describe('OffensiveRoeEditorCard', () => {
  beforeEach(() => vi.resetAllMocks())

  // Seed the risk ceiling (a Radix Select that jsdom cannot drive); the test exercises the Input and
  // toggle controls, which is where the readiness rule and the save payload are assembled.
  function engOffensive(over: Partial<{ customer: string; emergency: string; ceiling: string; reviewed: boolean }> = {}): Engagement {
    return {
      id: 'eng-1',
      name: 'Acme',
      client: 'Acme',
      status: 'active',
      inScope: [],
      outOfScope: [],
      authorizedFrom: null,
      authorizedTo: null,
      roe: {
        allowedToolClasses: [],
        blackouts: [],
        offensive: {
          customerContact: over.customer ?? '',
          emergencyContact: over.emergency ?? '',
          riskCeiling: over.ceiling ?? '',
          excludedAssets: [],
          exclusionsReviewed: over.reviewed ?? false,
          complete: false,
        },
      },
      liveReconEnabled: false,
      createdAt: null,
      businessAssetId: '',
    }
  }

  function renderOffensive(eng: Engagement) {
    const onUpdated = vi.fn()
    render(
      <MemoryRouter>
        <ToastProvider>
          <OffensiveRoeEditorCard eng={eng} onUpdated={onUpdated} />
        </ToastProvider>
      </MemoryRouter>,
    )
    return { onUpdated }
  }

  it('shows Incomplete until every required field is set, then Ready', async () => {
    // Contacts and ceiling are set; only the exclusions review is missing.
    renderOffensive(engOffensive({ customer: 'ciso@acme.example', emergency: '+1-555-0100', ceiling: 'high' }))
    expect(screen.getByText(/to go/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /exclusions reviewed/i }))

    await waitFor(() => expect(screen.getByText('Ready')).toBeInTheDocument())
  })

  it('saves the offensive rules of engagement with the entered values', async () => {
    vi.mocked(api.setOffensiveRoE).mockResolvedValue(engOffensive({ customer: 'x', emergency: 'y', ceiling: 'medium', reviewed: true }))
    renderOffensive(engOffensive({ ceiling: 'medium' }))

    fireEvent.change(screen.getByLabelText('Offensive RoE customer contact'), { target: { value: 'ciso@acme.example' } })
    fireEvent.change(screen.getByLabelText('Offensive RoE emergency contact'), { target: { value: '+1-555-0100' } })
    fireEvent.change(screen.getByLabelText('Offensive RoE excluded assets'), { target: { value: '10.0.0.9, db-prod' } })
    fireEvent.click(screen.getByRole('button', { name: /exclusions reviewed/i }))
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }))

    await waitFor(() =>
      expect(api.setOffensiveRoE).toHaveBeenCalledWith('eng-1', {
        customerContact: 'ciso@acme.example',
        emergencyContact: '+1-555-0100',
        riskCeiling: 'medium',
        excludedAssets: ['10.0.0.9', 'db-prod'],
        exclusionsReviewed: true,
      }),
    )
  })
})
