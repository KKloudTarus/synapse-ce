import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import { Team } from './Team'

vi.mock('../../lib/api', () => ({
  api: {
    createUser: vi.fn(),
    listUsers: vi.fn(),
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

vi.mock('../../hooks', () => ({
  useUserList: () => ({ data: [], loading: false, error: null, forbidden: false, refetch: vi.fn() }),
}))

vi.mock('../../lib/clipboard', () => ({ copyText: vi.fn().mockResolvedValue(undefined) }))

function renderTeam() {
  render(
    <ToastProvider>
      <Team />
    </ToastProvider>,
  )
}

describe('Team', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('announces a member add and says the API key is shown once', async () => {
    vi.mocked(api.createUser).mockResolvedValue({
      user: { id: 'u-1', name: 'Ada', role: 'member', disabled: false },
      apiKey: 'syn_live_abc123',
    } as never)

    renderTeam()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Ada' } })
    fireEvent.click(screen.getByRole('button', { name: /Add/ }))

    expect(await screen.findByRole('status')).toHaveTextContent('Ada added as member')
    expect(screen.getByText(/Shown once/)).toBeInTheDocument()
    expect(screen.getByText(/cannot be retrieved again/)).toBeInTheDocument()
    expect(screen.getByText('syn_live_abc123')).toBeInTheDocument()
  })

  it('announces a failed add as an alert', async () => {
    vi.mocked(api.createUser).mockRejectedValue(new Error('duplicate name'))

    renderTeam()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Ada' } })
    fireEvent.click(screen.getByRole('button', { name: /Add/ }))

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('duplicate name'))
    expect(screen.queryByText(/Shown once/)).not.toBeInTheDocument()
  })
})
