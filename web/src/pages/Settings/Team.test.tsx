import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { User } from '../../lib/types'
import { ToastProvider } from '../../components/synapse/Toast'
import { Team } from './Team'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: {
      listUsers: vi.fn(),
      createUser: vi.fn(),
      updateUser: vi.fn(),
      setUserDisabled: vi.fn(),
      rotateUserAPIKey: vi.fn(),
    },
  }
})

const alice: User = { id: 'u-1', name: 'Alice', role: 'member', disabled: false, createdAt: null }
const bob: User = { id: 'u-2', name: 'Bob', role: 'admin', disabled: true, createdAt: null }

function renderTeam() {
  return render(<ToastProvider><Team /></ToastProvider>)
}

describe('Team administration', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listUsers).mockResolvedValue([alice, bob])
  })

  it('lists members with their role and disabled state', async () => {
    renderTeam()

    expect(await screen.findByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Bob')).toBeInTheDocument()
    expect(screen.getByText('disabled')).toBeInTheDocument()
  })

  // The server has always accepted a role change; the dashboard could not express one, so an
  // operator could add a person to the tenant but never adjust what they can do.
  it('changes a member role only after an explicit save', async () => {
    vi.mocked(api.updateUser).mockResolvedValue({ ...alice, role: 'reviewer' })
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getAllByRole('button', { name: 'Change role' })[0])
    const editor = screen.getByRole('group', { name: /Role for Alice/ })
    fireEvent.click(within(editor).getByLabelText('Reviewer'))

    // Selecting is not committing: a privilege change takes a deliberate save.
    expect(api.updateUser).not.toHaveBeenCalled()
    fireEvent.click(within(editor).getByRole('button', { name: 'Save role' }))

    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith('u-1', 'Alice', 'reviewer'))
  })

  it('offers every role the server accepts, not just admin and member', async () => {
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getAllByRole('button', { name: 'Change role' })[0])
    const editor = screen.getByRole('group', { name: /Role for Alice/ })
    for (const label of ['Member', 'Consultant', 'Reviewer', 'Read only', 'Admin']) {
      expect(within(editor).getByLabelText(label)).toBeInTheDocument()
    }
  })

  it('cannot save a role that is already the current one', async () => {
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getAllByRole('button', { name: 'Change role' })[0])
    const editor = screen.getByRole('group', { name: /Role for Alice/ })
    expect(within(editor).getByRole('button', { name: 'Save role' })).toBeDisabled()
  })

  // Revoking access is the action that matters most on a security control plane.
  it('disables an active member and re-enables a disabled one', async () => {
    vi.mocked(api.setUserDisabled).mockResolvedValue({ ...alice, disabled: true })
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(api.setUserDisabled).toHaveBeenCalledWith('u-1', true))

    fireEvent.click(screen.getByRole('button', { name: 'Enable' }))
    await waitFor(() => expect(api.setUserDisabled).toHaveBeenCalledWith('u-2', false))
  })

  // The rotated key is returned exactly once, so the screen has to say so where it is read.
  it('rotates a key and states that it is shown once', async () => {
    vi.mocked(api.rotateUserAPIKey).mockResolvedValue({ user: alice, apiKey: 'sk-rotated-123' })
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getAllByRole('button', { name: /Rotate key/ })[0])

    expect(await screen.findByText('sk-rotated-123')).toBeInTheDocument()
    expect(screen.getByText(/Shown once. The previous key stopped working immediately./)).toBeInTheDocument()
  })

  it('surfaces a failed action instead of leaving the row unchanged', async () => {
    vi.mocked(api.setUserDisabled).mockRejectedValue(new Error('insufficient permissions'))
    renderTeam()

    await screen.findByText('Alice')
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))

    // The row itself carries the failure, not only the transient toast, so the operator can still
    // read why the action did not take effect after the toast has gone.
    const shown = await screen.findAllByText('insufficient permissions')
    expect(shown.some((node) => node.className.includes('text-critical'))).toBe(true)
  })
})
