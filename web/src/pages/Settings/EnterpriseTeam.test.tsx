import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EnterpriseTeam } from './EnterpriseTeam'
import { ApiError } from '../../lib/api/errors'

const { administration } = vi.hoisted(() => ({ administration: {
  bootstrap: vi.fn(), roster: vi.fn(), invitations: vi.fn(), change: vi.fn(), createInvitation: vi.fn(), revokeInvitation: vi.fn(),
} }))
vi.mock('../../auth/AuthContext', () => ({ useOptionalAuth: () => ({ currentUser: { recentAuth: true, credentialKind: 'password' } }) }))
vi.mock('../../lib/api/identityAdministration', () => ({ identityAdministration: administration }))
vi.mock('../../components/synapse/ConfirmDialog', () => ({ ConfirmDialog: ({ open, onConfirm }: { open: boolean; onConfirm: () => void }) => open ? <button onClick={onConfirm}>Confirm</button> : null }))

describe('EnterpriseTeam', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    administration.roster.mockResolvedValue([{ id: 'm1', personId: 'p1', name: 'Ada', role: 'member', state: 'active', version: 7 }])
    administration.invitations.mockResolvedValue([{ id: 'i1', recipient: 'ada@example.test', role: 'member', state: 'pending', version: 2, expiresAt: '' }])
    administration.change.mockResolvedValue(undefined); administration.revokeInvitation.mockResolvedValue(undefined)
  })

  it('confirms a versioned role change before posting it', async () => {
    render(<EnterpriseTeam />)
    await screen.findByText('Ada')
    fireEvent.change(screen.getByLabelText('Role for Ada'), { target: { value: 'admin' } })
    expect(administration.change).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(administration.change).toHaveBeenCalledWith('m1', 'change_role', 7, 'admin', undefined))
  })

  it('confirms invitation revocation with the invitation version', async () => {
    render(<EnterpriseTeam />)
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(administration.revokeInvitation).toHaveBeenCalledWith('i1', 2, undefined))
  })

  it('masks a newly issued invitation code until it is revealed and dismisses it', async () => {
    administration.createInvitation.mockResolvedValue({ code: 'invitation-secret' })
    render(<EnterpriseTeam />)
    fireEvent.change(await screen.findByLabelText('Invitation email'), { target: { value: 'new@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create invitation' }))
    expect(await screen.findByText(/Copy this code now/)).toBeInTheDocument()
    expect(screen.queryByText('invitation-secret')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reveal' }))
    expect(screen.getByText('invitation-secret')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByText('invitation-secret')).not.toBeInTheDocument()
  })

  it.each([
    [401, 'Your administrator session has expired. Reauthenticate, then retry.', false],
    [403, 'You are not permitted to change this organization’s access.', false],
    [409, 'This record changed elsewhere. Reload the team and try again.', true],
  ])('makes %i failures actionable without applying a stale role', async (status, message, retryable) => {
    administration.change.mockRejectedValue(new ApiError(status, 'server detail'))
    render(<EnterpriseTeam />)
    fireEvent.change(await screen.findByLabelText('Role for Ada'), { target: { value: 'admin' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(message)
    expect(screen.getByLabelText('Role for Ada')).toHaveValue('member')
    expect(screen.queryByRole('button', { name: 'Retry' })).toBe(retryable ? screen.getByRole('button', { name: 'Retry' }) : null)
  })

  it('retries a 503 mutation with its versioned payload', async () => {
    administration.change.mockRejectedValueOnce(new ApiError(503, 'temporary')).mockResolvedValue(undefined)
    render(<EnterpriseTeam />)
    fireEvent.change(await screen.findByLabelText('Role for Ada'), { target: { value: 'admin' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(administration.change).toHaveBeenCalledTimes(2))
    expect(administration.change).toHaveBeenLastCalledWith('m1', 'change_role', 7, 'admin', undefined)
  })

  it('aborts and ignores a roster response after unmount', async () => {
    let resolveRoster!: (value: { id: string; personId: string; name: string; role: string; state: string; version: number }[]) => void
    administration.roster.mockImplementationOnce(() => new Promise((resolve) => { resolveRoster = resolve }))
    const view = render(<EnterpriseTeam />)
    await waitFor(() => expect(administration.roster).toHaveBeenCalled())
    const signal = administration.roster.mock.calls[0][0] as AbortSignal
    view.unmount()
    expect(signal.aborted).toBe(true)
    resolveRoster([{ id: 'late', personId: 'p2', name: 'Late', role: 'member', state: 'active', version: 1 }])
    await Promise.resolve()
    expect(screen.queryByText('Late')).not.toBeInTheDocument()
  })
})
