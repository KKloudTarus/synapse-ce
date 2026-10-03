import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InvitationAcceptance } from './InvitationAcceptance'
import { useAuth } from './AuthContext'

vi.mock('./AuthContext', () => ({ useAuth: vi.fn() }))
const retry = vi.fn(async () => {})
const mockedAuth = vi.mocked(useAuth)

function auth(): ReturnType<typeof useAuth> {
  return { phase: 'unauthenticated', aup: null, currentUser: null, error: null, errorRequestId: null, canRetry: false, retrying: false, connecting: false, oidcAvailable: true, connect: async () => {}, acceptAup: async () => {}, logout: async () => {}, retry, completeOrganizationSwitch: async () => {} }
}

describe('InvitationAcceptance', () => {
  const fetchSpy = vi.fn<typeof fetch>()
  beforeEach(() => { vi.clearAllMocks(); fetchSpy.mockReset(); vi.stubGlobal('fetch', fetchSpy); mockedAuth.mockReturnValue(auth()); window.history.replaceState(null, '', '/') })
  function respond(value: unknown, status = 200) { fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, headers: new Headers(), json: async () => value } as Response) }

  it('requires a provider choice before beginning an invitation authorization', async () => {
    respond({ connections: [{ id: 'provider-a', name: 'Example SSO' }, { id: 'provider-b', name: 'Partner SSO' }] })
    respond({ connections: [] })
    render(<InvitationAcceptance />)
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'secret-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue with invitation' }))
    const provider = await screen.findByLabelText('Approved identity provider')
    expect(screen.getByRole('button', { name: 'Continue to provider' })).toBeDisabled()
    fireEvent.change(provider, { target: { value: 'provider-b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue to provider' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(String((fetchSpy.mock.calls[1][1] as RequestInit).body)).toContain('provider-b')
  })

  it('uses the marker only to load a pending mailbox challenge and refreshes auth after success', async () => {
    window.history.replaceState(null, '', '/?auth_error=mailbox_verification_required')
    respond({ challenge_required: true })
    respond({ csrf_token: 'replacement-csrf' })
    render(<InvitationAcceptance />)
    await screen.findByRole('heading', { name: 'Verify your mailbox' })
    expect(window.location.search).toBe('')
    fireEvent.change(screen.getByLabelText('Mailbox verification code'), { target: { value: 'mailbox-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify mailbox' }))
    await waitFor(() => expect(retry).toHaveBeenCalledTimes(1))
    expect(String((fetchSpy.mock.calls[1][1] as RequestInit).body)).not.toContain('mailbox_verification_required')
  })
})
