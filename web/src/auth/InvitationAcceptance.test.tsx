import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InvitationAcceptance } from './InvitationAcceptance'
import { useAuth } from './AuthContext'

vi.mock('./AuthContext', () => ({ useAuth: vi.fn() }))
const retry = vi.fn(async () => {})
const mockedAuth = vi.mocked(useAuth)

function auth(): ReturnType<typeof useAuth> {
  return { phase: 'unauthenticated', aup: null, currentUser: null, error: null, errorRequestId: null, canRetry: false, retrying: false, connecting: false, oidcAvailable: true, connect: async () => {}, acceptAup: async () => {}, logout: async () => {}, retry, completeMailboxContinuation: retry, completeOrganizationSwitch: async () => {} }
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
    expect(window.location.search).toContain('mailbox_verification_required')
    fireEvent.change(screen.getByLabelText('Mailbox verification code'), { target: { value: 'mailbox-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify mailbox' }))
    await waitFor(() => expect(retry).toHaveBeenCalledTimes(1))
    expect(String((fetchSpy.mock.calls[1][1] as RequestInit).body)).not.toContain('mailbox_verification_required')
  })

  it('groups a rejected invitation without exposing the server denial and focuses the guidance', async () => {
    respond({ error: 'forbidden' }, 403)
    render(<InvitationAcceptance />)
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'revoked-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue with invitation' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('This invitation is invalid, expired, or no longer active. Ask your administrator for a current invitation.')
    expect(alert).not.toHaveTextContent('forbidden')
    expect(document.activeElement).toBe(alert)
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('explains a denied mailbox code separately from invitation availability', async () => {
    respond({ challenge_required: true })
    respond({ error: 'forbidden' }, 403)
    window.history.replaceState(null, '', '/?auth_error=mailbox_verification_required')
    render(<InvitationAcceptance />)
    await screen.findByRole('heading', { name: 'Verify your mailbox' })
    fireEvent.change(screen.getByLabelText('Mailbox verification code'), { target: { value: 'wrong-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify mailbox' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('This mailbox verification code is invalid or expired. Ask your administrator for a new invitation if you need one.')
  })

  it('offers a retry after a transient invitation failure without replacing the current session', async () => {
    respond({ error: 'temporary' }, 503)
    respond({ connections: [{ id: 'provider-a', name: 'Example SSO' }] })
    render(<InvitationAcceptance />)
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'retry-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue with invitation' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('button', { name: 'Continue with Example SSO' })).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('asks the user to wait and permits only a manual retry after rate limiting', async () => {
    respond({ error: 'rate limited' }, 429)
    respond({ connections: [{ id: 'provider-a', name: 'Example SSO' }] })
    render(<InvitationAcceptance />)
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'retry-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue with invitation' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many attempts. Wait a moment, then retry.')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('button', { name: 'Continue with Example SSO' })).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('asks the user to sign in again after a rejected source session', async () => {
    respond({ error: 'unauthenticated' }, 401)
    render(<InvitationAcceptance />)
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'session-code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue with invitation' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Your sign-in session is no longer available. Sign in again, then retry the invitation.')
    expect(alert).not.toHaveTextContent('unauthenticated')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })
})
