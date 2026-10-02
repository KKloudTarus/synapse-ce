import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './AuthContext'
import { Connect } from '../pages/Connect'
import { ApiError } from '../lib/api/errors'

const mocks = vi.hoisted(() => ({
  aup: vi.fn(),
  me: vi.fn(),
  acceptAup: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  api: { aup: mocks.aup, me: mocks.me, acceptAup: mocks.acceptAup },
  discoverSession: vi.fn(),
  logoutSession: vi.fn(),
  setCSRFToken: vi.fn(),
  setToken: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
}))

import { discoverSession, logoutSession, setCSRFToken, setToken, setUnauthorizedHandler } from '../lib/api'

const ACCEPTED = { accepted: true, version: 'v1', text: 'Use responsibly.' }
const PENDING_AUP = { accepted: false, version: 'v1', text: 'Use responsibly.' }
const CURRENT_USER = { id: 'user-1', name: 'Operator', role: 'admin' }

function apiError(status: number, code?: string, extra: Record<string, unknown> = {}) {
  const message = code ? `server says ${code}` : `HTTP ${status}`
  return new ApiError(status, message, code ? { error: message, code, ...extra } : undefined)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

function PhaseProbe() {
  const { phase } = useAuth()
  return <output data-testid="phase">{phase}</output>
}

function renderConnect() {
  return render(<AuthProvider><PhaseProbe /><Connect /></AuthProvider>)
}

const phase = () => screen.getByTestId('phase').textContent

function latestUnauthorizedHandler(): (e?: ApiError) => void {
  const calls = vi.mocked(setUnauthorizedHandler).mock.calls
  return calls[calls.length - 1][0] as (e?: ApiError) => void
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState(null, '', '/')
  vi.mocked(discoverSession).mockReset().mockResolvedValue({ authenticated: false, csrfToken: '' })
  vi.mocked(logoutSession).mockReset().mockResolvedValue()
  vi.mocked(setToken).mockClear()
  vi.mocked(setCSRFToken).mockClear()
  vi.mocked(setUnauthorizedHandler).mockClear()
  mocks.aup.mockReset().mockResolvedValue(ACCEPTED)
  mocks.me.mockReset().mockResolvedValue(CURRENT_USER)
  mocks.acceptAup.mockReset().mockResolvedValue({})
})

describe('BFF authentication', () => {
  it('discovers an existing BFF session before loading the AUP', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    renderConnect()

    await waitFor(() => expect(mocks.aup).toHaveBeenCalledTimes(1))
    expect(setCSRFToken).toHaveBeenCalledWith('csrf-1')
  })

  it('shows an unauthenticated state when a session is expired', async () => {
    renderConnect()

    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
    expect(mocks.aup).not.toHaveBeenCalled()
  })

  it('navigates to the OIDC login endpoint', async () => {
    renderConnect()

    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toHaveAttribute('href', '/api/auth/oidc/login')
  })

  it('falls back to the clearly labelled stored development token', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    renderConnect()

    await waitFor(() => expect(setToken).toHaveBeenCalledWith('saved-token'))
    expect(mocks.aup).toHaveBeenCalledTimes(1)
  })

  it('keeps the saved bearer token when session discovery itself fails', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    vi.mocked(discoverSession).mockRejectedValue(new Error('offline'))
    renderConnect()

    await waitFor(() => expect(mocks.aup).toHaveBeenCalledTimes(1))
    expect(setToken).toHaveBeenCalledWith('saved-token')
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('discards the saved bearer token only when the token is rejected', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(apiError(401, 'authentication_invalid'))
    renderConnect()

    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('logs out through the BFF and returns to unauthenticated state', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    mocks.aup.mockResolvedValue(PENDING_AUP)
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(logoutSession).toHaveBeenCalledTimes(1))
    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
  })

  it('stays signed in when server-side session revocation fails', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    vi.mocked(logoutSession).mockRejectedValue(new Error('gateway down'))
    mocks.aup.mockResolvedValue(PENDING_AUP)
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByText(/Could not end the server session/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Sign in with your organization' })).not.toBeInTheDocument()
  })

  it('signs out when the server already rejects the session being revoked', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    vi.mocked(logoutSession).mockRejectedValue(new ApiError(401, 'missing or invalid API token', { error: 'missing or invalid API token', code: 'authentication_invalid' }))
    mocks.aup.mockResolvedValue(PENDING_AUP)
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
    expect(screen.queryByText(/Could not end the server session/)).not.toBeInTheDocument()
  })

  it('clears a local bearer session without calling the BFF', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockResolvedValue(PENDING_AUP)
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
    expect(logoutSession).not.toHaveBeenCalled()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('swallows 404 session discovery error when BFF is unconfigured and does not show error banner', async () => {
    vi.mocked(discoverSession).mockRejectedValue(new ApiError(404, 'not found'))
    renderConnect()

    // A 404 means OIDC/BFF is unconfigured, so the org sign-in would be a dead CTA — it is hidden and
    // the API-token login is shown instead. No error banner is raised for this expected condition.
    expect(await screen.findByLabelText('API token')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Sign in with your organization' })).not.toBeInTheDocument()
    expect(screen.queryByText(/Could not check your sign-in session/)).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('toggles password visibility with the show/hide token button', async () => {
    renderConnect()

    const input = await screen.findByLabelText('API token')
    expect(input).toHaveAttribute('type', 'password')

    const toggleButton = screen.getByRole('button', { name: 'Show token' })
    fireEvent.click(toggleButton)

    expect(input).toHaveAttribute('type', 'text')
    expect(screen.getByRole('button', { name: 'Hide token' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Hide token' }))
    expect(input).toHaveAttribute('type', 'password')
  })
})

describe('credential restoration outcomes', () => {
  it('keeps the saved token and offers retry when authentication is unavailable, then reaches ready on retry', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true, request_id: 'req-123' }))
      .mockResolvedValueOnce(ACCEPTED)
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily unavailable/)
    expect(screen.getByText('req-123')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
    expect(phase()).toBe('unauthenticated')

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(phase()).toBe('ready'))
    expect(mocks.aup).toHaveBeenCalledTimes(2)
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('keeps the saved token when the API cannot be reached', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(new ApiError(0, 'Cannot reach the API.'))
    renderConnect()

    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('keeps a saved token when /me has a dependency failure and succeeds on Retry', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.me
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true, request_id: 'me-req-7' }))
      .mockResolvedValueOnce(CURRENT_USER)
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily unavailable/)
    expect(screen.getByText('me-req-7')).toBeInTheDocument()
    expect(phase()).toBe('unauthenticated')
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(phase()).toBe('ready'))
    expect(mocks.me).toHaveBeenCalledTimes(2)
  })

  it('does not persist a manually entered token when /me has a dependency failure', async () => {
    mocks.me.mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true, request_id: 'me-connect-3' }))
    renderConnect()

    fireEvent.change(await screen.findByLabelText('API token'), { target: { value: 'unverified-token' } })
    fireEvent.submit(screen.getByLabelText('API token').closest('form')!)

    expect(await screen.findByRole('alert')).toHaveTextContent(/authentication_unavailable/)
    expect(screen.getByText('me-connect-3')).toBeInTheDocument()
    expect(phase()).toBe('unauthenticated')
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('clears the saved token when the server reports authentication_invalid', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(apiError(401, 'authentication_invalid'))
    renderConnect()

    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('clears the saved token on a 401 without a code from an older server', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(new ApiError(401, 'unauthorized'))
    renderConnect()

    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('keeps the saved token on authentication_required because nothing was proven invalid', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(apiError(401, 'authentication_required'))
    renderConnect()

    expect(await screen.findByLabelText('API token')).toBeInTheDocument()
    expect(phase()).toBe('unauthenticated')
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('keeps the saved token on permission_denied and never reaches ready', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValue(apiError(403, 'permission_denied'))
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent(/permission_denied/)
    expect(phase()).toBe('unauthenticated')
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
    // A 403 is final for this request, so there is no retry loop that could later promote it.
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('keeps a cookie session and offers retry when session discovery is unavailable', async () => {
    vi.mocked(discoverSession)
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true }))
      .mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-2' })
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily unavailable/)
    expect(logoutSession).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(phase()).toBe('ready'))
    expect(setCSRFToken).toHaveBeenCalledWith('csrf-2')
  })

  it('treats an unknown 5xx code as retryable and an unknown 4xx code as final', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockRejectedValueOnce(apiError(503, 'future_dependency_code'))
    const { unmount } = renderConnect()

    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
    unmount()

    mocks.aup.mockRejectedValueOnce(apiError(409, 'future_policy_code'))
    renderConnect()
    expect(await screen.findByRole('alert')).toHaveTextContent(/future_policy_code/)
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('sends one restoration request when Retry is activated twice in a row', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    const late = deferred<typeof ACCEPTED>()
    mocks.aup
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true }))
      .mockReturnValueOnce(late.promise)
    renderConnect()

    const retry = await screen.findByRole('button', { name: 'Retry' })
    fireEvent.click(retry)
    fireEvent.click(retry)
    expect(await screen.findByRole('button', { name: /Retrying/ })).toBeDisabled()
    expect(mocks.aup).toHaveBeenCalledTimes(2)

    await act(async () => { late.resolve(ACCEPTED) })
    await waitFor(() => expect(phase()).toBe('ready'))
    expect(mocks.aup).toHaveBeenCalledTimes(2)
  })

  it('ignores a late restoration response after a new token is connected', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    const late = deferred<typeof ACCEPTED>()
    mocks.aup
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true }))
      .mockReturnValueOnce(late.promise)
      .mockResolvedValueOnce(PENDING_AUP)
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    // Wait until the retried restoration is waiting on its AUP read before connecting.
    await waitFor(() => expect(mocks.aup).toHaveBeenCalledTimes(2))
    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'new-token' } })
    fireEvent.submit(screen.getByLabelText('API token').closest('form')!)
    await waitFor(() => expect(phase()).toBe('need-aup'))

    // The earlier attempt now fails as if the old token were rejected. It must not clear the new one.
    await act(async () => { late.reject(apiError(401, 'authentication_invalid')) })
    expect(phase()).toBe('need-aup')
    expect(sessionStorage.getItem('synapse.token')).toBe('new-token')
    expect(screen.queryByText('Invalid API token.')).not.toBeInTheDocument()
  })

  it('ignores a late authenticated response after signing out', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockResolvedValueOnce(PENDING_AUP)
    renderConnect()

    const late = deferred<typeof ACCEPTED>()
    mocks.aup.mockReturnValueOnce(late.promise)
    fireEvent.click(await screen.findByRole('button', { name: /Accept/ }))
    await waitFor(() => expect(mocks.acceptAup).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(phase()).toBe('unauthenticated'))

    await act(async () => { late.resolve(ACCEPTED) })
    expect(phase()).toBe('unauthenticated')
  })
})

describe('requests after sign-in', () => {
  it('ignores an unavailable dependency reported to the unauthorized handler', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    renderConnect()
    await waitFor(() => expect(phase()).toBe('ready'))

    act(() => latestUnauthorizedHandler()(apiError(503, 'authentication_unavailable', { retryable: true })))
    act(() => latestUnauthorizedHandler()(apiError(403, 'csrf_invalid')))
    expect(phase()).toBe('ready')
    expect(sessionStorage.getItem('synapse.token')).toBe('saved-token')
  })

  it('returns to sign-in and clears the token when a later request reports authentication_invalid', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    renderConnect()
    await waitFor(() => expect(phase()).toBe('ready'))

    act(() => latestUnauthorizedHandler()(apiError(401, 'authentication_invalid')))
    expect(phase()).toBe('unauthenticated')
    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('reports an expired cookie session when a later request reports authentication_invalid', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    renderConnect()
    await waitFor(() => expect(phase()).toBe('ready'))

    act(() => latestUnauthorizedHandler()(apiError(401, 'authentication_invalid')))
    expect(await screen.findByText('Your sign-in session expired. Sign in again.')).toBeInTheDocument()
    expect(phase()).toBe('unauthenticated')
  })
})

describe('OIDC access denied', () => {
  it('shows the access-denied notice without retrying and removes it from the URL', async () => {
    window.history.replaceState(null, '', '/?auth_error=access_denied&keep=1')
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent('This sign-in is not approved for Synapse. Ask an administrator to link your identity.')
    expect(window.location.search).toBe('?keep=1')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(discoverSession).toHaveBeenCalledTimes(1)
  })

  it('shows a generic notice for any other sign-in error', async () => {
    window.history.replaceState(null, '', '/?auth_error=something_new')
    renderConnect()

    expect(await screen.findByRole('alert')).toHaveTextContent('Organization sign-in could not be completed.')
    expect(window.location.search).toBe('')
  })
})

describe('keyboard access', () => {
  it('moves focus to Retry, reaches it with Tab, and triggers it with Enter', async () => {
    const user = userEvent.setup()
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup
      .mockRejectedValueOnce(apiError(503, 'authentication_unavailable', { retryable: true }))
      .mockResolvedValueOnce(ACCEPTED)
    renderConnect()

    const retry = await screen.findByRole('button', { name: 'Retry' })
    await waitFor(() => expect(retry).toHaveFocus())

    retry.blur()
    await user.tab()
    expect(retry).toHaveFocus()
    await user.keyboard('{Enter}')
    await waitFor(() => expect(phase()).toBe('ready'))
    expect(mocks.aup).toHaveBeenCalledTimes(2)
  })
})
