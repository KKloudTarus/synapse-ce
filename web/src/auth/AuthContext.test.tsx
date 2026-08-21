import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from './AuthContext'
import { Connect } from '../pages/Connect'

const mocks = vi.hoisted(() => ({
  aup: vi.fn(),
  acceptAup: vi.fn(),
}))

vi.mock('../lib/api', () => ({
  api: { aup: mocks.aup, acceptAup: mocks.acceptAup },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) { super(message) }
  },
  discoverSession: vi.fn(),
  logoutSession: vi.fn(),
  setCSRFToken: vi.fn(),
  setToken: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
}))

import { ApiError, discoverSession, logoutSession, setCSRFToken, setToken } from '../lib/api'

function renderConnect() {
  return render(<AuthProvider><Connect /></AuthProvider>)
}

describe('BFF authentication', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: false, csrfToken: '' })
    vi.mocked(logoutSession).mockResolvedValue()
    mocks.aup.mockResolvedValue({ accepted: true, version: 'v1', text: 'Use responsibly.' })
  })

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
    mocks.aup.mockRejectedValue(new ApiError(401, 'unauthorized'))
    renderConnect()

    expect(await screen.findByText('Invalid API token.')).toBeInTheDocument()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })

  it('logs out through the BFF and returns to unauthenticated state', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    mocks.aup.mockResolvedValue({ accepted: false, version: 'v1', text: 'Use responsibly.' })
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(logoutSession).toHaveBeenCalledTimes(1))
    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
  })

  it('stays signed in when server-side session revocation fails', async () => {
    vi.mocked(discoverSession).mockResolvedValue({ authenticated: true, csrfToken: 'csrf-1' })
    vi.mocked(logoutSession).mockRejectedValue(new Error('gateway down'))
    mocks.aup.mockResolvedValue({ accepted: false, version: 'v1', text: 'Use responsibly.' })
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByText(/Could not end the server session/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Sign in with your organization' })).not.toBeInTheDocument()
  })

  it('clears a local bearer session without calling the BFF', async () => {
    sessionStorage.setItem('synapse.token', 'saved-token')
    mocks.aup.mockResolvedValue({ accepted: false, version: 'v1', text: 'Use responsibly.' })
    renderConnect()

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toBeInTheDocument()
    expect(logoutSession).not.toHaveBeenCalled()
    expect(sessionStorage.getItem('synapse.token')).toBeNull()
  })
})
