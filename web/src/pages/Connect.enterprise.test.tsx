import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Connect } from './Connect'

const retry = vi.fn(async () => {})
const auth = {
  phase: 'unauthenticated' as const,
  aup: null,
  error: null,
  errorRequestId: null,
  canRetry: false,
  retrying: false,
  retry,
  connecting: false,
  connect: vi.fn(async () => {}),
  acceptAup: vi.fn(async () => {}),
  logout: vi.fn(async () => {}),
  oidcAvailable: true,
}

vi.mock('../auth/AuthContext', () => ({ useAuth: () => auth }))

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

describe('Connect enterprise sign-in', () => {
  const fetchSpy = vi.fn<typeof fetch>()

  beforeEach(() => {
    retry.mockClear()
    fetchSpy.mockReset()
    vi.stubGlobal('fetch', fetchSpy)
  })

  it('shows the one server-approved connection without legacy sign-in choices', async () => {
    fetchSpy.mockResolvedValueOnce(json({ enabled: true, tenant_id: 'tenant-a', requirement: 'required', connections: [{ id: 'connection-a', name: 'Example identity' }], bootstrap_eligible: false }))

    render(<Connect />)

    expect(await screen.findByRole('button', { name: 'Continue with Example identity' })).toBeEnabled()
    expect(screen.getByText('Organization sign-in is required.')).toBeInTheDocument()
    expect(screen.queryByText('Development or automation API token')).not.toBeInTheDocument()
  })

  it('requires an explicit selection when several approved connections exist', async () => {
    fetchSpy.mockResolvedValueOnce(json({ enabled: true, tenant_id: 'tenant-a', requirement: 'optional', connections: [{ id: 'connection-a', name: 'Example identity' }, { id: 'connection-b', name: 'Partner identity' }], bootstrap_eligible: false }))

    render(<Connect />)

    const select = await screen.findByLabelText('Approved sign-in connection')
    const submit = screen.getByRole('button', { name: 'Continue with selected connection' })
    expect(submit).toBeDisabled()
    fireEvent.change(select, { target: { value: 'connection-b' } })
    expect(submit).toBeEnabled()
  })

  it('does not fall back to legacy OIDC when approved context cannot be loaded', async () => {
    fetchSpy.mockResolvedValueOnce(json({ error: 'unavailable' }, 503))

    render(<Connect />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Enterprise sign-in is temporarily unavailable. Try again.')
    expect(screen.queryByRole('link', { name: 'Sign in with your organization' })).not.toBeInTheDocument()
    expect(screen.queryByText('Development or automation API token')).not.toBeInTheDocument()
  })

  it('keeps legacy sign-in when the public context endpoint is absent', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 404 }))

    render(<Connect />)

    expect(await screen.findByRole('link', { name: 'Sign in with your organization' })).toHaveAttribute('href', '/api/auth/oidc/login')
    expect(screen.getByText('Development or automation API token')).toBeInTheDocument()
  })

  it('reports recovery activation failures without refreshing authentication state', async () => {
    fetchSpy
      .mockResolvedValueOnce(json({ enabled: true, tenant_id: 'tenant-a', requirement: 'required', connections: [], bootstrap_eligible: false }))
      .mockResolvedValueOnce(json({ error: 'invalid recovery code' }, 401))

    render(<Connect />)

    await screen.findByText(/No approved sign-in connections are available/)
    fireEvent.click(screen.getByText('Emergency activation'))
    fireEvent.change(screen.getByLabelText('Recovery code'), { target: { value: 'secret code' } })
    fireEvent.click(screen.getByRole('button', { name: 'Activate emergency session' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Emergency activation could not be completed.')
    expect(retry).not.toHaveBeenCalled()
    await waitFor(() => expect(fetchSpy).toHaveBeenLastCalledWith('/api/auth/enterprise/recovery', expect.objectContaining({ method: 'POST', body: JSON.stringify({ secret: 'secret code' }) })))
  })
})
