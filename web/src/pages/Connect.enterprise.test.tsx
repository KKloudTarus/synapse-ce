import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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
    window.history.replaceState(null, '', '/')
    retry.mockClear()
    fetchSpy.mockReset()
    vi.stubGlobal('fetch', fetchSpy)
  })

  afterEach(() => vi.unstubAllGlobals())

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

  it('loads the explicit organization and submits that context to Login', async () => {
    window.history.replaceState(null, '', '/?tenant_id=tenant-b')
    fetchSpy
      .mockResolvedValueOnce(json({ enabled: true, tenant_id: 'tenant-b', requirement: 'optional', connections: [{ id: 'connection-b', name: 'Secondary identity' }] }))
      .mockResolvedValueOnce(json({ authorization_url: 'https://id.example/authorize' }))
    render(<Connect />)
    const button = await screen.findByRole('button', { name: 'Continue with Secondary identity' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/auth/enterprise/context?tenant_id=tenant-b', expect.anything())
    expect(screen.getByText('tenant-b')).toBeInTheDocument()
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: window.location.href, search: window.location.search })
    fireEvent.click(button)
    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://id.example/authorize'))
    expect(fetchSpy).toHaveBeenLastCalledWith('/api/auth/enterprise/begin', expect.objectContaining({
      body: JSON.stringify({ connection_id: 'connection-b', purpose: 'login', tenant_id: 'tenant-b' }),
    }))
  })

  it.each([
    ['missing endpoint', 404, null],
    ['disabled tenant', 200, { enabled: false }],
    ['wrong returned tenant', 200, { enabled: true, tenant_id: 'tenant-a', requirement: 'optional', connections: [] }],
  ])('fails closed for an explicit organization: %s', async (_name, status, body) => {
    window.history.replaceState(null, '', '/?tenant_id=tenant-b')
    fetchSpy.mockResolvedValueOnce(json(body, status))
    render(<Connect />)
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByLabelText('API token')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Sign in with your organization' })).not.toBeInTheDocument()
  })

  it('rejects duplicate organization selectors even when a response names one', async () => {
    window.history.replaceState(null, '', '/?tenant_id=tenant-b&tenant_id=tenant-a')
    fetchSpy.mockResolvedValueOnce(json({ enabled: true, tenant_id: 'tenant-b', requirement: 'optional', connections: [] }))
    render(<Connect />)
    expect(await screen.findByRole('alert')).toHaveTextContent('selected organization could not be loaded')
    expect(fetchSpy).toHaveBeenCalledWith('/api/auth/enterprise/context?tenant_id=tenant-b&tenant_id=tenant-a', expect.anything())
  })

})
