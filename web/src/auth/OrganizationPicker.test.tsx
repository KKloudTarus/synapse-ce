import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { OrganizationPicker } from './OrganizationPicker'
import { useAuth } from './AuthContext'

vi.mock('./AuthContext', () => ({ useAuth: vi.fn() }))

const completeOrganizationSwitch = vi.fn<() => Promise<void>>()
const mockedUseAuth = vi.mocked(useAuth)

function authValue(): ReturnType<typeof useAuth> {
  return {
    phase: 'ready',
    aup: null,
    currentUser: { id: 'user-a', name: 'Alex', role: 'admin', membershipId: 'membership-a' },
    error: null,
    errorRequestId: null,
    canRetry: false,
    retrying: false,
    connecting: false,
    oidcAvailable: true,
    connect: async () => {},
    acceptAup: async () => {},
    logout: async () => {},
    retry: async () => {},
    completeOrganizationSwitch,
  }
}

describe('OrganizationPicker', () => {
  const fetchSpy = vi.fn<typeof fetch>()

  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('fetch', fetchSpy)
    fetchSpy.mockReset()
    completeOrganizationSwitch.mockResolvedValue(undefined)
    mockedUseAuth.mockReturnValue(authValue())
  })

  function respond(body: unknown, status = 200): void {
    fetchSpy.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(),
      json: async () => body,
    } as Response)
  }

  function memberships(): void {
    respond({
      memberships: [
        { tenant_id: 'tenant-a', membership_id: 'membership-a', name: 'Alpha', role: 'admin', active: true },
        { tenant_id: 'tenant-b', membership_id: 'membership-b', name: 'Beta', role: 'reviewer', active: true },
      ],
    })
  }

  it('requires an explicit provider choice when the switch asks for reauthentication', async () => {
    memberships()
    respond({ reauthentication_required: true, connections: [{ id: 'provider-a', name: 'Example SSO' }] })
    respond({ csrf_token: 'new-csrf', tenant_id: 'tenant-b' })
    render(<OrganizationPicker />)

    await screen.findByLabelText('Organization')
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: 'membership-b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch organization' }))

    const provider = await screen.findByLabelText('Verify with an identity provider')
    expect(screen.getByRole('button', { name: 'Continue to provider' })).toBeDisabled()
    fireEvent.change(provider, { target: { value: 'provider-a' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue to provider' }))

    await waitFor(() => expect(completeOrganizationSwitch).toHaveBeenCalledWith('new-csrf'))
    const secondBody = JSON.parse(String((fetchSpy.mock.calls[2][1] as RequestInit).body)) as Record<string, unknown>
    expect(secondBody).toMatchObject({ tenant_id: 'tenant-b', membership_id: 'membership-b', connection_id: 'provider-a' })
  })

  it('keeps membership load failures visible and allows retry', async () => {
    respond({ error: 'Organization service unavailable.' }, 503)
    memberships()
    render(<OrganizationPicker />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Organization service unavailable.')
    fireEvent.click(screen.getByRole('button', { name: 'Retry organizations' }))
    expect(await screen.findByLabelText('Organization')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('does not load enterprise memberships for a legacy principal', async () => {
    mockedUseAuth.mockReturnValue({ ...authValue(), currentUser: { id: 'legacy', name: 'Operator', role: 'admin' } })
    render(<OrganizationPicker />)
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('retries a transport failure with the same retry key and request body', async () => {
    memberships()
    fetchSpy.mockRejectedValueOnce(new TypeError('offline'))
    respond({ csrf_token: 'new-csrf', tenant_id: 'tenant-b' })
    render(<OrganizationPicker />)

    await screen.findByLabelText('Organization')
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: 'membership-b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch organization' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))

    await waitFor(() => expect(completeOrganizationSwitch).toHaveBeenCalledWith('new-csrf'))
    const first = String((fetchSpy.mock.calls[1][1] as RequestInit).body)
    const second = String((fetchSpy.mock.calls[2][1] as RequestInit).body)
    expect(second).toBe(first)
  })
})
