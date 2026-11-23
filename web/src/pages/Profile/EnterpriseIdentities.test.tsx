import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EnterpriseIdentities } from './EnterpriseIdentities'

const { useOptionalAuth } = vi.hoisted(() => ({ useOptionalAuth: vi.fn() }))
vi.mock('../../auth/AuthContext', () => ({ useOptionalAuth }))
vi.mock('../../auth/InvitationAcceptance', () => ({ InvitationAcceptance: () => <p>Invitation entry</p> }))

function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } }) }

describe('EnterpriseIdentities', () => {
  beforeEach(() => {
    vi.restoreAllMocks(); useOptionalAuth.mockReturnValue({ currentUser: { recentAuth: true } })
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/identity/authenticators') return Promise.resolve(json({ identities: [{ connection_id: 'linked', name: 'Work SSO', state: 'approved' }] }))
      if (path === '/api/v1/identity/link-connections') return Promise.resolve(json({ connections: [{ id: 'linked', name: 'Work SSO' }, { id: 'okta', name: 'Okta' }] }))
      if (path === '/api/auth/enterprise/begin') return Promise.resolve(json({ error: 'provider unavailable' }, 503))
      return Promise.resolve(json({}))
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('links only a selected approved provider and keeps provider errors visible', async () => {
    render(<EnterpriseIdentities />)
    expect(await screen.findByText('Work SSO · approved')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Link identity' }))
    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/auth/enterprise/begin', expect.objectContaining({ method: 'POST' })))
    const call = vi.mocked(fetch).mock.calls.find(([path]) => path === '/api/auth/enterprise/begin')
    expect(call).toBeDefined()
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ purpose: 'link', connection_id: 'okta' })
    expect(await screen.findByRole('alert')).toHaveTextContent('provider unavailable')
    expect(document.body.textContent).not.toContain('authorization_url')
  })

  it('reauthenticates a linked provider when the session is stale instead of linking a new subject', async () => {
    useOptionalAuth.mockReturnValue({ currentUser: { recentAuth: false } })
    render(<EnterpriseIdentities />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reauthenticate with Work SSO' }))
    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([path]) => path === '/api/auth/enterprise/begin')
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ purpose: 'step_up', connection_id: 'linked' })
    })
    expect(screen.queryByRole('button', { name: 'Link identity' })).not.toBeInTheDocument()
    expect(await screen.findByRole('alert')).toHaveTextContent('provider unavailable')
    expect(screen.getByRole('button', { name: 'Reauthenticate with Work SSO' })).toBeEnabled()
  })

  it('offers reauthentication for the only linked provider without offering to link it again', async () => {
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(path === '/api/v1/identity/authenticators'
      ? json({ identities: [{ connection_id: 'linked', name: 'Work SSO', state: 'approved' }] })
      : json({ connections: [{ id: 'linked', name: 'Work SSO' }] }))))
    render(<EnterpriseIdentities />)
    expect(await screen.findByRole('button', { name: 'Reauthenticate with Work SSO' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Link identity' })).not.toBeInTheDocument()
    expect(screen.getByText('No additional identity providers are approved for this organization.')).toBeInTheDocument()
  })

  it('does not offer reauthentication for revoked identities or disabled connections', async () => {
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(path === '/api/v1/identity/authenticators'
      ? json({ identities: [{ connection_id: 'revoked', name: 'Revoked SSO', state: 'revoked' }, { connection_id: 'disabled', name: 'Disabled SSO', state: 'approved' }] })
      : json({ connections: [{ id: 'revoked', name: 'Revoked SSO' }] }))))
    render(<EnterpriseIdentities />)
    expect(await screen.findByText('Disabled SSO · approved')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Reauthenticate with/ })).not.toBeInTheDocument()
  })

  it('abandons a late loading response after unmount', async () => {
    let resolve!: (value: Response) => void
    vi.stubGlobal('fetch', vi.fn((path: string) => path === '/api/v1/identity/authenticators' ? new Promise<Response>((done) => { resolve = done }) : Promise.resolve(json({ connections: [] }))))
    const view = render(<EnterpriseIdentities />)
    view.unmount()
    resolve(json({ identities: [{ connection_id: 'late', name: 'Late', state: 'approved' }] }))
    await Promise.resolve()
    expect(screen.queryByText('Late · approved')).not.toBeInTheDocument()
  })
})
