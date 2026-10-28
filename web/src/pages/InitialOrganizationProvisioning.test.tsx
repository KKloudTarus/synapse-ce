import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InitialOrganizationProvisioning } from './InitialOrganizationProvisioning'
import { identityProvisioningApi } from '../lib/api/identityProvisioning'

vi.mock('../lib/api/identityProvisioning', () => ({ identityProvisioningApi: { begin: vi.fn(), status: vi.fn(), draft: vi.fn(), test: vi.fn(), activate: vi.fn(), invitation: vi.fn() } }))

const api = vi.mocked(identityProvisioningApi)
const initial = { id: 'provisioning-1', tenantId: 'sandbox-b', recipient: 'admin@example.test', state: 'open', version: 1, connection: null, invitation: null }
const drafted = { ...initial, state: 'draft', version: 2, connection: { id: 'connection-1', displayName: 'Sandbox identity', issuer: 'https://issuer.example/', clientId: 'client-id', enabled: false, revision: 0, draftRevision: 1, version: 1, testPassed: false, auth0OrganizationId: 'org-sandbox-b' } }
const tested = { ...drafted, state: 'tested', version: 3, connection: { ...drafted.connection, testPassed: true } }
const active = { ...tested, state: 'active', connection: { ...tested.connection, enabled: true } }

function renderProvisioning(initialEntry = '/settings/authentication') {
  return render(<MemoryRouter initialEntries={[initialEntry]}><InitialOrganizationProvisioning /></MemoryRouter>)
}

describe('InitialOrganizationProvisioning', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.begin.mockResolvedValue({ provisioning: initial, capability: 'capability-opaque' })
    api.draft.mockResolvedValue(drafted)
    api.test.mockResolvedValue({ authorizationURL: 'https://issuer.example/authorize?state=opaque' })
    api.activate.mockResolvedValue(active)
    api.invitation.mockResolvedValue({ provisioning: { ...active, invitation: { id: 'invite-1', recipient: 'admin@example.test', role: 'admin', state: 'created', version: 1, expiresAt: '2026-10-30T00:00:00Z' } }, code: 'invite-code-secret' })
  })

  it('allows initial Entra mode and fixes it after the draft is created', async () => {
    const issuer = 'https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0'
    api.draft.mockResolvedValue({ ...drafted, connection: { ...drafted.connection, issuer, auth0OrganizationId: '', draftEntraDiscoveryMode: 'common' } })
    renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: issuer } })
    fireEvent.change(screen.getByLabelText('Entra metadata discovery'), { target: { value: 'common' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Entra' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'client' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save connection draft' }))
    await waitFor(() => expect(api.draft).toHaveBeenCalledWith(expect.objectContaining({ entraDiscoveryMode: 'common' })))
    expect(screen.getByLabelText('Entra metadata discovery')).toBeDisabled()
    expect(screen.getByLabelText('Entra metadata discovery')).toHaveValue('common')
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'replacement' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save corrected credential' }))
    await waitFor(() => expect(api.draft).toHaveBeenLastCalledWith(expect.objectContaining({ entraDiscoveryMode: 'common', clientSecret: 'replacement', version: 1 })))
  })

  it('takes a target through draft, test, activation, and an explicitly approved first-admin invitation', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign })
    renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    expect(screen.queryByLabelText('Target organization ID')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Sandbox identity' } })
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'https://issuer.example/' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'client-id' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'client-secret' } })
    fireEvent.change(screen.getByLabelText('Auth0 organization ID (optional)'), { target: { value: 'org-sandbox-b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save connection draft' }))
    await waitFor(() => expect(api.draft).toHaveBeenCalledWith(expect.objectContaining({ capability: 'capability-opaque', clientSecret: 'client-secret', version: 0 })))
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    fireEvent.click(screen.getByRole('button', { name: 'Test actual provider' }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://issuer.example/authorize?state=opaque'))
    api.status.mockResolvedValue(tested)
    fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
    await screen.findByRole('button', { name: 'Activate connection' })
    fireEvent.click(screen.getByRole('button', { name: 'Activate connection' }))
    await waitFor(() => expect(api.activate).toHaveBeenCalledWith('capability-opaque', 1, 1))
    expect(screen.getByText('Role: ADMIN')).toBeInTheDocument()
    expect(screen.getByText('Recipient: admin@example.test')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create first administrator invitation' }))
    const code = await screen.findByLabelText('First administrator invitation code')
    expect(code).toHaveAttribute('type', 'password')
    expect(code).toHaveValue('invite-code-secret')
    expect(screen.queryByText('invite-code-secret')).not.toBeInTheDocument()
    vi.unstubAllGlobals()
  })

  it('auto-resumes a callback target with no recipient and lets an expired capability be explicitly reacquired', async () => {
    api.begin.mockResolvedValueOnce({ provisioning: tested, capability: 'resume-capability' })
    renderProvisioning('/settings/authentication?provisioning_tenant=sandbox-b')
    await waitFor(() => expect(api.begin).toHaveBeenCalledWith('sandbox-b', ''))
    api.status.mockRejectedValueOnce(new Error('Provisioning capability expired.'))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('capability expired')
    api.begin.mockResolvedValueOnce({ provisioning: tested, capability: 'fresh-capability' })
    fireEvent.click(screen.getByRole('button', { name: 'Resume provisioning' }))
    await waitFor(() => expect(api.begin).toHaveBeenLastCalledWith('sandbox-b', ''))
  })

  it('resumes the callback target after StrictMode replays the mount effects', async () => {
    api.begin.mockResolvedValue({ provisioning: tested, capability: 'resume-capability' })
    render(<StrictMode><MemoryRouter initialEntries={['/settings/authentication?provisioning_tenant=sandbox-b']}><InitialOrganizationProvisioning /></MemoryRouter></StrictMode>)
    expect(await screen.findByRole('heading', { name: 'Provisioning reserved' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh status' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Activate connection' })).toBeEnabled()
  })

  it('retains the retryable form after begin fails and never persists its secret or capability', async () => {
    api.begin.mockRejectedValueOnce(new Error('Temporary failure')).mockResolvedValueOnce({ provisioning: initial, capability: 'capability-opaque' })
    const localWrite = vi.spyOn(localStorage, 'setItem')
    const sessionWrite = vi.spyOn(sessionStorage, 'setItem')
    renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Temporary failure')
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    expect(localWrite).not.toHaveBeenCalled()
    expect(sessionWrite).not.toHaveBeenCalled()
  })

  it('discards an unsaved client secret when the operator cancels a reserved provisioning flow', async () => {
    renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'client-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
  })

  it('does not navigate after the provisioning component unmounts during a late provider-test response', async () => {
    let resolveTest: (value: { authorizationURL: string }) => void = () => {}
    api.begin.mockResolvedValue({ provisioning: drafted, capability: 'capability-opaque' })
    api.test.mockImplementation(() => new Promise((resolve) => { resolveTest = resolve }))
    const assign = vi.fn()
    vi.stubGlobal('location', { assign })
    const view = renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    fireEvent.click(screen.getByRole('button', { name: 'Test actual provider' }))
    view.unmount()
    resolveTest({ authorizationURL: 'https://issuer.example/authorize?state=opaque' })
    await Promise.resolve()
    expect(assign).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it('resumes the pinned draft and corrects only its credential with the current connection version', async () => {
    api.begin.mockResolvedValue({ provisioning: drafted, capability: 'resume-capability' })
    const corrected = { ...drafted, version: 3, connection: { ...drafted.connection, draftRevision: 2, version: 2 } }
    api.draft.mockResolvedValue(corrected)
    renderProvisioning('/settings/authentication?provisioning_tenant=sandbox-b')
    const secret = await screen.findByLabelText('Client secret')
    expect(screen.getByLabelText('Issuer')).toHaveValue('https://issuer.example/')
    expect(screen.getByLabelText('Issuer')).toHaveAttribute('readonly')
    expect(screen.getByLabelText('Client ID')).toHaveValue('client-id')
    expect(screen.getByLabelText('Client ID')).toHaveAttribute('readonly')
    fireEvent.change(secret, { target: { value: 'corrected-client-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save corrected credential' }))
    await waitFor(() => expect(api.draft).toHaveBeenCalledWith(expect.objectContaining({
      capability: 'resume-capability', version: 1, clientId: 'client-id', issuer: 'https://issuer.example/', clientSecret: 'corrected-client-secret',
    })))
    await waitFor(() => expect(screen.getByLabelText('Client secret')).toHaveValue(''))
    expect(screen.getByRole('button', { name: 'Test actual provider' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Activate connection' })).not.toBeInTheDocument()
    api.status.mockResolvedValue({ ...corrected, state: 'tested', connection: { ...corrected.connection, testPassed: true } })
    fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
    expect(await screen.findByRole('button', { name: 'Activate connection' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Test actual provider' })).not.toBeInTheDocument()
  })

  it('allows an initial ordinary OIDC draft without an Auth0 organization restriction', async () => {
    renderProvisioning()
    fireEvent.change(screen.getByLabelText('Target organization ID'), { target: { value: 'sandbox-b' } })
    fireEvent.change(screen.getByLabelText('First administrator email'), { target: { value: 'admin@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin provisioning' }))
    await screen.findByText('Provisioning reserved')
    expect(screen.getByLabelText('Auth0 organization ID (optional)')).not.toBeRequired()
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Ordinary OIDC' } })
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'https://issuer.example/' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'client-id' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'existing-client-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save connection draft' }))
    await waitFor(() => expect(api.draft).toHaveBeenCalledWith(expect.objectContaining({ auth0OrganizationId: '', version: 0 })))
  })

})
