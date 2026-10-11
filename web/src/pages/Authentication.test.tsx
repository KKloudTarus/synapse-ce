import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Authentication } from './Authentication'
import { identityApi } from '../lib/api/identity'

vi.mock('../lib/api/identity', () => ({
  identityApi: {
    connections: vi.fn(),
    policy: vi.fn(),
    alerts: vi.fn(),
    bootstrap: vi.fn(),
    draftConnection: vi.fn(),
    testConnection: vi.fn(),
    activateConnection: vi.fn(),
    disableConnection: vi.fn(),
    savePolicy: vi.fn(),
    rehearse: vi.fn(),
    testAlert: vi.fn(),
    createRecoveryCode: vi.fn(),
  },
}))

vi.mock('../components/synapse/ConfirmDialog', () => ({
  ConfirmDialog: ({ open, title, onConfirm, onCancel }: { open: boolean; title: string; onConfirm: () => void; onCancel: () => void }) => open ? (
    <div role="dialog" aria-label={title}><button type="button" onClick={onConfirm}>Confirm</button><button type="button" onClick={onCancel}>Cancel</button></div>
  ) : null,
}))

const mockedIdentityApi = vi.mocked(identityApi)

describe('Authentication', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'connection-a',
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 2,
      draftRevision: 3,
      version: 7,
      testPassed: true,
    }])
    mockedIdentityApi.policy.mockResolvedValue({
      requirement: 'optional',
      version: 4,
      rehearsedAt: null,
      alertConfigured: true,
      graceCutoff: null,
    })
    mockedIdentityApi.alerts.mockResolvedValue([])
  })

  it('uses the draft revision when an administrator confirms activation', async () => {
    mockedIdentityApi.activateConnection.mockResolvedValue(undefined)
    render(<Authentication enabled />)

    await screen.findByText('Primary identity')
    fireEvent.click(screen.getByRole('button', { name: 'Activate' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(mockedIdentityApi.activateConnection).toHaveBeenCalledWith('connection-a', 3, 7, undefined))
  })

  it('keeps a generated recovery code in component state and clears it on acknowledgement', async () => {
    mockedIdentityApi.createRecoveryCode.mockResolvedValue('one-time-code')
    render(<Authentication enabled />)

    await screen.findByRole('heading', { name: 'Emergency recovery' })
    fireEvent.change(screen.getByLabelText('Membership ID'), { target: { value: 'membership-a' } })
    fireEvent.change(screen.getByLabelText('Person ID'), { target: { value: 'person-a' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate recovery code' }))

    await screen.findByText('one-time-code')
    expect(localStorage.getItem('recovery_code')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'I have copied it' }))
    expect(screen.queryByText('one-time-code')).not.toBeInTheDocument()
  })

  it('redirects a connection test to the server-approved OIDC destination', async () => {
    mockedIdentityApi.testConnection.mockResolvedValue({ authorizationURL: 'https://issuer.example/authorize?state=opaque' })
    const assign = vi.fn()
    vi.stubGlobal('location', { assign })
    render(<Authentication enabled />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://issuer.example/authorize?state=opaque'))
    vi.unstubAllGlobals()
  })

  it('shows the server error when a test has no authorization destination', async () => {
    mockedIdentityApi.testConnection.mockRejectedValue(new Error('The server did not return an authorization destination.'))
    render(<Authentication enabled />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('authorization destination')
  })

  it('does not expose bootstrap verification for an ordinary SSO administrator', async () => {
    render(<Authentication enabled />)
    await screen.findByRole('heading', { name: 'Administrator verification' })
    expect(screen.queryByRole('button', { name: 'Verify administrator session' })).not.toBeInTheDocument()
    expect(screen.getByText(/Signed-in administrators use their current SSO proof/)).toBeInTheDocument()
  })
})
