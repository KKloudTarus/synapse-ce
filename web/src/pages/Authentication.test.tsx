import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Authentication } from './Authentication'
import { identityApi, type EnterpriseConnection } from '../lib/api/identity'
import { ApiError } from '../lib/api/client'

const auth = vi.hoisted(() => ({ currentUser: null as { credentialKind?: string } | null }))

vi.mock('../auth/AuthContext', () => ({
  useOptionalAuth: () => auth.currentUser ? { currentUser: auth.currentUser } : null,
}))

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
    auth.currentUser = null
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


  it('keeps the connection list when the organization has no policy row yet', async () => {
    mockedIdentityApi.policy.mockRejectedValue(new ApiError(404, 'not found', { code: 'not_found' }))
    render(<Authentication enabled />)
    expect(await screen.findByText('Primary identity')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText(/has not been enabled for shared identity/)).toBeInTheDocument()
  })

  it('surfaces a failed read and its retry while another read is still pending', async () => {
    // The alert read never settles. A page that waits for every read would stay on its
    // loading state with no way back, which is the regression this pins.
    mockedIdentityApi.alerts.mockReturnValue(new Promise(() => {}) as never)
    mockedIdentityApi.connections.mockRejectedValue(new ApiError(503, 'identity store unavailable'))
    render(<Authentication enabled />)
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('identity store unavailable')
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.queryByText('Loading authentication settings…')).not.toBeInTheDocument()
  })

  it('shows the missing-policy explanation while another read is still pending', async () => {
    // The connections read lands, the policy answers 404 and the alerts read never settles.
    // A page that waits for every read shows none of this.
    mockedIdentityApi.policy.mockRejectedValue(new ApiError(404, 'not found', { code: 'not_found' }))
    mockedIdentityApi.alerts.mockReturnValue(new Promise(() => {}) as never)
    render(<Authentication enabled />)
    expect(await screen.findByText(/has not been enabled for shared identity/)).toBeInTheDocument()
    expect(screen.getByText('Primary identity')).toBeInTheDocument()
    expect(screen.queryByText('Loading authentication settings…')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    // The section that has not answered says so for itself.
    expect(screen.getByText('Loading recovery alerts…')).toBeInTheDocument()
  })

  it('re-enables the controls when a refresh after a save does not finish', async () => {
    render(<Authentication enabled />)
    await screen.findByText('Primary identity')
    mockedIdentityApi.savePolicy.mockResolvedValue(undefined as never)
    // The refresh that follows the save: one read fails, another never answers.
    mockedIdentityApi.connections.mockRejectedValue(new ApiError(503, 'identity store unavailable'))
    mockedIdentityApi.alerts.mockReturnValue(new Promise(() => {}) as never)

    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(mockedIdentityApi.savePolicy).toHaveBeenCalled())
    // Every control stays usable: a refresh that never completes must not disable the page.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Rehearse recovery' })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Test alert' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeEnabled()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('identity store unavailable')
  })

  it('keeps a test-alert conflict visible through its refresh and clears it on Retry', async () => {
    mockedIdentityApi.testAlert.mockRejectedValueOnce(new ApiError(409, 'conflict'))
    render(<Authentication enabled />)

    fireEvent.click(await screen.findByRole('button', { name: 'Test alert' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('This request could not be completed. The latest settings have been loaded; review them and try again.')
    await waitFor(() => {
      expect(mockedIdentityApi.connections).toHaveBeenCalledTimes(2)
      expect(mockedIdentityApi.policy).toHaveBeenCalledTimes(2)
      expect(mockedIdentityApi.alerts).toHaveBeenCalledTimes(2)
    })
    expect(screen.getByRole('alert')).toHaveTextContent('This request could not be completed.')

    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }))
    await waitFor(() => {
      expect(mockedIdentityApi.connections).toHaveBeenCalledTimes(3)
      expect(mockedIdentityApi.policy).toHaveBeenCalledTimes(3)
      expect(mockedIdentityApi.alerts).toHaveBeenCalledTimes(3)
    })
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('keeps a requirement chosen while the policy refresh is still in flight', async () => {
    render(<Authentication enabled />)
    await screen.findByText('Primary identity')
    mockedIdentityApi.savePolicy.mockResolvedValue(undefined as never)
    let answerPolicy: (policy: unknown) => void = () => {}
    mockedIdentityApi.policy.mockReturnValue(new Promise((resolve) => { answerPolicy = resolve }) as never)

    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(mockedIdentityApi.savePolicy).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save policy' })).toBeEnabled())

    // The administrator changes the requirement while the refresh read is still outstanding.
    fireEvent.click(screen.getByRole('radio', { name: 'Required' }))
    expect(screen.getByRole('radio', { name: 'Required' })).toBeChecked()

    // The read answers with the value from before the edit. It carries the authoritative
    // version, and it must not put the old requirement back.
    answerPolicy({ requirement: 'optional', version: 5, rehearsedAt: null, alertConfigured: true, graceCutoff: null })
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Required' })).toBeChecked())
    expect(screen.getByRole('radio', { name: 'Optional' })).not.toBeChecked()

    mockedIdentityApi.savePolicy.mockClear()
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(mockedIdentityApi.savePolicy).toHaveBeenCalledWith(
      expect.objectContaining({ requirement: 'required', version: 5 }),
      undefined,
    ))
  })

  it('takes the refreshed requirement when nothing was edited while it was read', async () => {
    render(<Authentication enabled />)
    await screen.findByText('Primary identity')
    expect(screen.getByRole('radio', { name: 'Optional' })).toBeChecked()

    // A refresh that lands with nobody editing is authoritative, requirement included.
    mockedIdentityApi.policy.mockResolvedValue({
      requirement: 'required', version: 6, rehearsedAt: null, alertConfigured: true, graceCutoff: null,
    })
    mockedIdentityApi.rehearse.mockResolvedValue(undefined as never)
    fireEvent.click(screen.getByRole('button', { name: 'Rehearse recovery' }))
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Required' })).toBeChecked())
  })

  it('still reports a failure that is not the missing policy', async () => {
    mockedIdentityApi.connections.mockRejectedValue(new ApiError(503, 'identity store unavailable'))
    render(<Authentication enabled />)
    expect(await screen.findByRole('alert')).toHaveTextContent('identity store unavailable')
  })

  it('uses the draft revision when an administrator confirms activation', async () => {
    mockedIdentityApi.activateConnection.mockResolvedValue(undefined)
    render(<Authentication enabled />)

    await screen.findByText('Primary identity')
    fireEvent.click(screen.getByRole('button', { name: 'Activate' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(mockedIdentityApi.activateConnection).toHaveBeenCalledWith('connection-a', 3, 7, undefined))
  })

  it('saves an exact optional Auth0 organization ID in a connection draft', async () => {
    mockedIdentityApi.draftConnection.mockResolvedValue(undefined)
    render(<Authentication enabled />)

    await screen.findByText('Primary identity')
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Restricted identity' } })
    fireEvent.change(screen.getByLabelText('Issuer URL'), { target: { value: 'https://issuer.example' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'client-id' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'client-secret' } })
    fireEvent.change(screen.getByLabelText('Auth0 organization ID (optional)'), { target: { value: 'org_CaseSensitive' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }))

    await waitFor(() => expect(mockedIdentityApi.draftConnection).toHaveBeenCalledWith({
      displayName: 'Restricted identity',
      issuer: 'https://issuer.example',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      auth0OrganizationId: 'org_CaseSensitive',
    }, undefined))
  })

  it('configures a pending legacy connection with its selected ID and version', async () => {
    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'legacy-connection',
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 1,
      draftRevision: 1,
      version: 1,
      testPassed: false,
      configurationPending: true,
      clientId: '',
    }])
    mockedIdentityApi.draftConnection.mockResolvedValue(undefined)
    render(<Authentication enabled />)

    fireEvent.click(await screen.findByRole('button', { name: 'Configure' }))
    expect(screen.getByRole('heading', { name: 'Configure legacy connection' })).toBeInTheDocument()
    expect(screen.getByLabelText('Issuer URL')).toHaveValue('https://issuer.example')
    expect(screen.getByLabelText('Issuer URL')).toHaveProperty('readOnly', true)
    expect(screen.getByLabelText('Auth0 organization ID (optional)')).toHaveProperty('readOnly', true)
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    expect(screen.getByLabelText('Client ID')).not.toHaveProperty('readOnly', true)

    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'first-client' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'first-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }))

    await waitFor(() => expect(mockedIdentityApi.draftConnection).toHaveBeenCalledWith({
      id: 'legacy-connection',
      version: 1,
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      clientId: 'first-client',
      clientSecret: 'first-secret',
      auth0OrganizationId: '',
    }, undefined))
  })

  it('allows only a secret correction after a pending legacy connection has a client ID', async () => {
    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'legacy-connection',
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 1,
      draftRevision: 2,
      version: 2,
      testPassed: false,
      configurationPending: true,
      clientId: 'pinned-client',
    }])
    render(<Authentication enabled />)

    fireEvent.click(await screen.findByRole('button', { name: 'Update secret' }))
    expect(screen.getByRole('heading', { name: 'Update legacy connection secret' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client ID')).toHaveValue('pinned-client')
    expect(screen.getByLabelText('Client ID')).toHaveProperty('readOnly', true)
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    expect(screen.getByLabelText('Issuer URL')).toHaveProperty('readOnly', true)
    expect(screen.getByLabelText('Auth0 organization ID (optional)')).toHaveProperty('readOnly', true)
  })

  it('does not offer legacy configuration controls for a native connection and clears a canceled secret', async () => {
    render(<Authentication enabled />)
    await screen.findByText('Primary identity')
    expect(screen.queryByRole('button', { name: 'Configure' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Update secret' })).not.toBeInTheDocument()

    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'legacy-connection',
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 1,
      draftRevision: 1,
      version: 1,
      testPassed: false,
      configurationPending: true,
      clientId: '',
    }])
    fireEvent.click(screen.getByRole('button', { name: 'Rehearse recovery' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Configure' }))
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'discard-me' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(screen.getByRole('heading', { name: 'Create connection draft' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
  })

  it('discards a stale selected legacy configuration after a conflict and requires reselect', async () => {
    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'legacy-connection',
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 1,
      draftRevision: 2,
      version: 2,
      testPassed: false,
      configurationPending: true,
      clientId: 'pinned-client',
    }])
    mockedIdentityApi.draftConnection.mockRejectedValueOnce(new ApiError(409, 'stale configuration'))
    render(<Authentication enabled />)

    fireEvent.click(await screen.findByRole('button', { name: 'Update secret' }))
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'discard-me' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('latest settings have been loaded')
    expect(screen.queryByText('Legacy connection configuration saved.')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Create connection draft' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    await waitFor(() => expect(mockedIdentityApi.connections).toHaveBeenCalledTimes(2))
  })

  it('clears a selected legacy configuration when a newer list is loaded', async () => {
    const selected = {
      id: 'legacy-connection', displayName: 'Imported identity', issuer: 'https://issuer.example', enabled: false,
      revision: 1, draftRevision: 2, version: 2, testPassed: false, configurationPending: true, clientId: 'pinned-client',
    }
    mockedIdentityApi.connections.mockResolvedValueOnce([selected]).mockResolvedValueOnce([{ ...selected, draftRevision: 3, version: 3 }])
    mockedIdentityApi.draftConnection.mockResolvedValue(undefined)
    render(<Authentication enabled />)

    fireEvent.click(await screen.findByRole('button', { name: 'Update secret' }))
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'replacement-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Rehearse recovery' }))
    await waitFor(() => expect(mockedIdentityApi.connections).toHaveBeenCalledTimes(2))
    expect(screen.getByRole('heading', { name: 'Create connection draft' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    expect(mockedIdentityApi.draftConnection).not.toHaveBeenCalled()
  })

  it('clears a legacy secret selected from an old row while a refresh is still pending', async () => {
    const oldConnection: EnterpriseConnection = {
      id: 'legacy-connection', displayName: 'Imported identity', issuer: 'https://issuer.example', enabled: false,
      revision: 1, draftRevision: 2, version: 2, testPassed: false, configurationPending: true, clientId: 'pinned-client',
    }
    let completeRefresh: (connections: EnterpriseConnection[]) => void = () => {}
    mockedIdentityApi.connections.mockResolvedValueOnce([oldConnection]).mockReturnValueOnce(new Promise((resolve) => {
      completeRefresh = resolve
    }) as never)
    render(<Authentication enabled />)

    await screen.findByRole('button', { name: 'Update secret' })
    fireEvent.click(screen.getByRole('button', { name: 'Rehearse recovery' }))
    await waitFor(() => expect(mockedIdentityApi.connections).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Update secret' }))
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'discard-me' } })
    expect(screen.getByRole('heading', { name: 'Update legacy connection secret' })).toBeInTheDocument()

    completeRefresh([{ ...oldConnection, enabled: true, draftRevision: 3, version: 3, configurationPending: undefined, clientId: undefined }])

    await waitFor(() => expect(screen.getByText(/Active · revision 3/)).toBeInTheDocument())
    expect(screen.getByRole('heading', { name: 'Create connection draft' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client secret')).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Update secret' })).not.toBeInTheDocument()
    expect(mockedIdentityApi.draftConnection).not.toHaveBeenCalled()
  })

  it('shows a saved Auth0 organization ID without rendering connection settings or secrets', async () => {
    mockedIdentityApi.connections.mockResolvedValue([{
      id: 'connection-a',
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 2,
      draftRevision: 3,
      version: 7,
      testPassed: true,
      auth0OrganizationId: 'org_CaseSensitive',
    }])
    render(<Authentication enabled />)

    expect(await screen.findByText('org_CaseSensitive')).toBeInTheDocument()
    expect(screen.queryByText('client-secret')).not.toBeInTheDocument()
    expect(screen.queryByText('Settings')).not.toBeInTheDocument()
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

  it('limits a recovery session to permitted connection repair controls', async () => {
    auth.currentUser = { credentialKind: 'break_glass' }
    mockedIdentityApi.policy.mockResolvedValue({
      requirement: 'required',
      version: 4,
      rehearsedAt: null,
      alertConfigured: true,
      graceCutoff: null,
    })
    render(<Authentication enabled />)

    await screen.findByText('Primary identity')
    expect(screen.getByText(/recovery session is the current administrator proof/)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Optional' })).toBeInTheDocument()
    expect(screen.queryByRole('radio', { name: 'Required' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Rehearse recovery' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Test alert' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Generate recovery code' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Emergency recovery' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Activate' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeDisabled()
    fireEvent.click(screen.getByRole('radio', { name: 'Optional' }))
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeEnabled()
  })
})
