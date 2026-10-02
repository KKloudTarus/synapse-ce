import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Integration, IntegrationOperation, IntegrationProviderDescriptor } from '../../lib/types'
import { Integrations } from './Integrations'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    listIntegrationProviders: vi.fn(), listIntegrations: vi.fn(), listProjects: vi.fn(), getIntegration: vi.fn(),
    createIntegration: vi.fn(), updateIntegration: vi.fn(), setIntegrationEnabled: vi.fn(), archiveIntegration: vi.fn(),
    setIntegrationCredential: vi.fn(), deleteIntegrationCredential: vi.fn(), startIntegrationOperation: vi.fn(),
    listIntegrationOperations: vi.fn(), getIntegrationOperation: vi.fn(), cancelIntegrationOperation: vi.fn(),
    listIntegrationBindings: vi.fn(), createIntegrationBinding: vi.fn(), deleteIntegrationBinding: vi.fn(),
    listIntegrationExternalRuns: vi.fn(), configureInboundWebhook: vi.fn(),
  },
}))

// Radix Select uses browser pointer/scroll APIs absent from jsdom.
for (const name of ['scrollIntoView', 'hasPointerCapture', 'releasePointerCapture'] as const) {
  Object.defineProperty(HTMLElement.prototype, name, { configurable: true, value: vi.fn(() => false) })
}

const provider: IntegrationProviderDescriptor = {
  provider: 'jenkins', name: 'Jenkins', description: 'Read-only Jenkins integration',
  capabilities: ['test_connection', 'discover_pipelines', 'read_runs'], configFields: [],
  secretFields: [
    { name: 'username', label: 'Username', kind: 'text', required: true, description: '' },
    { name: 'api_token', label: 'API token', kind: 'password', required: true, description: '' },
  ],
}

const gitlabProvider: IntegrationProviderDescriptor = {
  provider: 'gitlab', name: 'GitLab', description: 'Inbound GitLab webhooks',
  capabilities: [], configFields: [], secretFields: [],
}

const gitlabIntegration: Integration = {
  id: 'integration-gitlab', provider: 'gitlab', name: 'GitLab inbound', endpoint: 'https://gitlab.example.com',
  config: {}, allowPrivateNetwork: false, pollIntervalSeconds: 300, enabled: false, archived: false,
  version: 1, connectionRevision: 1, credentialRevision: 0, credentialConfigured: false,
  createdAt: '2026-09-30T10:00:00Z', updatedAt: '2026-09-30T10:00:00Z',
}

const integration: Integration = {
  id: 'integration-1', provider: 'jenkins', name: 'Production Jenkins', endpoint: 'https://jenkins.example.com',
  config: {}, allowPrivateNetwork: false, pollIntervalSeconds: 300, enabled: false, archived: false,
  version: 1, connectionRevision: 1, credentialRevision: 1, credentialConfigured: true,
  createdAt: '2026-08-30T10:00:00Z', updatedAt: '2026-08-30T10:00:00Z',
}

const successfulTest: IntegrationOperation = {
  id: 'operation-1', integrationId: integration.id, type: 'test', state: 'succeeded', checkpoint: '',
  counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [],
  jobId: 'job-1', actor: 'admin', startedAt: '2026-08-30T10:01:00Z', finishedAt: '2026-08-30T10:01:01Z',
  createdAt: '2026-08-30T10:01:00Z', updatedAt: '2026-08-30T10:01:01Z',
}

const successfulDiscovery: IntegrationOperation = {
  ...successfulTest,
  id: 'operation-discover', type: 'discover', checkpoint: 'discovery-v1',
  counts: { ...successfulTest.counts, pipelines: 1 },
  pipelines: [{ externalKey: '/job/platform/job/main', name: 'main', fullName: 'platform/main', kind: 'pipeline', url: 'https://jenkins.example.com/job/platform/job/main' }],
}

const stalePoll: IntegrationOperation = {
  ...successfulTest,
  id: 'operation-poll-success', type: 'poll',
  finishedAt: '2026-08-30T08:00:00Z', updatedAt: '2026-08-30T08:00:00Z',
}

const partialPoll: IntegrationOperation = {
  ...successfulTest,
  id: 'operation-poll-partial', type: 'poll', state: 'partial',
  counts: { ...successfulTest.counts, runs: 1, unlinked: 1, errors: 1 },
  errors: ['One bound pipeline could not be refreshed.'],
  finishedAt: '2026-08-31T08:00:00Z', updatedAt: '2026-08-31T08:00:00Z',
}

describe('Integrations settings', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ id: 'u-admin', name: 'Admin', role: 'admin' } as never)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([provider])
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([])
    vi.mocked(api.listIntegrationBindings).mockResolvedValue([])
    vi.mocked(api.listIntegrationExternalRuns).mockResolvedValue([])
  })

  // #1358: an integration_admin operates an integration but cannot create one, edit its endpoint or
  // replace its credential; the server refuses those with 403 anyway.
  it('offers an integration_admin the operations but not the destination changes', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u-int', name: 'Integrator', role: 'integration_admin' } as never)
    vi.mocked(api.listIntegrations).mockResolvedValue([integration])
    vi.mocked(api.getIntegration).mockResolvedValue(integration)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([successfulTest])
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    expect(await screen.findByRole('button', { name: 'Test connection' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Archive' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add integration/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit configuration' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /credentials/ })).not.toBeInTheDocument()
  })

  it('creates an integration with descriptor-driven write-only credentials', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValueOnce([]).mockResolvedValue([integration])
    vi.mocked(api.createIntegration).mockResolvedValue(integration)
    vi.mocked(api.setIntegrationCredential).mockResolvedValue()
    vi.mocked(api.getIntegration).mockResolvedValue(integration)

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Add integration' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Production Jenkins' } })
    fireEvent.change(screen.getByLabelText(/^HTTPS endpoint/), { target: { value: 'https://jenkins.example.com' } })
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ci-reader' } })
    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'secret-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create integration' }))

    await waitFor(() => expect(api.createIntegration).toHaveBeenCalledWith(expect.objectContaining({ provider: 'jenkins', endpoint: 'https://jenkins.example.com' })))
  expect(api.setIntegrationCredential).toHaveBeenCalledWith(integration, { username: 'ci-reader', api_token: 'secret-token' })
  })

  it('handles loading, empty onboarding, and keyboard access', async () => {
    const user = userEvent.setup()
    let resolveProviders!: (providers: IntegrationProviderDescriptor[]) => void
    vi.mocked(api.listIntegrationProviders).mockReturnValue(new Promise((resolve) => { resolveProviders = resolve }))
    vi.mocked(api.listIntegrations).mockResolvedValue([])

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    expect(screen.getByText('Loading integrations…')).toBeInTheDocument()
    resolveProviders([provider])
    expect(await screen.findByRole('heading', { name: 'Add integration' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByText('No integrations configured')).toBeInTheDocument()

    const addButtons = screen.getAllByRole('button', { name: 'Add integration' })
    addButtons[0].focus()
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('heading', { name: 'Add integration' })).toBeInTheDocument()
  })

  it('renders a fatal provider loading failure as an alert', async () => {
    vi.mocked(api.listIntegrationProviders).mockRejectedValue(new Error('Provider catalog unavailable'))
    vi.mocked(api.listIntegrations).mockResolvedValue([])

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    expect(await screen.findByRole('alert')).toHaveTextContent('Provider catalog unavailable')
  })

  it('enables an inbound-only provider without credentials, tests, discovery or polling', async () => {
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([provider, gitlabProvider])
    vi.mocked(api.listIntegrations).mockResolvedValue([gitlabIntegration])
    vi.mocked(api.listProjects).mockResolvedValue([{ id: 'project-1', name: 'Platform', sourceBinding: { kind: 'git', value: 'https://gitlab.example.com/acme/app' } } as never])
    vi.mocked(api.getIntegration).mockResolvedValue(gitlabIntegration)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([])
    vi.mocked(api.setIntegrationEnabled).mockResolvedValue({ ...gitlabIntegration, enabled: true, version: 2 })

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    expect(await screen.findByText('Not required')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add credentials' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Discover' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Poll now' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Bind Project' })).toBeInTheDocument()
    expect(screen.queryByText('Run discovery to select a pipeline.')).not.toBeInTheDocument()

    const enable = screen.getByRole('button', { name: 'Enable' })
    expect(enable).toBeEnabled()
    fireEvent.click(enable)
    await waitFor(() => expect(api.setIntegrationEnabled).toHaveBeenCalledWith(gitlabIntegration, true))
  })

  it.each(['gitlab', 'bitbucket'])('offers only Git projects for the inbound %s binding', async (providerSlug) => {
    const inboundIntegration = { ...gitlabIntegration, provider: providerSlug }
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{ ...gitlabProvider, provider: providerSlug }])
    vi.mocked(api.listIntegrations).mockResolvedValue([inboundIntegration])
    vi.mocked(api.getIntegration).mockResolvedValue(inboundIntegration)
    vi.mocked(api.listProjects).mockResolvedValue([
      { id: 'git-project', name: 'Git app', sourceBinding: { kind: 'git', value: 'https://gitlab.example.com/org/app' } } as never,
      { id: 'local-project', name: 'Local checkout', sourceBinding: { kind: 'local', value: '/repo' } } as never,
    ])
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    const user = userEvent.setup()
    await user.click(await screen.findByLabelText('Synapse Project'))
    expect(await screen.findByRole('option', { name: 'Git app' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Local checkout' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('option', { name: 'Git app' }))
    await user.click(screen.getByRole('button', { name: 'Bind Project' }))
    await waitFor(() => expect(api.createIntegrationBinding).toHaveBeenCalledWith(inboundIntegration.id, 'git-project', '/inbound/git-project', 'Git app'))
  })

  it('requires a successful test before enabling and never renders stored plaintext', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValue([integration])
    vi.mocked(api.getIntegration).mockResolvedValue(integration)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([successfulTest])
    vi.mocked(api.setIntegrationEnabled).mockResolvedValue({ ...integration, enabled: true, version: 2 })

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    const enable = await screen.findByRole('button', { name: 'Enable' })
    await waitFor(() => expect(enable).toBeEnabled())
    fireEvent.click(enable)
    await waitFor(() => expect(api.setIntegrationEnabled).toHaveBeenCalledWith(integration, true))

    fireEvent.click(screen.getByRole('button', { name: 'Replace credentials' }))
    expect(screen.getByLabelText('Username')).toHaveValue('')
    expect(screen.getByLabelText('API token')).toHaveValue('')
    expect(screen.queryByDisplayValue('secret-token')).not.toBeInTheDocument()
  })

  it('shows stale partial health while preserving the last successful discovery', async () => {
    const enabledIntegration = { ...integration, enabled: true }
    vi.mocked(api.listIntegrations).mockResolvedValue([enabledIntegration])
    vi.mocked(api.getIntegration).mockResolvedValue(enabledIntegration)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([partialPoll, stalePoll, successfulDiscovery, successfulTest])

    render(<MemoryRouter><Integrations /></MemoryRouter>)

    expect(await screen.findByText('stale')).toBeInTheDocument()
    expect(await screen.findByText('One bound pipeline could not be refreshed.')).toBeInTheDocument()
    expect(await screen.findByLabelText('Discovered pipeline')).toBeInTheDocument()
    expect(screen.queryByText('Run discovery to select a pipeline.')).not.toBeInTheDocument()
    expect(screen.getByText('partial')).toBeInTheDocument()
  })

  it('ignores detail responses from a previously selected integration', async () => {
    const secondary = { ...integration, id: 'integration-2', name: 'Secondary Jenkins', endpoint: 'https://secondary.example.com', version: 9 }
    const lateOperation = { ...successfulTest, id: 'operation-late', integrationId: integration.id, state: 'failed' as const, errors: ['Late primary response'] }
    const currentOperation = { ...successfulTest, id: 'operation-current', integrationId: secondary.id, state: 'failed' as const, errors: ['Current secondary response'] }
    let resolvePrimary!: (value: Integration) => void
    vi.mocked(api.listIntegrations).mockResolvedValue([integration, secondary])
    vi.mocked(api.getIntegration).mockImplementation((id) => id === integration.id ? new Promise((resolve) => { resolvePrimary = resolve }) : Promise.resolve(secondary))
    vi.mocked(api.listIntegrationOperations).mockImplementation((id) => Promise.resolve(id === integration.id ? [lateOperation] : [currentOperation]))

    render(<MemoryRouter><Integrations /></MemoryRouter>)
    await screen.findByRole('button', { name: /Secondary Jenkins/ })
    fireEvent.click(screen.getByRole('button', { name: /Secondary Jenkins/ }))
    expect((await screen.findAllByText('Current secondary response')).length).toBeGreaterThan(0)

    await act(async () => {
      resolvePrimary(integration)
      await Promise.resolve()
    })
    expect(screen.queryByText('Late primary response')).not.toBeInTheDocument()
    expect(screen.getAllByText('Current secondary response').length).toBeGreaterThan(0)
  })
  it('configures a Bitbucket webhook without polling credentials or tests', async () => {
    const bb = {...integration,provider:'bitbucket',name:'Bitbucket project',credentialConfigured:false}
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{...provider,provider:'bitbucket',name:'Bitbucket Cloud',capabilities:[],secretFields:[]}])
    vi.mocked(api.listIntegrations).mockResolvedValue([bb]);vi.mocked(api.getIntegration).mockResolvedValue(bb)
    vi.mocked(api.listIntegrationBindings).mockResolvedValue([{id:'binding',integrationId:bb.id,projectId:'p1',externalKey:'p1',externalName:'Repo',version:1} as never])
    vi.mocked(api.configureInboundWebhook).mockResolvedValue({path:'/api/v1/hooks/opaque-public-id',version:1,rotated:false})
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    const input = await screen.findByLabelText('Webhook secret')
    expect(screen.getByRole('button',{name:'Enable'})).toBeEnabled()
    expect(screen.queryByRole('button',{name:'Test connection'})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:'Poll now'})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:'Add credentials'})).not.toBeInTheDocument()
    const secret='bitbucket-random-webhook-secret-123456'
    fireEvent.change(input,{target:{value:secret}})
    fireEvent.click(screen.getByRole('button',{name:'Save webhook secret'}))
    expect(await screen.findByText('/api/v1/hooks/opaque-public-id')).toBeInTheDocument()
    expect(api.configureInboundWebhook).toHaveBeenCalledWith(bb.id,secret)
    expect(input).toHaveValue('')
    expect(screen.queryByText(secret)).not.toBeInTheDocument()
  })

  it('keeps the Bitbucket secret form unavailable without administrator permission', async () => {
    const bb={...integration,provider:'bitbucket'}
    vi.mocked(api.me).mockResolvedValue({id:'u-read',role:'readonly'} as never)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{...provider,provider:'bitbucket',name:'Bitbucket Cloud',capabilities:[],secretFields:[]}])
    vi.mocked(api.listIntegrations).mockResolvedValue([bb]);vi.mocked(api.getIntegration).mockResolvedValue(bb)
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    expect(await screen.findByText('An administrator must configure or rotate the webhook secret.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Webhook secret')).not.toBeInTheDocument()
    expect(api.configureInboundWebhook).not.toHaveBeenCalled()
  })

  it('shows Bitbucket configuration failures and clears the submitted secret', async () => {
    const bb={...integration,provider:'bitbucket'}
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{...provider,provider:'bitbucket',name:'Bitbucket Cloud',capabilities:[],secretFields:[]}])
    vi.mocked(api.listIntegrations).mockResolvedValue([bb]);vi.mocked(api.getIntegration).mockResolvedValue(bb)
    vi.mocked(api.listIntegrationBindings).mockResolvedValue([{id:'binding',projectId:'p1'} as never])
    vi.mocked(api.configureInboundWebhook).mockRejectedValue(new Error('Webhook service unavailable'))
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    const input=await screen.findByLabelText('Webhook secret')
    fireEvent.change(input,{target:{value:'bitbucket-random-webhook-secret-123456'}})
    fireEvent.click(screen.getByRole('button',{name:'Save webhook secret'}))
    expect(await screen.findByText('Webhook service unavailable')).toBeInTheDocument()
    expect(input).toHaveValue('')
  })

  it('validates webhook secrets by UTF-8 bytes and refuses surrounding whitespace', async () => {
    const bb = { ...integration, provider: 'bitbucket' }
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{ ...provider, provider: 'bitbucket', name: 'Bitbucket Cloud', capabilities: [], secretFields: [] }])
    vi.mocked(api.listIntegrations).mockResolvedValue([bb])
    vi.mocked(api.getIntegration).mockResolvedValue(bb)
    vi.mocked(api.listIntegrationBindings).mockResolvedValue([{ id: 'binding', projectId: 'p1' } as never])
    render(<MemoryRouter><Integrations /></MemoryRouter>)
    const input = await screen.findByLabelText('Webhook secret')
    const save = screen.getByRole('button', { name: 'Save webhook secret' })
    for (const [value, enabled] of [['é'.repeat(16), true], ['界'.repeat(43), false], ['a'.repeat(31), false], ['a'.repeat(128), true], ['a'.repeat(32) + ' ', false]] as const) {
      fireEvent.change(input, { target: { value } })
      if (enabled) expect(save).toBeEnabled()
      else expect(save).toBeDisabled()
    }
    expect(api.configureInboundWebhook).not.toHaveBeenCalled()
  })

})
