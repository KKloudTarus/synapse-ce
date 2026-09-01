import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Integration, IntegrationOperation, IntegrationProviderDescriptor } from '../../lib/types'
import { Integrations } from './Integrations'

vi.mock('../../lib/api', () => ({
  api: {
    listIntegrationProviders: vi.fn(), listIntegrations: vi.fn(), listProjects: vi.fn(), getIntegration: vi.fn(),
    createIntegration: vi.fn(), updateIntegration: vi.fn(), setIntegrationEnabled: vi.fn(), archiveIntegration: vi.fn(),
    setIntegrationCredential: vi.fn(), deleteIntegrationCredential: vi.fn(), startIntegrationOperation: vi.fn(),
    listIntegrationOperations: vi.fn(), getIntegrationOperation: vi.fn(), cancelIntegrationOperation: vi.fn(),
    listIntegrationBindings: vi.fn(), createIntegrationBinding: vi.fn(), deleteIntegrationBinding: vi.fn(),
    listIntegrationExternalRuns: vi.fn(),
  },
}))

const provider: IntegrationProviderDescriptor = {
  provider: 'jenkins', name: 'Jenkins', description: 'Read-only Jenkins integration',
  capabilities: ['test_connection', 'discover_pipelines', 'read_runs'], configFields: [],
  secretFields: [
    { name: 'username', label: 'Username', kind: 'text', required: true, description: '' },
    { name: 'api_token', label: 'API token', kind: 'password', required: true, description: '' },
  ],
}

const integration: Integration = {
  id: 'integration-1', provider: 'jenkins', name: 'Production Jenkins', endpoint: 'https://jenkins.example.com',
  config: {}, allowPrivateNetwork: false, pollIntervalSeconds: 300, enabled: false, archived: false,
  version: 1, credentialConfigured: true, createdAt: '2026-08-30T10:00:00Z', updatedAt: '2026-08-30T10:00:00Z',
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
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([provider])
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([])
    vi.mocked(api.listIntegrationBindings).mockResolvedValue([])
    vi.mocked(api.listIntegrationExternalRuns).mockResolvedValue([])
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
    expect(api.setIntegrationCredential).toHaveBeenCalledWith(integration.id, { username: 'ci-reader', api_token: 'secret-token' })
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
})
