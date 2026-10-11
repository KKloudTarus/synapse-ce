import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, type NotificationChannel, type NotificationDelivery } from '../../lib/api'
import { resetCapabilityCache } from '../../lib/capabilities'
import type { Capability, Integration, IntegrationOperation, IntegrationProviderDescriptor } from '../../lib/types'
import { channelHealth, channelLastError, ciHealth, IntegrationsHub } from './IntegrationsHub'

vi.mock('../../lib/api', async () => {
  const client = await vi.importActual<typeof import('../../lib/api/client')>('../../lib/api/client')
  return {
    ApiError: client.ApiError,
    api: {
      me: vi.fn(), listCapabilities: vi.fn(),
      listIntegrationProviders: vi.fn(), listIntegrations: vi.fn(), listIntegrationOperations: vi.fn(), startIntegrationOperation: vi.fn(),
      listConnectors: vi.fn(),
      listNotificationChannels: vi.fn(), notificationDeliveryPage: vi.fn(), testNotificationChannel: vi.fn(),
      listSIEMSinks: vi.fn(),
    },
  }
})

const provider: IntegrationProviderDescriptor = {
  provider: 'jenkins', name: 'Jenkins', description: '', capabilities: ['test_connection', 'discover_pipelines', 'read_runs'],
  configFields: [], secretFields: [],
}

const integration: Integration = {
  id: 'integration-1', provider: 'jenkins', name: 'Production Jenkins', endpoint: 'https://jenkins.example.com',
  config: {}, allowPrivateNetwork: false, pollIntervalSeconds: 300, enabled: true, archived: false,
  version: 1, connectionRevision: 1, credentialRevision: 1, credentialConfigured: true,
  createdAt: '2026-08-30T10:00:00Z', updatedAt: '2026-08-30T10:00:00Z',
}

const operation = (over: Partial<IntegrationOperation>): IntegrationOperation => ({
  id: 'op', integrationId: integration.id, type: 'test', state: 'succeeded', checkpoint: '',
  counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [],
  jobId: '', actor: 'admin', startedAt: null, finishedAt: '2026-09-01T10:00:00Z',
  createdAt: '2026-09-01T10:00:00Z', updatedAt: '2026-09-01T10:00:00Z', ...over,
})

const channel: NotificationChannel = {
  id: 'channel-1', name: 'Security Slack', type: 'slack', enabled: true, destination: 'hooks.slack.com',
  revision: 1, secret_version: 1, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
}

const delivery = (over: Partial<NotificationDelivery>): NotificationDelivery => ({
  id: 'delivery', event_id: 'event', channel_id: channel.id, channel_type: 'slack', redrive_fence: 0, matched_rule_ids: [],
  state: 'delivered', attempts: 1, created_at: '2026-09-02T00:00:00Z', updated_at: '2026-09-02T00:00:00Z', ...over,
})

const capability = (over: Partial<Capability> & { key: string }): Capability => ({
  name: over.key, enabled: true, switch: '', requires: [], values: [], planned: false, ...over,
})

function renderHub() {
  return render(<MemoryRouter><IntegrationsHub /></MemoryRouter>)
}

const group = async (name: string) => within(await screen.findByRole('region', { name }))

describe('IntegrationsHub', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    resetCapabilityCache()
    vi.mocked(api.me).mockResolvedValue({ id: 'u', name: 'Admin', role: 'admin' })
    vi.mocked(api.listCapabilities).mockResolvedValue(null)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([provider])
    vi.mocked(api.listIntegrations).mockResolvedValue([])
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([])
    vi.mocked(api.listConnectors).mockResolvedValue([])
    vi.mocked(api.listNotificationChannels).mockResolvedValue([])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [] })
    vi.mocked(api.listSIEMSinks).mockResolvedValue([])
  })

  it('shows a loading state until permissions and capabilities arrive', () => {
    vi.mocked(api.me).mockReturnValue(new Promise(() => {}))
    renderHub()
    expect(screen.getByText('Loading integrations…')).toBeInTheDocument()
  })

  it('shows an error when permissions cannot be read', async () => {
    vi.mocked(api.me).mockRejectedValue(new Error('session expired'))
    renderHub()
    expect(await screen.findByRole('alert')).toHaveTextContent('session expired')
  })

  it('groups integrations by capability in a fixed order', async () => {
    renderHub()
    await screen.findByRole('region', { name: 'CI/CD' })
    const headings = screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)
    expect(headings).toEqual(['CI/CD', 'Source control', 'Messaging', 'Ticketing', 'Documentation', 'SIEM'])
    expect(await (await group('CI/CD')).findByText('No CI/CD integrations yet')).toBeInTheDocument()
    expect(await (await group('Source control')).findByText('No source-control connectors yet')).toBeInTheDocument()
    expect(await (await group('Messaging')).findByText('No notification channels yet')).toBeInTheDocument()
    // No capability catalog: the planned groups still have nothing to configure in this build.
    expect((await group('Ticketing')).getByText('Ticketing is not available in this build yet')).toBeInTheDocument()
    const siem = await group('SIEM')
    expect(await siem.findByText('No SIEM destinations yet')).toBeInTheDocument()
    expect(siem.getByText('Available')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Manage CI/CD' })).toHaveAttribute('href', '/settings/integrations/ci')
    expect(screen.getByRole('link', { name: 'Manage connectors' })).toHaveAttribute('href', '/settings/connectors')
    expect(screen.getByRole('link', { name: 'Manage channels' })).toHaveAttribute('href', '/settings/alerting')
    expect(screen.getByRole('link', { name: 'Message templates' })).toHaveAttribute('href', '/settings/templates')
    expect(screen.getByRole('link', { name: 'Manage SIEM streams' })).toHaveAttribute('href', '/settings/siem')
  })

  it('renders a CI/CD card from the integration and its operation history, and tests it', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValue([integration, { ...integration, id: 'archived', name: 'Old Jenkins', archived: true }])
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([
      operation({ id: 'poll-ok', type: 'poll', finishedAt: '2026-09-01T09:00:00Z', createdAt: '2026-09-01T09:00:00Z' }),
      operation({ id: 'test-failed', state: 'failed', errors: ['Jenkins answered 401'], finishedAt: '2026-09-02T09:00:00Z', createdAt: '2026-09-02T09:00:00Z' }),
    ])
    vi.mocked(api.startIntegrationOperation).mockResolvedValue(operation({ id: 'queued', state: 'queued' }))
    renderHub()

    const card = within(await screen.findByRole('listitem', { name: 'Production Jenkins' }))
    expect(screen.queryByRole('listitem', { name: 'Old Jenkins' })).not.toBeInTheDocument()
    expect(card.getByText('Jenkins')).toBeInTheDocument()
    expect(card.getByText('https://jenkins.example.com')).toBeInTheDocument()
    expect(card.getByText('Error')).toBeInTheDocument()
    expect(card.getByText('Poll')).toBeInTheDocument()
    expect(card.getByText('Jenkins answered 401')).toBeInTheDocument()

    fireEvent.click(card.getByRole('button', { name: 'Test Production Jenkins' }))
    await waitFor(() => expect(api.startIntegrationOperation).toHaveBeenCalledWith('integration-1', 'test'))
    expect(await screen.findByText('Connection test queued for Production Jenkins.')).toBeInTheDocument()
    expect(api.listIntegrationOperations).toHaveBeenCalledTimes(2)
  })

  it('keeps a CI/CD card when its history cannot be read, marking the fields unavailable', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValue([{ ...integration, credentialConfigured: false }])
    vi.mocked(api.listIntegrationOperations).mockRejectedValue(new Error('boom'))
    renderHub()
    const card = within(await screen.findByRole('listitem', { name: 'Production Jenkins' }))
    expect(card.getAllByText('Not reported by this integration')).toHaveLength(3)
    expect(card.getByRole('button', { name: 'Test Production Jenkins' })).toBeDisabled()
    expect(card.getByText('Add credentials before testing.')).toBeInTheDocument()
  })

  it('says CI/CD is off when the integrations routes are absent, and shows other load errors', async () => {
    vi.mocked(api.listIntegrations).mockRejectedValue(new ApiError(404, 'not found'))
    vi.mocked(api.listNotificationChannels).mockRejectedValue(new ApiError(500, 'channel store unavailable'))
    renderHub()
    expect(await (await group('CI/CD')).findByText('CI/CD integrations are not enabled on this deployment')).toBeInTheDocument()
    expect(await (await group('Messaging')).findByRole('alert')).toHaveTextContent('channel store unavailable')
    expect(screen.queryByRole('link', { name: 'Manage CI/CD' })).not.toBeInTheDocument()
  })

  it('renders source-control connectors with health, success and error unavailable', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([
      { id: 'c1', name: 'Prod GitHub', provider: 'github', host: 'github.com', username: 'x-access-token', authKind: 'token', apiBase: '', createdAt: '', updatedAt: '' },
    ])
    renderHub()
    const card = within(await screen.findByRole('listitem', { name: 'Prod GitHub' }))
    expect(card.getByText('GitHub')).toBeInTheDocument()
    expect(card.getAllByText('Not reported by this integration')).toHaveLength(3)
    expect(card.queryByRole('button')).not.toBeInTheDocument()
  })

  it('says source control is off when the connector store is absent', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(null)
    renderHub()
    expect(await (await group('Source control')).findByText('Connectors are not enabled on this deployment')).toBeInTheDocument()
  })

  it('shows SIEM as off when the sink API is absent', async () => {
    vi.mocked(api.listSIEMSinks).mockResolvedValue(null)
    renderHub()
    expect(await (await group('SIEM')).findByText('SIEM streams are not enabled')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Manage SIEM streams' })).not.toBeInTheDocument()
  })

  it('renders a messaging card from channel deliveries and sends a test', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue([
      capability({ key: 'notifications', switch: 'SYNAPSE_NOTIFICATIONS_ENABLED' }),
      capability({ key: 'notifications.channel_types', values: ['webhook', 'slack', 'email'] }),
    ])
    vi.mocked(api.listNotificationChannels).mockResolvedValue([channel])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({
      items: [
        delivery({ id: 'd2', state: 'delivered', delivered_at: '2026-09-03T00:00:00Z' }),
        delivery({ id: 'd1', state: 'dead_letter', last_error: 'slack answered 404', updated_at: '2026-09-02T00:00:00Z' }),
      ],
    })
    vi.mocked(api.testNotificationChannel).mockResolvedValue({ delivery_id: 'd3', state: 'pending' })
    renderHub()

    const card = within(await screen.findByRole('listitem', { name: 'Security Slack' }))
    expect(api.notificationDeliveryPage).toHaveBeenCalledWith({ channel_id: 'channel-1' })
    expect(card.getByText('Healthy')).toBeInTheDocument()
    expect(card.getByText('slack answered 404')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About Messaging' }).parentElement).toHaveTextContent('This build delivers to: webhook, slack, email.')

    fireEvent.click(card.getByRole('button', { name: 'Test Security Slack' }))
    await waitFor(() => expect(api.testNotificationChannel).toHaveBeenCalledWith('channel-1'))
    expect(await screen.findByText('Test delivery queued for Security Slack (d3).')).toBeInTheDocument()
  })

  it('shows a paused channel as Paused even when its last delivery succeeded', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue([capability({ key: 'notifications', switch: 'SYNAPSE_NOTIFICATIONS_ENABLED' })])
    vi.mocked(api.listNotificationChannels).mockResolvedValue([{
      ...channel,
      health: { state: 'paused', paused_at: '2026-09-04T00:00:00Z', paused_reason: 'consecutive_permanent_failures', consecutive_failures: 5, last_failure_code: 'destination_blocked' },
    }])
    vi.mocked(api.notificationDeliveryPage).mockResolvedValue({ items: [delivery({ state: 'delivered' })] })
    renderHub()
    const card = within(await screen.findByRole('listitem', { name: 'Security Slack' }))
    expect(card.getByText('Paused')).toBeInTheDocument()
    expect(card.queryByText('Healthy')).not.toBeInTheDocument()
  })

  it('shows a disabled capability as off with its switch and planned ones as not available', async () => {
    vi.mocked(api.listCapabilities).mockResolvedValue([
      capability({ key: 'notifications', name: 'Tenant notifications', enabled: false, switch: 'SYNAPSE_NOTIFICATIONS_ENABLED' }),
      capability({ key: 'ticketing', name: 'Ticketing', enabled: false, planned: true }),
      capability({ key: 'docpublish', name: 'Documentation publishing', enabled: false, planned: true }),
    ])
    renderHub()
    const messaging = await group('Messaging')
    expect(messaging.getByText('Notifications are off')).toBeInTheDocument()
    expect(messaging.getByText(/Set SYNAPSE_NOTIFICATIONS_ENABLED=true/)).toBeInTheDocument()
    expect(messaging.getByText('Off')).toBeInTheDocument()
    expect(api.listNotificationChannels).not.toHaveBeenCalled()

    const ticketing = await group('Ticketing')
    expect(ticketing.getByText('Ticketing is not available in this build yet')).toBeInTheDocument()
    expect(ticketing.getByText('Not available yet')).toBeInTheDocument()
    expect((await group('Documentation')).getByText('Documentation is not available in this build yet')).toBeInTheDocument()
  })

  // #1358: everything the hub reads or tests needs manage_integrations, which integration_admin holds.
  it('shows an integration_admin every group and lets them run a test', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u', name: 'Integrator', role: 'integration_admin' })
    vi.mocked(api.listIntegrations).mockResolvedValue([integration])
    renderHub()
    const card = within(await screen.findByRole('listitem', { name: 'Production Jenkins' }))
    expect(card.getByRole('button', { name: 'Test Production Jenkins' })).toBeEnabled()
    expect(await (await group('Source control')).findByText('No source-control connectors yet')).toBeInTheDocument()
    expect(await (await group('Messaging')).findByText('No notification channels yet')).toBeInTheDocument()
    expect(await (await group('SIEM')).findByText('No SIEM destinations yet')).toBeInTheDocument()
    expect(screen.queryByText('Administrator access required')).not.toBeInTheDocument()
    expect(api.listConnectors).toHaveBeenCalled()
    expect(api.listNotificationChannels).toHaveBeenCalled()
    expect(api.listSIEMSinks).toHaveBeenCalled()
  })

  it('limits a non-admin to viewing CI/CD and never calls admin-only APIs', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u', name: 'Member', role: 'member' })
    vi.mocked(api.listIntegrations).mockResolvedValue([integration])
    renderHub()
    const card = within(await screen.findByRole('listitem', { name: 'Production Jenkins' }))
    expect(card.getByRole('button', { name: 'Test Production Jenkins' })).toBeDisabled()
    expect(card.getByText('Only tenant administrators and integration administrators can run a test.')).toBeInTheDocument()
    expect((await group('Source control')).getByText('Administrator access required')).toBeInTheDocument()
    expect((await group('Messaging')).getByText('Administrator access required')).toBeInTheDocument()
    expect((await group('SIEM')).getByText('Administrator access required')).toBeInTheDocument()
    expect(api.listConnectors).not.toHaveBeenCalled()
    expect(api.listNotificationChannels).not.toHaveBeenCalled()
    expect(api.listSIEMSinks).not.toHaveBeenCalled()
  })
})

describe('health derivation', () => {
  const now = Date.parse('2026-09-01T10:05:00Z')

  it('matches the CI/CD detail page', () => {
    const poll = operation({ type: 'poll', finishedAt: '2026-09-01T10:00:00Z' })
    expect(ciHealth(integration, [poll], now).label).toBe('Healthy')
    expect(ciHealth(integration, [], now).label).toBe('Stale')
    expect(ciHealth(integration, [], now, false).label).toBe('Healthy')
    expect(ciHealth({ ...integration, enabled: false }, [], now, false).label).toBe('Disabled')
    expect(ciHealth(integration, [operation({ state: 'running' }), poll], now).label).toBe('Running')
    expect(ciHealth(integration, [operation({ state: 'partial' }), poll], now).label).toBe('Partial')
  })

  it('reads the newest non-cancelled delivery for a channel', () => {
    expect(channelHealth(channel, []).label).toBe('No deliveries yet')
    expect(channelHealth({ ...channel, enabled: false }, [delivery({})]).label).toBe('Disabled')
    expect(channelHealth(channel, [delivery({ state: 'cancelled' }), delivery({ state: 'dead_letter' })]).label).toBe('Failing')
    expect(channelHealth(channel, [delivery({ state: 'retrying' })]).label).toBe('Retrying')
  })

  it('reads the worker pause before the delivery history', () => {
    const paused = { ...channel, health: { state: 'paused' as const, consecutive_failures: 5 } }
    expect(channelHealth(paused, [delivery({ state: 'delivered' })])).toEqual({ label: 'Paused', tone: 'danger' })
    expect(channelHealth({ ...paused, enabled: false }, []).label).toBe('Disabled')
    expect(channelHealth({ ...channel, health: { state: 'active', consecutive_failures: 2 } }, [delivery({})]).label).toBe('Healthy')
  })

  it('shows the failure that paused a channel when the delivery page has no newer error', () => {
    const paused = {
      ...channel,
      health: { state: 'paused' as const, consecutive_failures: 5, last_failure_code: 'http_404', last_failure_at: '2026-09-03T00:00:00Z' },
    }
    expect(channelLastError(paused, [])).toEqual({ at: '2026-09-03T00:00:00Z', detail: 'http_404' })
    // An older delivery error loses to the health record; a newer one wins.
    expect(channelLastError(paused, [delivery({ last_error: 'http_503', updated_at: '2026-09-02T00:00:00Z' })]).detail).toBe('http_404')
    expect(channelLastError(paused, [delivery({ last_error: 'http_503', updated_at: '2026-09-04T00:00:00Z' })]).detail).toBe('http_503')
    expect(channelLastError(channel, [])).toEqual({ at: null })
  })
})
