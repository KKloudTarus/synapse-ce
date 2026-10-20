import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { TicketProviderSettings } from './TicketProviderSettings'
vi.mock('../../lib/api', () => ({ api: { me: vi.fn(), listIntegrationProviders: vi.fn(), listIntegrations: vi.fn(), listEngagements: vi.fn(), listProjects: vi.fn(), ticketMetadata: vi.fn(), listTicketMappings: vi.fn(), createTicketMapping: vi.fn(), updateTicketMapping: vi.fn(), deleteTicketMapping: vi.fn() } }))
const connection = { id: 'forge', name: 'Private forge', provider: 'github-issues', endpoint: 'https://github.example', enabled: true, archived: false }
const descriptor = { provider: 'github-issues', name: 'GitHub Issues', description: 'Private repository issues.', capabilities: ['tickets'], secretFields: [] }
const metadata = { projects: [{ id: 'owner/repo', name: 'owner/repo' }], issueTypes: [{ id: 'issue', name: 'Issue' }], securityPolicy: 'private_repository', fields: [], components: [], priorities: [], securityLevels: [], transitions: [] }
function show() { return render(<MemoryRouter><TicketProviderSettings /></MemoryRouter>) }
beforeEach(() => {
 vi.resetAllMocks()
 vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
 vi.mocked(api.listIntegrationProviders).mockResolvedValue([descriptor] as never)
 vi.mocked(api.listIntegrations).mockResolvedValue([connection] as never)
 vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng', name: 'Dedicated sandbox' }] as never)
 vi.mocked(api.listProjects).mockResolvedValue([])
 vi.mocked(api.listTicketMappings).mockResolvedValue([])
 vi.mocked(api.ticketMetadata).mockResolvedValue(metadata as never)
})
describe('native ticket provider settings', () => {
 it('creates an approved native mapping without a Jira security waiver or duplicate forge credential', async () => {
  vi.mocked(api.createTicketMapping).mockImplementation(async (value) => ({ ...value, id: 'mapping', version: 1 }))
  show()
  expect(await screen.findByText(/Uses the SCM connector/)).toBeInTheDocument()
  const project = await screen.findByLabelText('Provider project')
  await waitFor(() => expect(project).toBeEnabled())
  expect(screen.getByRole('option', { name: 'owner/repo' })).toBeInTheDocument()
  fireEvent.change(project, { target: { value: 'owner/repo' } })
  await waitFor(() => expect(screen.getByLabelText('Provider issue type')).not.toBeDisabled())
  const metadataCallsBeforeType = vi.mocked(api.ticketMetadata).mock.calls.length
  fireEvent.change(screen.getByLabelText('Provider issue type'), { target: { value: 'issue' } })
  expect(vi.mocked(api.ticketMetadata)).toHaveBeenCalledTimes(metadataCallsBeforeType)
  expect(await screen.findByText(/Private repository required/)).toBeInTheDocument()
  await waitFor(() => expect(screen.getByRole('button', { name: 'Create ticket mapping' })).not.toBeDisabled())
  fireEvent.click(screen.getByRole('button', { name: 'Create ticket mapping' }))
  await waitFor(() => expect(api.createTicketMapping).toHaveBeenCalledWith(expect.objectContaining({ integrationId: 'forge', projectKey: 'owner/repo', issueType: 'issue', securityLevel: '', waiverReason: '', groupingMode: 'finding', statusTransitions: {} })))
  expect(await screen.findByText('Ticket mapping saved.')).toBeInTheDocument()
  expect(screen.queryByLabelText('Security waiver reason')).not.toBeInTheDocument()
 })
 it('shows a permission state and never discovers metadata for readonly users', async () => {
  vi.mocked(api.me).mockResolvedValue({ role: 'readonly' } as never)
  show(); expect(await screen.findByText('Ticket settings require integration access')).toBeInTheDocument()
  expect(api.ticketMetadata).not.toHaveBeenCalled()
 })
 it('disables an otherwise valid save action for an integration manager', async () => {
  vi.mocked(api.me).mockResolvedValue({ role: 'integration_admin' } as never)
  vi.mocked(api.listTicketMappings).mockResolvedValue([{ id: 'mapping', integrationId: 'forge', scope: 'engagement', scopeId: 'eng', projectKey: 'owner/repo', issueType: 'issue', component: '', labels: [], priorityMap: {}, securityLevel: '', waiverReason: '', dataClass: 'summary', locale: 'en', summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', statusTransitions: {}, groupingMode: 'finding', autoPushEnabled: false, autoPushMinSeverity: 'high', version: 1 }] as never)
  show()
  fireEvent.click(await screen.findByRole('button', { name: 'GitHub Issues · Private forge · https://github.example · owner/repo · issue (en)' }))
  await waitFor(() => expect(api.ticketMetadata).toHaveBeenCalled())
  expect(screen.getByRole('button', { name: 'Save ticket mapping' })).toBeDisabled()
  expect(api.updateTicketMapping).not.toHaveBeenCalled()
 })
 it('shows the empty destination state', async () => {
  vi.mocked(api.listIntegrations).mockResolvedValue([])
  show(); expect(await screen.findByText('No ticket provider connections')).toBeInTheDocument()
 })
 it('keeps an orphaned mapping available for inspection and deletion without a connection', async () => {
  const orphan = { id: 'removed-mapping', integrationId: 'removed', scope: 'engagement', scopeId: 'other', projectKey: 'owner/repo', issueType: 'issue', component: '', labels: [], priorityMap: {}, securityLevel: '', waiverReason: '', dataClass: 'summary', locale: 'en', summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', statusTransitions: {}, groupingMode: 'finding', autoPushEnabled: false, autoPushMinSeverity: 'high', version: 1 }
  vi.mocked(api.listIntegrations).mockResolvedValue([])
  vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng', name: 'Current sandbox' }, { id: 'other', name: 'Previous sandbox' }] as never)
  vi.mocked(api.listTicketMappings).mockImplementation(async (_scope, scopeId) => scopeId === 'other' ? [orphan] as never : [] as never)
  show()
  expect(await screen.findByText('No ticket provider connections')).toBeInTheDocument()
  fireEvent.change(await screen.findByLabelText('Ticket scope target'), { target: { value: 'other' } })
  const unresolved = await screen.findByRole('button', { name: 'Unresolved ticket destination' })
  fireEvent.click(unresolved)
  expect(await screen.findByRole('alert')).toHaveTextContent('no longer resolves to a provider connection')
  expect(screen.getByRole('button', { name: 'Save ticket mapping' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Delete mapping' }))
  await waitFor(() => expect(api.deleteTicketMapping).toHaveBeenCalledWith(orphan))
 })
 it('labels saved mappings with the provider, connection, endpoint, and mapping target', async () => {
  vi.mocked(api.listTicketMappings).mockResolvedValue([{ id: 'mapping', integrationId: 'forge', scope: 'engagement', scopeId: 'eng', projectKey: 'owner/repo', issueType: 'issue', locale: 'en' }] as never)
  show()
  expect(await screen.findByRole('button', { name: 'GitHub Issues · Private forge · https://github.example · owner/repo · issue (en)' })).toBeInTheDocument()
 })
 it('marks a saved mapping unresolved when its connection is no longer listed', async () => {
  vi.mocked(api.listTicketMappings).mockResolvedValue([{ id: 'mapping', integrationId: 'removed', scope: 'engagement', scopeId: 'eng', projectKey: 'owner/repo', issueType: 'issue', locale: 'en' }] as never)
  show()
  expect(await screen.findByRole('button', { name: 'Unresolved ticket destination' })).toBeInTheDocument()
 })
 it('keeps a missing native mapping visible but filters a known Jira mapping and locks its stale form', async () => {
  vi.mocked(api.listIntegrationProviders).mockResolvedValue([descriptor, { provider: 'jira-cloud', name: 'Jira Cloud', capabilities: ['tickets'], secretFields: [] }] as never)
  vi.mocked(api.listIntegrations).mockResolvedValue([connection, { id: 'jira', name: 'Jira workspace', provider: 'jira-cloud', endpoint: 'https://jira.example', enabled: true, archived: false }] as never)
  const mapping = { scope: 'engagement', scopeId: 'eng', component: '', labels: [], priorityMap: {}, securityLevel: '', waiverReason: '', dataClass: 'summary', summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', statusTransitions: {}, groupingMode: 'finding', autoPushEnabled: false, autoPushMinSeverity: 'high', version: 1 }
  vi.mocked(api.listTicketMappings).mockResolvedValue([
    { ...mapping, id: 'missing-native', integrationId: 'removed', projectKey: 'owner/repo', issueType: 'issue', locale: 'en' },
    { ...mapping, id: 'jira-mapping', integrationId: 'jira', projectKey: 'SEC', issueType: 'Bug', locale: 'en' },
  ] as never)
  show()
  const unresolved = await screen.findByRole('button', { name: 'Unresolved ticket destination' })
  expect(screen.queryByRole('button', { name: /Jira workspace|SEC.*Bug/ })).not.toBeInTheDocument()
  fireEvent.click(unresolved)
  expect(await screen.findByRole('alert')).toHaveTextContent('no longer resolves to a provider connection')
  expect(screen.getByLabelText('Provider project')).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Save ticket mapping' })).toBeDisabled()
 })
 it('fails closed on discovery error and keeps save disabled', async () => {
  vi.mocked(api.ticketMetadata).mockRejectedValue(new Error('Connector unavailable'))
  show(); expect(await screen.findByText('Connector unavailable')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Create ticket mapping' })).toBeDisabled()
 })
 it('ignores a late metadata response after switching connection', async () => {
  let resolveOld!: (value: typeof metadata) => void
  vi.mocked(api.listIntegrations).mockResolvedValue([connection, { ...connection, id: 'second', name: 'Second forge' }] as never)
  vi.mocked(api.ticketMetadata).mockImplementation((id) => id === 'forge' ? new Promise((resolve) => { resolveOld = resolve as typeof resolveOld }) : Promise.resolve({ ...metadata, projects: [{ id: 'second/repo', name: 'Second repository' }] } as never))
  show(); fireEvent.change(await screen.findByLabelText('Ticket connection'), { target: { value: 'second' } })
  expect(await screen.findByRole('option', { name: 'Second repository' })).toBeInTheDocument()
  resolveOld(metadata)
  await waitFor(() => expect(screen.queryByRole('option', { name: 'owner/repo' })).not.toBeInTheDocument())
 })
 it('clears the previous discovery error when switching to a healthy connection', async () => {
  vi.mocked(api.listIntegrations).mockResolvedValue([connection, { ...connection, id: 'second', name: 'Second forge' }] as never)
  vi.mocked(api.ticketMetadata).mockImplementation((id) => id === 'forge' ? Promise.reject(new Error('First connection unavailable')) : Promise.resolve(metadata as never))
  show()
  expect(await screen.findByText('First connection unavailable')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Ticket connection'), { target: { value: 'second' } })
  await waitFor(() => expect(screen.getByLabelText('Provider project')).toBeEnabled())
  expect(screen.getByRole('option', { name: 'owner/repo' })).toBeInTheDocument()
  expect(screen.queryByText('First connection unavailable')).not.toBeInTheDocument()
 })
})
