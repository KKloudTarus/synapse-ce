import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { JiraSettings } from './JiraSettings'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(), listIntegrationProviders: vi.fn(), listIntegrations: vi.fn(), listEngagements: vi.fn(), listProjects: vi.fn(),
    listTicketMappings: vi.fn(), jiraMetadata: vi.fn(), createTicketMapping: vi.fn(), updateTicketMapping: vi.fn(), deleteTicketMapping: vi.fn(),
    createIntegration: vi.fn(), setIntegrationCredential: vi.fn(), getIntegration: vi.fn(), setIntegrationEnabled: vi.fn(), startIntegrationOperation: vi.fn(), listIntegrationOperations: vi.fn(), getIntegrationOperation: vi.fn(),
  },
}))

const integration = { id: 'jira-1', provider: 'jira-cloud', name: 'Jira Cloud', endpoint: 'https://team.atlassian.net', archived: false, enabled: false, version: 1, connectionRevision: 1, credentialRevision: 0, credentialConfigured: true }
const mapping = { id: 'mapping-1', integrationId: 'jira-1', scope: 'project' as const, scopeId: 'project-1', projectKey: 'SEC', issueType: '10001', component: '', labels: [], priorityMap: {}, securityLevel: 'security-1', waiverReason: '', dataClass: 'summary' as const, locale: 'en' as const, summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', version: 1 }

describe('JiraSettings', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{ provider: 'jira-cloud', name: 'Jira Cloud', description: '', secretFields: [] }] as never)
    vi.mocked(api.listIntegrations).mockResolvedValue([integration] as never)
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-1', name: 'Quarterly assessment' }, { id: 'eng-2', name: 'Follow-up assessment' }] as never)
    vi.mocked(api.listProjects).mockResolvedValue([{ id: 'project-1', name: 'Platform' }] as never)
    vi.mocked(api.listTicketMappings).mockResolvedValue([])
    vi.mocked(api.jiraMetadata).mockResolvedValue({ projects: [{ id: 'SEC', name: 'Security' }], issueTypes: [{ id: '10001', name: 'Bug' }], priorities: [{ id: '1', name: 'Highest' }], securityLevels: [{ id: 'security-1', name: 'Internal' }], components: [], transitions: [{ id: '31', name: 'Start progress' }], fields: [{ id: 'customfield_101', name: 'Owning team', required: true, values: [], type: '', itemType: '', hasDefault: true }] })
    vi.mocked(api.createTicketMapping).mockResolvedValue(mapping)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([])
  })

  it.each([true, false])('keeps required reporter mapping blocked unless its authenticated identity is resolved (%s)', async (resolved) => {
    vi.mocked(api.jiraMetadata).mockResolvedValue({ projects: [{ id: 'SEC', name: 'Security' }], issueTypes: [{ id: '10001', name: 'Task' }], priorities: [], securityLevels: [{ id: 'security-1', name: 'Internal' }], components: [], transitions: [], fields: [{ id: 'reporter', name: 'Reporter', required: true, values: [], type: 'user', itemType: '', hasDefault: false }], resolvedReporter: resolved ? 'sandbox-admin' : undefined })
    render(<JiraSettings />)
    await screen.findByLabelText('Mapping scope')
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Jira project'), { target: { value: 'SEC' } })
    await waitFor(() => expect(screen.getByLabelText('Issue type')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Issue type'), { target: { value: '10001' } })
    await waitFor(() => expect(screen.getByLabelText('Security level')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Security level'), { target: { value: 'security-1' } })
    const save = screen.getByRole('button', { name: 'Create mapping' })
    if (resolved) {
      expect(screen.getByText('Reporter: sandbox-admin (authenticated Jira user).')).toBeInTheDocument()
      expect(save).toBeEnabled()
      expect(screen.queryByLabelText('Jira field Reporter')).not.toBeInTheDocument()
    } else {
      expect(save).toBeDisabled()
      expect(screen.getByText(/Required Jira fields have unsupported types/)).toBeInTheDocument()
    }
  })

  it('creates a project mapping with the selected Synapse project and no unsupported transition', async () => {
    render(<JiraSettings />)
    const scope = await screen.findByLabelText('Mapping scope')
    expect(screen.queryByLabelText('Transition')).not.toBeInTheDocument()
    expect(screen.getByText(/new tickets use Jira's initial workflow status/)).toBeInTheDocument()

    fireEvent.change(scope, { target: { value: 'project' } })
    await waitFor(() => expect(api.listTicketMappings).toHaveBeenCalledWith('project', 'project-1'))
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Jira project'), { target: { value: 'SEC' } })
    await waitFor(() => expect(screen.getByLabelText('Issue type')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Issue type'), { target: { value: '10001' } })
    await waitFor(() => expect(screen.getByLabelText('Security level')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Security level'), { target: { value: 'security-1' } })
    fireEvent.change(screen.getByLabelText('Jira priority for critical'), { target: { value: '1' } })
    fireEvent.change(screen.getByLabelText('Jira field Owning team'), { target: { value: 'blue-team' } })
    fireEvent.change(screen.getByLabelText('Jira priority for critical'), { target: { value: '' } })
    fireEvent.change(screen.getByLabelText('Jira field Owning team'), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create mapping' }))
    await waitFor(() => expect(api.createTicketMapping).toHaveBeenCalledWith(expect.objectContaining({ scope: 'project', scopeId: 'project-1', projectKey: 'SEC', issueType: '10001', securityLevel: 'security-1', priorityMap: {}, fieldValues: {}, dataClass: 'summary', summaryTemplate: '', descriptionTemplate: '', transitionId: '' })))
  })

  it('discovers transitions only for an explicit existing Jira issue and never saves one into the mapping', async () => {
    render(<JiraSettings />)
    await screen.findByLabelText('Mapping scope')
    await screen.findByRole('option', { name: 'Security' })
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Jira project'), { target: { value: 'SEC' } })
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledWith('jira-1', 'SEC', ''))
    await waitFor(() => expect(screen.getByLabelText('Issue type')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Issue type'), { target: { value: '10001' } })
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledWith('jira-1', 'SEC', '10001'))
    await waitFor(() => expect(screen.getByLabelText('Existing Jira issue key')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Existing Jira issue key'), { target: { value: 'SEC-123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Discover transitions' }))
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledWith('jira-1', 'SEC', '10001', 'SEC-123'))
    expect(await screen.findByText('Start progress')).toHaveProperty('tagName', 'LI')
    expect(screen.queryByLabelText('Transition')).not.toBeInTheDocument()
  })

  it('reloads metadata when selecting saved mappings with the same Jira destination', async () => {
    const first = { ...mapping, scope: 'engagement' as const, scopeId: 'eng-1' }
    const second = { ...first, id: 'mapping-2' }
    vi.mocked(api.listTicketMappings).mockResolvedValue([first, second])
    render(<JiraSettings />)

    const saved = await screen.findByLabelText('Saved Jira mappings')
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    const buttons = saved.querySelectorAll('button')
    expect(buttons).toHaveLength(2)

    const beforeFirstSelection = vi.mocked(api.jiraMetadata).mock.calls.length
    fireEvent.click(buttons[0])
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledTimes(beforeFirstSelection + 1))
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())

    const beforeSecondSelection = vi.mocked(api.jiraMetadata).mock.calls.length
    fireEvent.click(buttons[1])
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledTimes(beforeSecondSelection + 1))
    expect(screen.getByLabelText('Jira project')).toBeEnabled()
  })

  it('does not leave metadata loading when New mapping returns to an already blank destination', async () => {
    const blank = { ...mapping, projectKey: '', issueType: '', scope: 'engagement' as const, scopeId: 'eng-1' }
    vi.mocked(api.listTicketMappings).mockResolvedValue([blank])
    render(<JiraSettings />)

    const saved = await screen.findByLabelText('Saved Jira mappings')
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    const button = saved.querySelector('button')
    expect(button).not.toBeNull()
    const beforeSelection = vi.mocked(api.jiraMetadata).mock.calls.length
    fireEvent.click(button!)
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledTimes(beforeSelection + 1))
    await waitFor(() => expect(screen.getByRole('button', { name: 'New mapping' })).toBeEnabled())

    const beforeNewMapping = vi.mocked(api.jiraMetadata).mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: 'New mapping' }))
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledTimes(beforeNewMapping + 1))
    expect(screen.getByLabelText('Jira project')).toBeEnabled()
  })

  it('only enables a connection after the server reports a current successful test', async () => {
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([{ id: 'test-1', integrationId: 'jira-1', connectionRevision: 1, credentialRevision: 0, type: 'test', state: 'succeeded', checkpoint: '', counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [], jobId: '', actor: '', startedAt: null, finishedAt: null, createdAt: '', updatedAt: '' }] as never)
    vi.mocked(api.setIntegrationEnabled).mockResolvedValue({ ...integration, enabled: true, version: 2 } as never)
    render(<JiraSettings />)
    const enable = await screen.findByRole('button', { name: 'Enable' })
    await waitFor(() => expect(enable).toBeEnabled())
    expect(screen.getByText(/Last test: succeeded/)).toBeInTheDocument()
    fireEvent.click(enable)
    await waitFor(() => expect(api.setIntegrationEnabled).toHaveBeenCalledWith(expect.objectContaining({ id: 'jira-1', version: 1 }), true))
    expect(await screen.findByRole('button', { name: 'Disable' })).toBeInTheDocument()
  })

  it('clears actionable mapping state until the newly selected scope has loaded', async () => {
    let resolveSecond!: (value: typeof mapping[]) => void
    vi.mocked(api.listTicketMappings).mockImplementation((scope, scopeId) => {
      if (scope === 'engagement' && scopeId === 'eng-2') return new Promise((resolve) => { resolveSecond = resolve })
      return Promise.resolve([{ ...mapping, scope: 'engagement', scopeId: 'eng-1' }])
    })
    render(<JiraSettings />)
    const target = await screen.findByLabelText('Mapping scope target')
    await waitFor(() => expect(screen.getByLabelText('Jira connection')).toBeEnabled())
    fireEvent.change(target, { target: { value: 'eng-2' } })
    expect(screen.getByText('Loading Jira mappings…')).toBeInTheDocument()
    expect(screen.getByLabelText('Jira connection')).toBeDisabled()
    expect(screen.queryByLabelText('Saved Jira mappings')).not.toBeInTheDocument()
    resolveSecond([])
    await waitFor(() => expect(screen.queryByText('Loading Jira mappings…')).not.toBeInTheDocument())
    expect(screen.getByLabelText('Jira connection')).toBeEnabled()
  })

  it('renders discovered transitions as a readable list instead of a disabled select', async () => {
    render(<JiraSettings />)
    await screen.findByLabelText('Mapping scope')
    await screen.findByRole('option', { name: 'Security' })
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Jira project'), { target: { value: 'SEC' } })
    await waitFor(() => expect(screen.getByLabelText('Issue type')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Issue type'), { target: { value: '10001' } })
    await waitFor(() => expect(screen.getByLabelText('Existing Jira issue key')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Existing Jira issue key'), { target: { value: 'SEC-123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Discover transitions' }))
    expect(await screen.findByRole('list', { name: 'Discovered Jira transitions' })).toHaveTextContent('Start progress')
    expect(screen.queryByRole('combobox', { name: 'Discovered Jira transitions' })).not.toBeInTheDocument()
  })

  it('requires a refreshed operation result before enabling a queued connection test', async () => {
    const queued = { id: 'test-queued', integrationId: 'jira-1', connectionRevision: 1, credentialRevision: 0, type: 'test' as const, state: 'queued' as const, checkpoint: '', counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [], jobId: '', actor: '', startedAt: null, finishedAt: null, createdAt: '', updatedAt: '' }
    const succeeded = { ...queued, state: 'succeeded' as const }
    vi.mocked(api.startIntegrationOperation).mockResolvedValue(queued)
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([queued])
    vi.mocked(api.getIntegrationOperation).mockResolvedValue(succeeded)
    render(<JiraSettings />)
    const testConnection = await screen.findByRole('button', { name: 'Test connection' })
    fireEvent.click(testConnection)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeDisabled())
    fireEvent.click(screen.getByRole('button', { name: 'Refresh test result' }))
    await waitFor(() => expect(api.getIntegrationOperation).toHaveBeenCalledWith('test-queued'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeEnabled())
  })

  it('does not reuse a successful test after credentials replace its revision', async () => {
    let resolvePending!: (value: any[]) => void
    const pending = new Promise<any[]>((resolve) => { resolvePending = resolve })
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{ provider: 'jira-cloud', name: 'Jira Cloud', description: '', secretFields: [{ name: 'token', label: 'API token', kind: 'password', required: true, description: '' }] }] as never)
    vi.mocked(api.listIntegrationOperations).mockReturnValueOnce(pending as never).mockResolvedValue([])
    vi.mocked(api.setIntegrationCredential).mockResolvedValue(undefined)
    vi.mocked(api.getIntegration).mockResolvedValue({ ...integration, version: 2, connectionRevision: 2, credentialRevision: 1 } as never)
    render(<JiraSettings />)
    await screen.findByRole('button', { name: 'Replace credentials' })
    fireEvent.click(screen.getByRole('button', { name: 'Replace credentials' }))
    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'replacement' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save credentials' }))
    await waitFor(() => expect(api.getIntegration).toHaveBeenCalledWith('jira-1'))
    resolvePending([{ id: 'old-test', integrationId: 'jira-1', connectionRevision: 1, credentialRevision: 0, type: 'test', state: 'succeeded', checkpoint: '', counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [], jobId: '', actor: '', startedAt: null, finishedAt: null, createdAt: '', updatedAt: '' }])
    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeDisabled())
  })

  it('serializes duplicate create clicks behind one pending request', async () => {
    let resolvePending!: (value: any) => void
    const pending = new Promise<any>((resolve) => { resolvePending = resolve })
    vi.mocked(api.createIntegration).mockReturnValue(pending)
    render(<JiraSettings />)
    fireEvent.click(await screen.findByRole('button', { name: 'Add Jira' }))
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Jira Data Center' } })
    fireEvent.change(screen.getByLabelText('HTTPS endpoint'), { target: { value: 'https://jira.example.test' } })
    const create = screen.getByRole('button', { name: 'Create connection' })
    fireEvent.click(create); fireEvent.click(create)
    expect(api.createIntegration).toHaveBeenCalledTimes(1)
    resolvePending({ ...integration, id: 'jira-2' })
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Create connection' })).not.toBeInTheDocument())
  })

  it('initializes the existing mapping draft when the first Jira connection is created', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValue([])
    vi.mocked(api.createIntegration).mockResolvedValue({ ...integration, id: 'jira-new' } as never)
    render(<JiraSettings />)
    fireEvent.click(await screen.findByRole('button', { name: 'Add Jira' }))
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'First Jira' } })
    fireEvent.change(screen.getByLabelText('HTTPS endpoint'), { target: { value: 'https://jira.example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create connection' }))
    await waitFor(() => expect(api.jiraMetadata).toHaveBeenCalledWith('jira-new', '', ''))
    await waitFor(() => expect(screen.getByLabelText('Jira project')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Jira project'), { target: { value: 'SEC' } })
    await waitFor(() => expect(screen.getByLabelText('Issue type')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Issue type'), { target: { value: '10001' } })
    await waitFor(() => expect(screen.getByLabelText('Security level')).toBeEnabled())
    fireEvent.change(screen.getByLabelText('Security level'), { target: { value: 'security-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create mapping' }))
    await waitFor(() => expect(api.createTicketMapping).toHaveBeenCalledWith(expect.objectContaining({ integrationId: 'jira-new', scope: 'engagement', scopeId: 'eng-1' })))
  })

  it('shows a current failed refresh and clears the earlier queued notice', async () => {
    const queued = { id: 'test-queued', integrationId: 'jira-1', connectionRevision: 1, credentialRevision: 0, type: 'test' as const, state: 'queued' as const, checkpoint: '', counts: { pipelines: 0, runs: 0, linked: 0, unlinked: 0, errors: 0 }, errors: [], pipelines: [], jobId: '', actor: '', startedAt: null, finishedAt: null, createdAt: '', updatedAt: '' }
    vi.mocked(api.startIntegrationOperation).mockResolvedValue(queued)
    vi.mocked(api.getIntegrationOperation).mockResolvedValue({ ...queued, state: 'failed' as const, errors: ['Credential rejected'] })
    render(<JiraSettings />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText('Connection test queued for Jira Cloud.')).toBeInTheDocument()
    vi.mocked(api.listIntegrationOperations).mockResolvedValue([queued])
    fireEvent.click(screen.getByRole('button', { name: 'Refresh test result' }))
    await waitFor(() => expect(screen.getByText(/Last test: failed \(Credential rejected\)/)).toBeInTheDocument())
    expect(screen.queryByText('Connection test queued for Jira Cloud.')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Enable' })).toBeDisabled()
  })
})
