import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../lib/api'
import { TicketsPanel } from './TicketsPanel'

vi.mock('../../../lib/api', () => ({ api: { findingTickets: vi.fn(), projectSourceFindingTickets: vi.fn(), ticketObservations: vi.fn(), projectSourceFindingTicketObservations: vi.fn(), me: vi.fn(), listIntegrations: vi.fn(), listIntegrationProviders: vi.fn(), previewTicket: vi.fn(), previewProjectSourceFindingTicket: vi.fn(), submitTicket: vi.fn(), submitProjectSourceFindingTicket: vi.fn(), linkTicket: vi.fn(), linkProjectSourceFindingTicket: vi.fn(), unlinkTicket: vi.fn(), unlinkProjectSourceFindingTicket: vi.fn(), reconcileTicketIntent: vi.fn(), retryTicketIntent: vi.fn() } }))
vi.mock('../../../lib/api/client', () => ({ newIdempotencyKey: () => 'request-key' }))

const ticketData = (over: Record<string, unknown> = {}) => ({
  links: [], intents: [], mappings: [{ id: 'mapping-1', integrationId: 'jira-1', scope: 'engagement' as const, scopeId: 'eng-1', projectKey: 'SEC', issueType: 'Bug', component: '', labels: [], priorityMap: {}, securityLevel: '', waiverReason: '', dataClass: 'summary' as const, locale: 'en' as const, summaryTemplate: '', descriptionTemplate: '', fieldValues: {}, transitionId: '', statusTransitions: {}, groupingMode: 'finding' as const, autoPushEnabled: false, autoPushMinSeverity: 'high' as const, version: 1 }], ...over,
})

describe('TicketsPanel', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData())
    vi.mocked(api.ticketObservations).mockResolvedValue({ observations: [], proposals: [], comments: [] })
    vi.mocked(api.projectSourceFindingTickets).mockResolvedValue(ticketData())
    vi.mocked(api.projectSourceFindingTicketObservations).mockResolvedValue({ observations: [], proposals: [], comments: [] })
    vi.mocked(api.me).mockResolvedValue({ role: 'reviewer' } as never)
    vi.mocked(api.listIntegrations).mockResolvedValue([{ id: 'jira-1', name: 'Private forge', provider: 'github-issues', endpoint: 'https://github.example' }] as never)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([{ provider: 'github-issues', name: 'GitHub Issues' }] as never)
  })

  it('requires a preview digest before it submits a durable ticket intent', async () => {
    vi.mocked(api.previewTicket).mockResolvedValue({ fields: {}, summary: 'SEC: SQL injection', description: 'Rendered plain text', dataClass: 'summary', digest: 'digest-1', mappingVersion: 1, provider: 'github-issues', endpoint: 'https://github.example' })
    vi.mocked(api.submitTicket).mockResolvedValue({ id: 'intent-1', state: 'queued', errorCode: '', version: 1, createdAt: '' })
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    expect(await screen.findByRole('button', { name: 'Preview ticket' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Submit ticket' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Preview ticket' }))
    expect(await screen.findByText('SEC: SQL injection')).toBeInTheDocument()
    expect(api.previewTicket).toHaveBeenCalledWith('eng-1', 'finding-1', 'mapping-1')
    fireEvent.click(screen.getByRole('button', { name: 'Submit ticket' }))
    fireEvent.click(screen.getByRole('button', { name: 'Submit ticket' }))
    await waitFor(() => expect(api.submitTicket).toHaveBeenCalledWith('eng-1', 'finding-1', 'mapping-1', 'digest-1', 'request-key'))
    expect(api.submitTicket).toHaveBeenCalledTimes(1)
    expect(await screen.findByText(/Ticket request recorded/)).toBeInTheDocument()
  })

  it('distinguishes colliding forge mappings and shows the snapshot-bound preview destination', async () => {
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData({ mappings: [
      { ...ticketData().mappings[0], id: 'github-map', integrationId: 'github', projectKey: 'owner/repo', issueType: 'issue', locale: 'en' },
      { ...ticketData().mappings[0], id: 'gitlab-map', integrationId: 'gitlab', projectKey: 'owner/repo', issueType: 'issue', locale: 'en' },
    ] }))
    vi.mocked(api.listIntegrations).mockResolvedValue([
      { id: 'github', name: 'GitHub sandbox', provider: 'github-issues', endpoint: 'https://github.example' },
      { id: 'gitlab', name: 'GitLab sandbox', provider: 'gitlab-issues', endpoint: 'https://stale.gitlab.example' },
    ] as never)
    vi.mocked(api.listIntegrationProviders).mockResolvedValue([
      { provider: 'github-issues', name: 'GitHub Issues' },
      { provider: 'gitlab-issues', name: 'GitLab Issues' },
    ] as never)
    vi.mocked(api.previewTicket).mockResolvedValue({ fields: { project: { key: 'owner/repo' }, issuetype: { id: 'issue' } }, summary: 'GitLab preview', description: '', dataClass: 'summary', digest: 'gitlab-digest', mappingVersion: 1, provider: 'gitlab-issues', endpoint: 'https://bound.gitlab.example' })

    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    expect(await screen.findByRole('option', { name: /GitHub Issues · GitHub sandbox · https:\/\/github\.example/ })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Ticket mapping'), { target: { value: 'gitlab-map' } })
    expect(screen.getByRole('option', { name: /GitLab Issues · GitLab sandbox · https:\/\/stale\.gitlab\.example/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Preview ticket' }))
    expect(await screen.findByText('https://bound.gitlab.example')).toBeInTheDocument()
    expect(screen.queryByText('https://stale.gitlab.example')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Submit ticket' })).toBeEnabled()
  })

  it('does not preview or submit when destination disclosure is unavailable', async () => {
    vi.mocked(api.listIntegrations).mockResolvedValue([] as never)
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    expect(await screen.findByText(/no longer resolves to a provider connection/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Preview ticket' })).toBeDisabled()
    expect(api.previewTicket).not.toHaveBeenCalled()
  })

  it('shows uncertain-create recovery and requires an explicit duplicate-risk acknowledgement before retry', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData({ intents: [{ id: 'intent-1', state: 'uncertain', errorCode: 'multiple_matches', version: 4, createdAt: '' }] }))
    vi.mocked(api.reconcileTicketIntent).mockResolvedValue({ id: 'intent-1', state: 'uncertain', errorCode: 'multiple_matches', version: 5, createdAt: '' })
    vi.mocked(api.retryTicketIntent).mockResolvedValue({ id: 'intent-1', state: 'queued', errorCode: '', version: 6, createdAt: '' })
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    expect(await screen.findByText(/No single provider match was proven/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reconcile' }))
    await waitFor(() => expect(api.reconcileTicketIntent).toHaveBeenCalledWith(expect.objectContaining({ id: 'intent-1', version: 4 })))
    fireEvent.click(screen.getByRole('button', { name: 'Retry…' }))
    const retry = await screen.findByRole('button', { name: 'Retry ticket request' })
    expect(retry).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.change(screen.getByLabelText('Retry reason'), { target: { value: 'Jira timeout verified by operator' } })
    expect(retry).toBeEnabled()
    fireEvent.click(retry)
    await waitFor(() => expect(api.retryTicketIntent).toHaveBeenCalledWith(expect.objectContaining({ id: 'intent-1' }), 'Jira timeout verified by operator'))
  })

  it('reloads the durable link after reconciliation completes without leaving actions busy', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.findingTickets).mockResolvedValueOnce(ticketData({ intents: [{ id: 'intent-1', state: 'uncertain', errorCode: 'zero_matches', version: 1, createdAt: '' }] })).mockResolvedValueOnce(ticketData({ links: [{ id: 'link-1', externalUrl: 'https://jira.example/browse/SEC-1', externalId: 'SEC-1', integrationId: 'jira-1', createdAt: '' }], intents: [{ id: 'intent-1', state: 'done', errorCode: '', version: 2, createdAt: '' }] }))
    vi.mocked(api.reconcileTicketIntent).mockResolvedValue({ id: 'intent-1', state: 'done', errorCode: '', version: 2, createdAt: '' })
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reconcile' }))
    expect(await screen.findByRole('link', { name: /SEC-1/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh tickets' })).toBeEnabled()
  })

  it('keeps ticket links readable but blocks preview and submit for a viewer', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'viewer' } as never)
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData({ links: [{ id: 'link-1', externalUrl: 'https://jira.example/browse/SEC-1', externalId: 'SEC-1', integrationId: 'jira-1', createdAt: '' }] }))
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    expect(await screen.findByRole('link', { name: /SEC-1/ })).toHaveAttribute('href', 'https://jira.example/browse/SEC-1')
    expect(screen.getByRole('button', { name: 'Preview ticket' })).toBeDisabled()
    expect(screen.getByText(/must preview or submit/)).toBeInTheDocument()
  })

  it('adds and removes a manual HTTPS link without requiring a Ticket mapping', async () => {
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData({ mappings: [] }))
    vi.mocked(api.linkTicket).mockResolvedValue({ id: 'manual-1', externalUrl: 'https://tracker.example/tickets/7', externalId: '', integrationId: '', createdAt: '' })
    vi.mocked(api.unlinkTicket).mockResolvedValue()
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    fireEvent.change(await screen.findByPlaceholderText('https://jira.example/browse/SEC-123'), { target: { value: 'https://tracker.example/tickets/7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Link' }))
    await waitFor(() => expect(api.linkTicket).toHaveBeenCalledWith('eng-1', 'finding-1', 'https://tracker.example/tickets/7'))
    fireEvent.click(await screen.findByRole('button', { name: /Remove ticket/ }))
    await waitFor(() => expect(api.unlinkTicket).toHaveBeenCalledWith('eng-1', 'finding-1', 'manual-1'))
  })

  it('ignores a late preview after the operator opens a different finding', async () => {
    let resolvePreview!: (value: { fields: Record<string, unknown>; summary: string; description: string; dataClass: string; digest: string; mappingVersion: number }) => void
    vi.mocked(api.previewTicket).mockReturnValue(new Promise((resolve) => { resolvePreview = resolve }) as never)
    const view = render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Preview ticket' }))
    await waitFor(() => expect(api.previewTicket).toHaveBeenCalledWith('eng-1', 'finding-1', 'mapping-1'))
    view.rerender(<TicketsPanel engagementId="eng-1" findingId="finding-2" />)
    resolvePreview({ fields: {}, summary: 'Old finding preview', description: '', dataClass: 'summary', digest: 'old', mappingVersion: 1 })
    await screen.findByRole('button', { name: 'Preview ticket' })
    await waitFor(() => expect(screen.queryByText('Old finding preview')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Submit ticket' })).not.toBeInTheDocument()
  })

  it('ignores destination discovery from a previous finding scope', async () => {
    let resolveOld!: (value: unknown) => void
    vi.mocked(api.listIntegrations)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }) as never)
      .mockResolvedValueOnce([{ id: 'jira-1', name: 'Fresh connection', provider: 'github-issues', endpoint: 'https://fresh.example' }] as never)
    const view = render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    await screen.findByRole('button', { name: 'Preview ticket' })
    view.rerender(<TicketsPanel engagementId="eng-1" findingId="finding-2" />)
    expect(await screen.findByText(/Destination: GitHub Issues · Fresh connection · https:\/\/fresh\.example/)).toBeInTheDocument()
    resolveOld([{ id: 'jira-1', name: 'Old connection', provider: 'github-issues', endpoint: 'https://old.example' }])
    await waitFor(() => expect(screen.queryByText('https://old.example')).not.toBeInTheDocument())
  })

  it('keeps one visible link when an idempotent manual link request is replayed', async () => {
    const link = { id: 'manual-1', externalUrl: 'https://tracker.example/tickets/7', externalId: '', integrationId: '', createdAt: '' }
    vi.mocked(api.findingTickets).mockResolvedValue(ticketData({ links: [link], mappings: [] }))
    vi.mocked(api.linkTicket).mockResolvedValue(link)
    render(<TicketsPanel engagementId="eng-1" findingId="finding-1" />)
    const input = await screen.findByPlaceholderText('https://jira.example/browse/SEC-123')
    fireEvent.change(input, { target: { value: link.externalUrl } })
    fireEvent.click(screen.getByRole('button', { name: 'Link' }))
    await waitFor(() => expect(input).toHaveValue(''))
    expect(api.linkTicket).toHaveBeenCalledTimes(1)
    expect(screen.getAllByRole('link', { name: link.externalUrl })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: `Remove ticket ${link.externalUrl}` })).toHaveLength(1)
  })

  it('uses Project-scoped ticket routes without an engagement identifier', async () => {
    vi.mocked(api.previewProjectSourceFindingTicket).mockResolvedValue({ fields: {}, summary: 'SEC: Project finding', description: 'Rendered plain text', dataClass: 'summary', digest: 'project-digest', mappingVersion: 1, provider: 'github-issues', endpoint: 'https://github.example' })
    vi.mocked(api.submitProjectSourceFindingTicket).mockResolvedValue({ id: 'intent-project', state: 'queued', errorCode: '', version: 1, createdAt: '' })
    render(<TicketsPanel projectKey="payments" findingId="finding-1" />)

    await screen.findByRole('button', { name: 'Preview ticket' })
    expect(api.projectSourceFindingTickets).toHaveBeenCalledWith('payments', 'finding-1')
    await waitFor(() => expect(api.projectSourceFindingTicketObservations).toHaveBeenCalledWith('payments', 'finding-1'))
    fireEvent.click(screen.getByRole('button', { name: 'Preview ticket' }))
    await waitFor(() => expect(api.previewProjectSourceFindingTicket).toHaveBeenCalledWith('payments', 'finding-1', 'mapping-1'))
    fireEvent.click(screen.getByRole('button', { name: 'Submit ticket' }))
    await waitFor(() => expect(api.submitProjectSourceFindingTicket).toHaveBeenCalledWith('payments', 'finding-1', 'mapping-1', 'project-digest', 'request-key'))
    expect(api.previewTicket).not.toHaveBeenCalled()
    expect(api.submitTicket).not.toHaveBeenCalled()
  })
})
