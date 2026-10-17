import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DocumentPublishingPanel } from './DocumentPublishingPanel'

vi.mock('../../../lib/api', () => ({ api: { me: vi.fn(), listAssessmentCycles: vi.fn() } }))
vi.mock('../../../lib/api/integrations', () => ({ integrationsApi: { listIntegrations: vi.fn() } }))
vi.mock('../../../lib/api/documents', () => ({ documentsApi: { listEngagementDocuments: vi.fn(), listProjectDocuments: vi.fn(), publish: vi.fn(), unpublish: vi.fn(), documentIntent: vi.fn() } }))
vi.mock('../../../components/synapse/ConfirmDialog', () => ({ ConfirmDialog: ({ open, onConfirm }: { open: boolean; onConfirm: () => void }) => open ? <button onClick={onConfirm}>Confirm permanent unpublish</button> : null }))

import { api } from '../../../lib/api'
import { integrationsApi } from '../../../lib/api/integrations'
import { documentsApi } from '../../../lib/api/documents'

afterEach(() => vi.clearAllMocks())
function ready(role = 'reviewer') { vi.mocked(api.me).mockResolvedValue({ role } as never); vi.mocked(api.listAssessmentCycles).mockResolvedValue({ items: [], nextCursor: '' } as never); vi.mocked(integrationsApi.listIntegrations).mockResolvedValue([{ id: 'confluence', name: 'Confluence', provider: 'confluence-cloud', enabled: true, archived: false, credentialConfigured: true }] as never); vi.mocked(documentsApi.listEngagementDocuments).mockResolvedValue([]); vi.mocked(documentsApi.listProjectDocuments).mockResolvedValue([]) }

describe('DocumentPublishingPanel', () => {
  it('derives the engagement source and does not expose destination controls', async () => {
    ready(); vi.mocked(documentsApi.publish).mockResolvedValue({ skipped: false, intent: { id: 'intent', state: 'pending' } } as never)
    render(<DocumentPublishingPanel engagementId="eng-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Publish report' }))
    await waitFor(() => expect(documentsApi.publish).toHaveBeenCalledWith(expect.objectContaining({ integrationId: 'confluence', sourceKind: 'engagement_report', scopeId: 'eng-1', sourceRef: 'engagement:eng-1' })))
    expect(screen.queryByLabelText(/space/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/group/i)).not.toBeInTheDocument()
  })
  it('hides write controls for non-review roles', async () => { ready('consultant'); render(<DocumentPublishingPanel engagementId="eng-1" />); expect(await screen.findByText(/reviewer or administrator/i)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Publish report' })).not.toBeInTheDocument() })
  it('confirms permanent unpublish before requesting the purge', async () => { ready(); vi.mocked(documentsApi.listEngagementDocuments).mockResolvedValue([{ id: 'link', remoteUrl: 'https://confluence.test/page', remoteVersion: 1, contentHash: 'a'.repeat(64) }] as never); vi.mocked(documentsApi.unpublish).mockResolvedValue({ skipped: false, intent: { id: 'purge', state: 'pending' } } as never); render(<DocumentPublishingPanel engagementId="eng-1" />); fireEvent.click(await screen.findByRole('button', { name: 'Unpublish' })); fireEvent.click(screen.getByRole('button', { name: 'Confirm permanent unpublish' })); await waitFor(() => expect(documentsApi.unpublish).toHaveBeenCalledWith('link', expect.any(String))) })
  it('derives a project summary and only offers completed cycles with a final manifest', async () => {
    ready()
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({ items: [
      { id: 'cycle-final', name: 'Final cycle', projectId: 'project-1', status: 'completed', activeClosureManifestId: 'manifest-1' },
      { id: 'cycle-open', name: 'Open cycle', projectId: 'project-1', status: 'open', activeClosureManifestId: 'manifest-2' },
      { id: 'cycle-other', name: 'Other project', projectId: 'project-2', status: 'completed', activeClosureManifestId: 'manifest-3' },
      { id: 'cycle-no-manifest', name: 'Unreleased', projectId: 'project-1', status: 'completed', activeClosureManifestId: '' },
    ], nextCursor: '' } as never)
    vi.mocked(documentsApi.publish).mockResolvedValue({ skipped: false, intent: { id: 'intent', state: 'pending' } } as never)
    render(<DocumentPublishingPanel project={{ id: 'project-1', key: 'quality' }} />)
    const source = await screen.findByLabelText('Report source')
    expect(source).toHaveTextContent('Project quality summary')
    expect(source).toHaveTextContent('Closure report · Final cycle')
    expect(source).not.toHaveTextContent('Open cycle')
    expect(source).not.toHaveTextContent('Other project')
    fireEvent.change(source, { target: { value: 'assessment-cycle:cycle-final' } })
    fireEvent.click(screen.getByRole('button', { name: 'Publish report' }))
    await waitFor(() => expect(documentsApi.publish).toHaveBeenCalledWith(expect.objectContaining({ sourceKind: 'assessment_closure_report', scopeId: 'project-1', sourceRef: 'assessment-cycle:cycle-final' })))
  })
})
