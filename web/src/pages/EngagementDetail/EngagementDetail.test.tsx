import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import type { AssessmentLifecycle } from '../../lib/types'
import { EngagementDetail } from './index'

vi.mock('../../lib/api', () => ({
  api: {
    getEngagement: vi.fn(),
    findings: vi.fn(),
    latestScan: vi.fn(),
    scanStatus: vi.fn(),
    importedSBOM: vi.fn(),
    uploadedSource: vi.fn(),
    startScan: vi.fn(),
    evidence: vi.fn(),
    listBusinessAssets: vi.fn(),
    assignEngagementAsset: vi.fn(),
    assessmentLifecycle: vi.fn(),
    listAssessmentClosureManifests: vi.fn(),
    me: vi.fn(),
    createRetest: vi.fn(),
    previewAssessmentRelationshipChange: vi.fn(),
    commitAssessmentRelationshipChange: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

const mockEngagement = {
  id: 'eng-123456',
  name: 'Acme Core Security Audit',
  client: 'Acme Corp',
  status: 'active',
  inScope: [{ kind: 'repo', value: 'github.com/acme/core-service' }],
  outOfScope: [],
  authorizedFrom: null,
  authorizedTo: null,
  roe: { allowedToolClasses: [], blackouts: [] },
  liveReconEnabled: false,
  requiresExplicitExecutionAuthorization: false,
  createdAt: '2026-08-15T00:00:00Z',
  businessAssetId: '',
}

const mockLifecycle: AssessmentLifecycle = {
  assessmentId: 'eng-123456',
  cycle: {
    id: 'cycle-1',
    name: 'Acme Core Security Audit',
    boundaryKind: 'standalone',
    businessAssetId: '',
    projectId: '',
    status: 'open',
    rootAssessmentId: 'eng-123456',
    selectedHeadAssessmentId: 'eng-123456',
    nextRetestNumber: 1,
    version: 1,
    createdAt: '2026-08-15T00:00:00Z',
    updatedAt: '2026-08-15T00:00:00Z',
    createdBy: 'operator',
    updatedBy: 'operator',
  },
  members: [{
    assessmentId: 'eng-123456',
    assessmentType: 'initial',
    predecessorAssessmentId: '',
    retestNumber: 0,
    relationshipVersion: 1,
    createdAt: '2026-08-15T00:00:00Z',
    createdBy: 'operator',
    archivedAt: null,
  }],
  branchHeads: [{
    assessmentId: 'eng-123456',
    assessmentType: 'initial',
    predecessorAssessmentId: '',
    retestNumber: 0,
    relationshipVersion: 1,
    createdAt: '2026-08-15T00:00:00Z',
    createdBy: 'operator',
    archivedAt: null,
  }],
}

describe('EngagementDetail Page Shell', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getEngagement).mockResolvedValue(mockEngagement)
    vi.mocked(api.findings).mockResolvedValue([])
    vi.mocked(api.latestScan).mockResolvedValue(null)
    vi.mocked(api.scanStatus).mockResolvedValue(null)
    vi.mocked(api.importedSBOM).mockResolvedValue(null as any)
    vi.mocked(api.uploadedSource).mockResolvedValue(null as any)
    vi.mocked(api.evidence).mockResolvedValue(null)
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
    vi.mocked(api.assessmentLifecycle).mockResolvedValue(mockLifecycle)
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([])
    vi.mocked(api.me).mockResolvedValue({ id: 'operator', name: 'Operator', role: 'member' })
  })

  it('renders breadcrumb, engagement name, and status pill', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('heading', { name: 'Acme Core Security Audit' })).toBeInTheDocument()
    expect(screen.getByLabelText('Breadcrumb')).toBeInTheDocument()
    expect(screen.getByText('Engagements')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getAllByTitle('github.com/acme/core-service').length).toBeGreaterThan(0)
  })

  it('groups lifecycle below scan controls in the Engagement summary, before the content tabs', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'operator', name: 'Operator', role: 'member', features: { assessmentLifecycleRead: true, assessmentLifecycleUIDefault: true } })
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes><Route path="/engagements/:id" element={<EngagementDetail />} /></Routes>
      </MemoryRouter>,
    )

    const lifecycle = await screen.findByRole('region', { name: 'Assessment lifecycle' })
    const summary = screen.getByRole('region', { name: 'Engagement summary' })
    expect(summary).toContainElement(screen.getByRole('heading', { level: 1, name: mockEngagement.name }))
    expect(summary).toContainElement(lifecycle)
    const scanButton = within(summary).getByRole('button', { name: 'Run scan' })
    expect(scanButton.compareDocumentPosition(lifecycle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(lifecycle.compareDocumentPosition(screen.getByRole('tablist', { name: 'Engagement Views' })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(within(lifecycle).getByRole('link', { name: 'Compare' })).toHaveAttribute('href', '/engagements/eng-123456/comparison')
    const disclosure = within(lifecycle).getByRole('button', { name: /Details & history/ })
    expect(disclosure).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('list', { name: 'Assessment Cycle history' })).not.toBeInTheDocument()
    fireEvent.click(disclosure)
    expect(within(lifecycle).getByRole('list', { name: 'Assessment Cycle history' })).toBeInTheDocument()
  })

  it('does not add an empty lifecycle section when tenant UI rollout is disabled', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes><Route path="/engagements/:id" element={<EngagementDetail />} /></Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('region', { name: 'Engagement summary' })).toBeInTheDocument()
    await waitFor(() => expect(api.me).toHaveBeenCalled())
    expect(screen.queryByRole('region', { name: 'Assessment lifecycle' })).not.toBeInTheDocument()
    expect(api.assessmentLifecycle).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeInTheDocument()
  })

  it('renders tab list with accessible roles and switches tabs', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
          <Route path="/engagements/:id/:tabSlug" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('tablist', { name: 'Engagement Views' })).toBeInTheDocument()

    const findingsTab = screen.getByRole('tab', { name: /Findings/i })
    expect(findingsTab).toBeInTheDocument()
    const comparisonTab = screen.getByRole('tab', { name: 'Comparison' })
    const supplyChainTab = screen.getByRole('tab', { name: /Supply Chain/i })
    expect(findingsTab.compareDocumentPosition(comparisonTab) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(comparisonTab.compareDocumentPosition(supplyChainTab) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    fireEvent.click(findingsTab)

    await waitFor(() => {
      // A single panel holds whichever tab is active, so its id is stable and the
      // active group tab is what labels it.
      const panel = screen.getByRole('tabpanel')
      expect(panel).toHaveAttribute('id', 'engagement-tabpanel')
      expect(panel).toHaveAttribute('aria-labelledby', 'tab-findings')
    })
    expect(screen.queryByRole('button', { name: 'Comparison' })).not.toBeInTheDocument()
  })

  it('moves between tabs with the arrow keys and keeps one tab stop', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
          <Route path="/engagements/:id/:tabSlug" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    const tablist = await screen.findByRole('tablist', { name: 'Engagement Views' })
    const tabs = screen.getAllByRole('tab')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    // Roving tabindex: exactly one tab is in the tab order.
    expect(tabs.filter((tab) => tab.getAttribute('tabindex') === '0')).toHaveLength(1)

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    await waitFor(() => expect(screen.getAllByRole('tab')[1]).toHaveAttribute('aria-selected', 'true'))
    expect(screen.getAllByRole('tab')[1]).toHaveFocus()

    fireEvent.keyDown(tablist, { key: 'End' })
    await waitFor(() => {
      const all = screen.getAllByRole('tab')
      expect(all[all.length - 1]).toHaveAttribute('aria-selected', 'true')
    })

    // End wraps forward to the first tab, Home returns to it directly.
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    await waitFor(() => expect(screen.getAllByRole('tab')[0]).toHaveAttribute('aria-selected', 'true'))
  })

  it('renders not found state when engagement does not exist', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue(null as any)

    render(
      <MemoryRouter initialEntries={['/engagements/non-existent']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByText('Engagement not found')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Back to engagements/i })).toBeInTheDocument()
  })

  it('locks scan settings to an uploaded source package', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue({
      ...mockEngagement,
      inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'a'.repeat(64)}` }],
    })
    vi.mocked(api.uploadedSource).mockResolvedValue({
      filename: 'acme-source.tar.gz',
      size: 1024,
      sha256: 'a'.repeat(64),
      target: `uploaded-source/sha256/${'a'.repeat(64)}`,
      uploadedBy: 'operator',
      uploadedAt: '2026-08-28T00:00:00Z',
    })
    vi.mocked(api.startScan).mockResolvedValue({
      id: 'scan-1', engagementId: 'eng-123456', target: `uploaded-source/sha256/${'a'.repeat(64)}`,
      kind: 'upload', status: 'running', stage: 'queued', progress: 0, error: '', startedAt: null, finishedAt: null, debugEvents: [],
    })

    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByText('Source: acme-source.tar.gz')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Scan settings' }))
    expect(await screen.findByText('Uploaded Source Active')).toBeInTheDocument()
    expect(screen.queryByLabelText('Scan target')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save & Run scan' }))
    await waitFor(() => expect(api.startScan).toHaveBeenCalledWith('eng-123456', '', 'upload', '', 'full', false))
  })

  it('shows source metadata failures with retry instead of treating them as a source-less engagement', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValueOnce(new ApiError(503, 'Source service unavailable')).mockResolvedValueOnce({
      versionId: 'source-version', filename: 'restored.zip', size: 123, sha256: 'c'.repeat(64), target: '',
      uploadedBy: 'operator', uploadedAt: '2026-09-08T00:00:00Z',
    })
    render(<MemoryRouter initialEntries={['/engagements/eng-123456']}><Routes>
      <Route path="/engagements/:id" element={<EngagementDetail />} />
    </Routes></MemoryRouter>)
    expect(await screen.findByText('Could not load source metadata: Source service unavailable')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Retry source lookup' }))
    expect(await screen.findByText('Source: restored.zip')).toBeVisible()
    expect(screen.queryByText('Could not load source metadata: Source service unavailable')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('Immutable source details'))
    expect(screen.getByLabelText(`Source SHA-256 ${'c'.repeat(64)}`)).toBeVisible()
  })

  it('does not show a source metadata error for a linked engagement without an uploaded package', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'No source package'))
    render(<MemoryRouter initialEntries={['/engagements/eng-123456']}><Routes>
      <Route path="/engagements/:id" element={<EngagementDetail />} />
    </Routes></MemoryRouter>)
    expect(await screen.findByRole('heading', { name: 'Acme Core Security Audit' })).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Retry source lookup' })).not.toBeInTheDocument()
  })

  it('locks uploaded source scans before package metadata loads', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue({
      ...mockEngagement,
      inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'b'.repeat(64)}` }],
    })
    vi.mocked(api.uploadedSource).mockImplementation(() => new Promise<never>(() => undefined))
    vi.mocked(api.startScan).mockResolvedValue({
      id: 'scan-2', engagementId: 'eng-123456', target: `uploaded-source/sha256/${'b'.repeat(64)}`,
      kind: 'upload', status: 'running', stage: 'queued', progress: 0, error: '', startedAt: null, finishedAt: null, debugEvents: [],
    })

    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('heading', { name: 'Acme Core Security Audit' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Scan settings' }))
    expect(await screen.findByText('Uploaded Source Active')).toBeInTheDocument()
    expect(screen.queryByLabelText('Scan target')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save & Run scan' }))
    await waitFor(() => expect(api.startScan).toHaveBeenCalledWith('eng-123456', '', 'upload', '', 'full', false))
  })

  it('guides an unauthorized Re-test to Settings without starting a scan', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue({ ...mockEngagement, requiresExplicitExecutionAuthorization: true } as never)
    render(<MemoryRouter initialEntries={['/engagements/eng-123456']}><Routes>
      <Route path="/engagements/:id" element={<EngagementDetail />} />
      <Route path="/engagements/:id/:tabSlug" element={<EngagementDetail />} />
    </Routes></MemoryRouter>)

    expect(await screen.findByText('Scan authorization required.')).toBeVisible()
    expect(screen.getByText('Set both authorization window bounds and allow SCA tools before scanning this Re-test.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeDisabled()
    expect(api.startScan).not.toHaveBeenCalled()

    const settings = screen.getByRole('link', { name: 'Configure in Settings' })
    expect(settings).toHaveAttribute('href', '/engagements/eng-123456/settings')
    fireEvent.click(settings)
    expect(await screen.findByText('Authorization window')).toBeVisible()
    expect(screen.getByText('Rules of engagement')).toBeVisible()
  })

  it('names only the missing SCA permission for a partially configured Re-test', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue({
      ...mockEngagement,
      requiresExplicitExecutionAuthorization: true,
      authorizedFrom: '2026-09-01T00:00:00Z',
      authorizedTo: '2026-10-01T00:00:00Z',
    } as never)
    render(<MemoryRouter initialEntries={['/engagements/eng-123456']}><Routes>
      <Route path="/engagements/:id" element={<EngagementDetail />} />
    </Routes></MemoryRouter>)

    expect(await screen.findByText('Allow SCA tools before scanning this Re-test.')).toBeVisible()
    expect(screen.queryByText('Set both authorization window bounds before scanning this Re-test.')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeDisabled()
  })
})

it('disables scan actions for a completed Assessment and explains the Re-test path', async () => {
  vi.mocked(api.getEngagement).mockResolvedValue({ ...mockEngagement, status: 'completed' } as never)
  render(<MemoryRouter initialEntries={['/engagements/eng-123456']}><Routes><Route path="/engagements/:id" element={<EngagementDetail />} /></Routes></MemoryRouter>)
  expect(await screen.findByRole('button', { name: 'Run scan' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Scan settings' })).toBeDisabled()
  expect(screen.getByText(/Completed Assessments keep their finalized Snapshots/)).toBeInTheDocument()
  expect(api.startScan).not.toHaveBeenCalled()
})
