import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import type { AssessmentClosureManifest, AssessmentLifecycle, UploadedSourcePackage } from '../../lib/types'
import { AssessmentLifecyclePanel } from './AssessmentLifecyclePanel'

vi.mock('../../lib/api', () => ({
  api: {
    assessmentLifecycle: vi.fn(),
    listAssessmentClosureManifests: vi.fn(),
    me: vi.fn(),
    createRetest: vi.fn(),
    uploadedSource: vi.fn(),
    getEngagement: vi.fn(),
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

const sourcePackage: UploadedSourcePackage = {
  versionId: 'source-version-2', filename: 'payments-v2.zip', size: 2048, sha256: 'b'.repeat(64),
  target: `uploaded-source/sha256/${'b'.repeat(64)}`, uploadedBy: 'alice', uploadedAt: '2026-09-08T00:00:00Z',
}

const lifecycle: AssessmentLifecycle = {
  assessmentId: 'assessment-2',
  cycle: {
    id: 'cycle-1', name: 'Payments lifecycle', boundaryKind: 'asset_project', businessAssetId: 'asset-1', projectId: 'project-1',
    status: 'open', rootAssessmentId: 'assessment-0', selectedHeadAssessmentId: 'assessment-2', nextRetestNumber: 4, version: 7,
    createdAt: '2026-08-01T00:00:00Z', updatedAt: '2026-08-04T00:00:00Z', createdBy: 'alice', updatedBy: 'alice',
  },
  members: [
    { assessmentId: 'assessment-0', assessmentStatus: 'completed', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '2026-08-01T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-1', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 1, relationshipVersion: 2, createdAt: '2026-08-02T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-2', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-1', retestNumber: 2, relationshipVersion: 3, createdAt: '2026-08-03T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-3', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 3, relationshipVersion: 1, createdAt: '2026-08-04T00:00:00Z', createdBy: 'alice', archivedAt: '2026-08-05T00:00:00Z' },
  ],
  branchHeads: [
    { assessmentId: 'assessment-2', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-1', retestNumber: 2, relationshipVersion: 3, createdAt: '2026-08-03T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-3', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 3, relationshipVersion: 1, createdAt: '2026-08-04T00:00:00Z', createdBy: 'alice', archivedAt: '2026-08-05T00:00:00Z' },
  ],
}

function renderPanel(status = 'completed') {
  return render(<MemoryRouter><AssessmentLifecyclePanel assessmentId="assessment-2" engagementStatus={status} /></MemoryRouter>)
}

async function openHistory() {
  fireEvent.click(await screen.findByRole('button', { name: /Details & history/ }))
}

describe('AssessmentLifecyclePanel', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.assessmentLifecycle).mockResolvedValue(lifecycle)
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'No uploaded source'))
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [{ kind: 'repo', value: 'https://example.test/repo' }] } as never)
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([])
    vi.mocked(api.me).mockResolvedValue({ id: 'admin-1', name: 'Admin', role: 'admin', features: { assessmentLifecycleRead: true, assessmentLifecycleUIDefault: true } })
  })

  it('does not request lifecycle data when tenant UI rollout is disabled', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'admin-1', name: 'Admin', role: 'admin', features: { assessmentLifecycleRead: true, assessmentLifecycleUIDefault: false } })
    const { container } = renderPanel()
    await waitFor(() => expect(api.me).toHaveBeenCalledTimes(1))
    expect(api.assessmentLifecycle).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })

  it('renders a deterministic branched tree with distinct lifecycle badges', async () => {
    renderPanel()
    await openHistory()

    expect(await screen.findByRole('list', { name: 'Assessment Cycle history' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Initial · assessment-0' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Re-test #2 · assessment-2' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getAllByText('Selected head')).toHaveLength(2)
    expect(screen.getAllByText('Branch head')).toHaveLength(2)
    expect(screen.getAllByText('Display latest')).toHaveLength(2)
    expect(screen.getByText('Archived')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Assessment lifecycle breadcrumb' })).toHaveTextContent('Asset asset-1/Project project-1/Payments lifecycle/assessment-2')
  })

  it('marks final only from the active immutable manifest and requires reopen before another Re-test', async () => {
    vi.mocked(api.assessmentLifecycle).mockResolvedValue({
      ...lifecycle,
      cycle: { ...lifecycle.cycle, status: 'completed', activeClosureManifestId: 'manifest-active', activeClosureCycleVersion: 8 },
    })
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([closureManifest()])
    renderPanel()
    await openHistory()

    expect(await screen.findAllByText('Final')).toHaveLength(2)
    expect(screen.getByText(/Snapshot snapshot-2/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review reopen' })).toHaveAttribute('href', '/assessment-cycles/cycle-1')
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
  })

  it('reuses one idempotency key when a non-executable draft is retried', async () => {
    vi.mocked(api.createRetest).mockRejectedValueOnce(new Error('temporary network failure')).mockRejectedValueOnce(new Error('temporary network failure'))
    renderPanel()

    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByText('temporary network failure')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))

    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(2))
    const first = vi.mocked(api.createRetest).mock.calls[0]?.[1]
    const second = vi.mocked(api.createRetest).mock.calls[1]?.[1]
    if (!first || !second) throw new Error('expected two Create Re-test calls')
    expect(first).toEqual({ predecessorAssessmentId: 'assessment-2', source: undefined, scopeStrategy: 'copy', profileStrategy: 'none', idempotencyKey: expect.any(String) })
    expect(first.idempotencyKey).toBeTruthy()
    expect(second.idempotencyKey).toBe(first.idempotencyKey)
  })

  it('creates a draft without typing a name, dates, timezone, or authorization and opens it within the app', async () => {
    vi.mocked(api.createRetest).mockResolvedValue({
      engagement: { id: 'assessment-new', name: 'Payments Re-test' },
      cycle: lifecycle.cycle,
      member: { ...lifecycle.members[2], assessmentId: 'assessment-new', assessmentStatus: 'draft', retestNumber: 4 },
      inheritanceDiff: { scope: 'copy', authorization: 'explicit_only', roe: 'explicit_only', scannerProfile: 'none' },
      warnings: ['authorization_not_copied'],
    } as never)
    render(<MemoryRouter><Routes>
      <Route path="/" element={<AssessmentLifecyclePanel assessmentId="assessment-2" engagementStatus="completed" />} />
      <Route path="/engagements/assessment-new" element={<h1>New Re-test opened</h1>} />
    </Routes></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    const drawer = within(screen.getByRole('dialog'))
    expect(drawer.queryByRole('textbox')).not.toBeInTheDocument()
    for (const label of ['Name', 'Planned date', 'Authorized from', 'Authorized to', 'Timezone', 'Allowed tool classes']) {
      expect(drawer.queryByLabelText(label)).not.toBeInTheDocument()
    }
    expect(drawer.getByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Re-test #2')
    expect(drawer.getByText('Payments lifecycle')).toBeVisible()
    expect(drawer.getByText('Re-test #2 · Completed')).toBeVisible()
    expect(drawer.getByRole('button', { name: 'Cancel' })).toBeVisible()
    await waitFor(() => expect(drawer.getByRole('button', { name: 'Create Re-test' })).toBeEnabled())
    fireEvent.click(drawer.getByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByText('Re-test created')).toBeInTheDocument()
    expect(api.createRetest).toHaveBeenCalledTimes(1)
    expect(api.createRetest).toHaveBeenCalledWith('assessment-2', {
      predecessorAssessmentId: 'assessment-2', source: undefined, scopeStrategy: 'copy', profileStrategy: 'none', idempotencyKey: expect.any(String),
    })
    expect(screen.getByText('Payments Re-test')).toBeInTheDocument()
    expect(screen.getByText(/Configure execution authorization in Re-test Settings/)).toBeInTheDocument()
    expect(screen.getByText('Authorization Not Copied')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create Re-test' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Open Re-test' }))
    expect(await screen.findByRole('heading', { name: 'New Re-test opened' })).toBeInTheDocument()
  })

  it('validates a new archive and keeps identical retries stable while edited source commands get a new key', async () => {
    vi.mocked(api.uploadedSource).mockResolvedValue(sourcePackage)
    vi.mocked(api.createRetest).mockRejectedValue(new Error('temporary upload failure'))
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    fireEvent.click(await screen.findByRole('radio', { name: /Upload new source/ }))
    const upload = screen.getByLabelText('Re-test source archive')
    fireEvent.change(upload, { target: { files: [new File(['wrong type'], 'source.exe')] } })
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
    expect(api.createRetest).not.toHaveBeenCalled()
    fireEvent.change(upload, { target: { files: [] } })
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
    const source = new File(['new revision'], 'source.zip', { type: 'application/zip' })
    fireEvent.change(screen.getByLabelText('Re-test source archive'), { target: { files: [source] } })
    expect(await screen.findByText(/Ready to upload when the Re-test is created/)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Replace' })).toBeVisible()
    expect(screen.getByRole('checkbox', { name: 'Force update source' })).toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Remove source archive' }))
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Re-test source archive'), { target: { files: [source] } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByText('temporary upload failure')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(2))
    expect(vi.mocked(api.createRetest).mock.calls[1]?.[1]?.source).toBe(source)
    expect(vi.mocked(api.createRetest).mock.calls[0]?.[1]?.idempotencyKey).toBe(vi.mocked(api.createRetest).mock.calls[1]?.[1]?.idempotencyKey)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeEnabled())
    fireEvent.click(screen.getByRole('radio', { name: /Use current source/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(3))
    const edited = vi.mocked(api.createRetest).mock.calls[2]?.[1]
    expect(edited).toMatchObject({ sourceStrategy: 'reuse_current', sourceVersionId: 'source-version-2', source: undefined })
    expect(edited?.idempotencyKey).not.toBe(vi.mocked(api.createRetest).mock.calls[1]?.[1]?.idempotencyKey)
  })

  it('defaults to the selected predecessor immutable source and keeps a draft minimal', async () => {
    vi.mocked(api.uploadedSource).mockResolvedValue(sourcePackage)
    vi.mocked(api.createRetest).mockRejectedValue(new Error('expected rejection'))
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByRole('radio', { name: /Use current source/ })).toBeChecked()
    expect(api.uploadedSource).toHaveBeenCalledWith('assessment-2')
    expect(screen.getByText('payments-v2.zip')).toBeVisible()
    expect(screen.getByLabelText(`Source SHA-256 ${'b'.repeat(64)}`)).toBeVisible()
    expect(screen.queryByLabelText('Re-test source archive')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Assessment scope' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledWith('assessment-2', {
      predecessorAssessmentId: 'assessment-2', scopeStrategy: 'copy', profileStrategy: 'none',
      sourceStrategy: 'reuse_current', sourceVersionId: 'source-version-2', source: undefined, idempotencyKey: expect.any(String),
    }))
  })

  it('blocks creation on source lookup errors and retries without losing the predecessor', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValueOnce(new ApiError(503, 'Source service unavailable')).mockResolvedValueOnce(sourcePackage)
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Source service unavailable')
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
    expect(screen.queryByRole('radio', { name: /Use current source/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry source lookup' }))
    expect(await screen.findByRole('radio', { name: /Use current source/ })).toBeChecked()
    expect(screen.getByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Re-test #2')
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeEnabled()
    expect(api.uploadedSource).toHaveBeenCalledTimes(2)
  })

  it('can create a new-source child when the predecessor upload metadata is no longer available', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'d'.repeat(64)}` }] } as never)
    vi.mocked(api.createRetest).mockRejectedValue(new Error('expected request rejection'))
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    expect(await screen.findByRole('radio', { name: /Use current source/ })).toBeDisabled()
    expect(screen.getByRole('radio', { name: /Upload new source/ })).toBeChecked()
    expect(screen.getByRole('combobox', { name: 'Assessment scope' })).toBeDisabled()
    const source = new File(['new revision'], 'replacement.zip')
    fireEvent.change(screen.getByLabelText('Re-test source archive'), { target: { files: [source] } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledWith('assessment-2', expect.objectContaining({
      predecessorAssessmentId: 'assessment-2', scopeStrategy: 'copy', sourceStrategy: 'upload_new', sourceVersionId: undefined, source,
    })))
  })

  it('refreshes eligible predecessors when the current Assessment completes without navigation', async () => {
    vi.mocked(api.assessmentLifecycle).mockResolvedValueOnce({
      ...lifecycle,
      members: lifecycle.members.map((member) => ({ ...member, assessmentStatus: 'active' })),
    })
    const view = renderPanel('active')
    await screen.findByRole('button', { name: /Details & history/ })
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
    view.rerender(<MemoryRouter><AssessmentLifecyclePanel assessmentId="assessment-2" engagementStatus="completed" /></MemoryRouter>)
    await waitFor(() => expect(api.assessmentLifecycle).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Create Re-test' }))
    expect(screen.getByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Re-test #2')
  })

  it('uses the authoritative preview, requires a reason, and preserves input after a stale conflict', async () => {
    vi.mocked(api.previewAssessmentRelationshipChange).mockResolvedValue({
      cycleId: 'cycle-1', command: 'reparent_within_cycle', assessmentId: 'assessment-2',
      oldPredecessorAssessmentId: 'assessment-1', newPredecessorAssessmentId: 'assessment-0',
      oldSelectedHeadAssessmentId: 'assessment-2', newSelectedHeadAssessmentId: 'assessment-2', descendantAssessmentIds: ['assessment-child'],
      impact: { memberIds: ['assessment-2'], snapshotIds: ['snapshot-1'], identityIds: ['identity-1'], comparisonIds: ['comparison-1'], projectionIds: ['projection-1'] },
      locks: [], reasonRequired: true, commitAllowed: true, cycleVersion: 7, expiresAt: '2026-09-01T02:00:00Z', previewToken: 'signed-preview',
    })
    vi.mocked(api.commitAssessmentRelationshipChange).mockRejectedValue(new ApiError(409, 'stale'))
    renderPanel()

    await openHistory()
    fireEvent.click(screen.getByRole('button', { name: 'Change relationship' }))
    fireEvent.click(screen.getByRole('button', { name: 'Preview server impact' }))
    expect(await screen.findByText('1 members · 1 snapshots · 1 identities · 1 comparisons · 1 projections')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Commit authoritative preview' })).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason' }), { target: { value: 'Correct imported ancestry' } })
    fireEvent.click(screen.getByRole('button', { name: 'Commit authoritative preview' }))

    expect(await screen.findByText(/Preview is stale, expired, or already used/)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Reason' })).toHaveValue('Correct imported ancestry')
    expect(api.commitAssessmentRelationshipChange).toHaveBeenCalledWith(
      'cycle-1', 7,
      { command: 'reparent_within_cycle', assessmentId: 'assessment-2', newPredecessorAssessmentId: 'assessment-0' },
      'signed-preview', 'Correct imported ancestry', expect.any(String),
    )
  })

  it('keeps the summary compact and reveals full history with the keyboard', async () => {
    const user = userEvent.setup()
    renderPanel()
    const toggle = await screen.findByRole('button', { name: /4 members · 2 branch heads.*Details & history/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('list', { name: 'Assessment Cycle history' })).not.toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Assessment lifecycle breadcrumb' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Compare' })).toHaveAttribute('href', '/engagements/assessment-2/comparison')
    expect(screen.getByRole('link', { name: 'Payments lifecycle' })).toHaveAttribute('href', '/assessment-cycles/cycle-1')

    toggle.focus()
    await user.keyboard('{Enter}')
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('list', { name: 'Assessment Cycle history' })).toBeVisible()
    expect(screen.getByRole('navigation', { name: 'Assessment lifecycle breadcrumb' })).toHaveTextContent('assessment-2')
    await user.keyboard(' ')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    expect(screen.queryByRole('link', { name: 'Initial · assessment-0' })).not.toBeInTheDocument()
    expect(api.assessmentLifecycle).toHaveBeenCalledTimes(1)
  })

  it('explains disabled Re-test access without exposing reviewer actions', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'viewer-1', name: 'Viewer', role: 'viewer', features: { assessmentLifecycleRead: true, assessmentLifecycleUIDefault: true } })
    renderPanel('draft')
    fireEvent.click(await screen.findByRole('button', { name: 'Re-test requirements' }))
    expect(screen.getByRole('list', { name: 'Assessment Cycle history' })).toBeVisible()
    expect(screen.getByText(/Re-test creation requires operate permission/, { selector: 'span' })).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Create Re-test' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Change relationship' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Select Cycle head' })).not.toBeInTheDocument()
  })

  it('navigates to Compare within the app without losing the in-memory session', async () => {
    render(<MemoryRouter><Routes>
      <Route path="/" element={<AssessmentLifecyclePanel assessmentId="assessment-2" engagementStatus="completed" />} />
      <Route path="/engagements/assessment-2/comparison" element={<h1>Comparison opened</h1>} />
    </Routes></MemoryRouter>)
    fireEvent.click(await screen.findByRole('link', { name: 'Compare' }))
    expect(await screen.findByRole('heading', { name: 'Comparison opened' })).toBeInTheDocument()
  })

	it('renders loading, migration-pending, and permission error states', async () => {
		vi.mocked(api.assessmentLifecycle).mockImplementationOnce(() => new Promise<AssessmentLifecycle>(() => undefined))
		const loading = renderPanel()
		expect(await screen.findByText('Loading Assessment lifecycle…')).toBeInTheDocument()
    loading.unmount()

    vi.mocked(api.assessmentLifecycle).mockResolvedValueOnce(null as never)
    const empty = renderPanel()
    expect(await screen.findByText('Lifecycle migration pending')).toBeInTheDocument()
    empty.unmount()

    vi.mocked(api.assessmentLifecycle).mockRejectedValueOnce(new Error('Review permission is required.'))
    renderPanel()
    expect(await screen.findByText('Review permission is required.')).toBeInTheDocument()
  })
})

function closureManifest(): AssessmentClosureManifest {
  return {
    id: 'manifest-active', cycleId: 'cycle-1', manifestVersion: 1, lifecycle: 'active', cycleVersion: 8,
    rootAssessmentId: 'assessment-0', finalAssessmentId: 'assessment-2', initialSnapshotId: 'snapshot-0', finalSnapshotId: 'snapshot-2', comparisonId: 'comparison-1',
    initialSnapshotHash: 'a'.repeat(64), finalSnapshotHash: 'b'.repeat(64), comparisonHash: 'c'.repeat(64), canonicalInputHash: 'd'.repeat(64), contentHash: 'e'.repeat(64),
    policyVersion: 'closure-policy-v1', algorithmVersion: 'comparison-v1', fingerprintVersion: 'fingerprint-v1', riskVersion: 'risk-v1', rendererContractVersion: 'assessment-cycle-report-v1',
    coverageDecisions: { initial: [], final: [] }, scopeProfileChanges: [], overrideBlockerIds: [], nonFinalBranches: [],
    path: [
      { pathPosition: 0, assessmentId: 'assessment-0', assessmentType: 'initial', retestNumber: 0, relationshipVersion: 1, snapshotId: 'snapshot-0' },
      { pathPosition: 1, assessmentId: 'assessment-1', assessmentType: 'retest', retestNumber: 1, relationshipVersion: 2, snapshotId: 'snapshot-1' },
      { pathPosition: 2, assessmentId: 'assessment-2', assessmentType: 'retest', retestNumber: 2, relationshipVersion: 3, snapshotId: 'snapshot-2' },
    ],
    references: [], reason: 'accepted', overrideReason: '', asOfAt: '2026-09-01T01:00:00Z', createdAt: '2026-09-01T01:00:00Z', createdBy: 'reviewer',
    sealedAt: '2026-09-01T01:00:00Z', sealedBy: 'reviewer', supersededAt: null,
  }
}
