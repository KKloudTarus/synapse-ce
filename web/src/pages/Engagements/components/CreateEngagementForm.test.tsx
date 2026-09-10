import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../../lib/api'
import type { AssessmentCycleSummary } from '../../../lib/types'
import { CreateEngagementForm } from './CreateEngagementForm'

vi.mock('../../../lib/api', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../lib/api')>(),
  api: {
    listBusinessAssets: vi.fn(),
    listProjects: vi.fn(),
    listAssessmentCycles: vi.fn(),
    listAssessmentCycleMembers: vi.fn(),
    createRetest: vi.fn(),
    uploadedSource: vi.fn(),
    getEngagement: vi.fn(),
    createEngagement: vi.fn(),
    createEngagementFromSource: vi.fn(),
    startScan: vi.fn(),
  },
}))

const cycle: AssessmentCycleSummary = {
  id: 'cycle-1', name: 'Payments Cycle', boundaryKind: 'asset_project', businessAssetId: 'asset-1', projectId: 'project-1', status: 'open',
  rootAssessmentId: 'assessment-0', selectedHeadAssessmentId: 'assessment-1', activeClosureManifestId: '', activeClosureCycleVersion: 0,
  nextRetestNumber: 2, version: 3, createdAt: '2026-08-20T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z', createdBy: 'operator', updatedBy: 'operator',
  memberCount: 2, activeBranchCount: 1, latestAssessmentId: 'assessment-1', latestRetestNumber: 1,
  members: [
    { assessmentId: 'assessment-0', assessmentStatus: 'completed', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '2026-08-20T00:00:00Z', createdBy: 'operator', archivedAt: null },
    { assessmentId: 'assessment-1', assessmentStatus: 'completed', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 1, relationshipVersion: 1, createdAt: '2026-08-25T00:00:00Z', createdBy: 'operator', archivedAt: null },
  ],
  membersNextCursor: '', rootSnapshotId: 'snapshot-0', currentSnapshotId: 'snapshot-1', comparisonId: 'comparison-1', comparisonStatus: 'complete', comparisonSummary: null,
  selectedHeadLastScanAt: '2026-09-01T00:00:00Z', scanStaleness: 'fresh',
}

describe('CreateEngagementForm Re-test purpose', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({ items: [cycle], nextCursor: '', migrationPending: [], migrationPendingTotal: 0 })
    vi.mocked(api.uploadedSource).mockResolvedValue(null as never)
  })

  it('submits only lifecycle input and reuses the idempotency key for a draft retry', async () => {
    vi.mocked(api.createRetest).mockRejectedValue(new Error('temporary network failure'))
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)

    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Payments Cycle · Re-test #1')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save non-executable draft' })).toBeEnabled())
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'Payments verification' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    expect(await screen.findByText('temporary network failure')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))

    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(2))
    const first = vi.mocked(api.createRetest).mock.calls[0]
    const second = vi.mocked(api.createRetest).mock.calls[1]
    expect(first?.[0]).toBe('assessment-1')
    expect(first?.[1]).toMatchObject({ name: 'Payments verification', predecessorAssessmentId: 'assessment-1', scopeStrategy: 'copy', profileStrategy: 'none', authorizedFrom: '', authorizedTo: '', roe: undefined })
    expect(first?.[1]?.idempotencyKey).toBeTruthy()
    expect(second?.[1]?.idempotencyKey).toBe(first?.[1]?.idempotencyKey)
    expect(first?.[1]).not.toHaveProperty('cycleId')
    expect(first?.[1]).not.toHaveProperty('boundaryKind')
  })

  it('only offers completed members even when the selected head is still a draft', async () => {
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({
      items: [{ ...cycle, members: cycle.members.map((member) => ({ ...member, assessmentStatus: member.assessmentId === 'assessment-1' ? 'draft' : 'completed' })) }],
      nextCursor: '', migrationPending: [], migrationPendingTotal: 0,
    })
    vi.mocked(api.createRetest).mockRejectedValue(new Error('expected test rejection'))
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Payments Cycle · Initial')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save non-executable draft' })).toBeEnabled())
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'New branch' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledWith('assessment-0', expect.objectContaining({ predecessorAssessmentId: 'assessment-0' })))
    expect(api.listAssessmentCycles).toHaveBeenCalledWith({ status: 'open', limit: 50 })
  })

  it('hydrates paged members and offers completed predecessors outside the inline preview', async () => {
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({ items: [{ ...cycle, members: [], membersNextCursor: 'inline-next' }], nextCursor: '', migrationPending: [], migrationPendingTotal: 0 })
    vi.mocked(api.listAssessmentCycleMembers).mockResolvedValue({ items: cycle.members, nextCursor: '' })
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Payments Cycle · Re-test #1')
    expect(api.listAssessmentCycleMembers).toHaveBeenCalledWith('cycle-1', '', 100)
  })

  it('blocks the authorized action without a separate window and tool classes', async () => {
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    await screen.findByRole('combobox', { name: 'Based on Assessment' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save non-executable draft' })).toBeEnabled())
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'New Re-test' } })
    fireEvent.submit(screen.getByRole('textbox', { name: /Name/ }).closest('form')!)
    expect(await screen.findByText('Enter a separate authorization window and allowed tool classes, or save a non-executable draft.')).toBeInTheDocument()
    expect(api.createRetest).not.toHaveBeenCalled()
  })

  it('reuses the current uploaded source for a draft and gives edited requests a different key', async () => {
    vi.mocked(api.uploadedSource).mockResolvedValue({
      versionId: 'version-current', filename: 'current.zip', size: 1234, sha256: 'a'.repeat(64), target: '', uploadedBy: 'alice', uploadedAt: '2026-09-08T00:00:00Z',
    })
    vi.mocked(api.createRetest).mockRejectedValue(new Error('temporary network failure'))
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('radio', { name: /Use current source/ })).toBeChecked()
    expect(api.uploadedSource).toHaveBeenCalledWith('assessment-1')
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'Current source verification' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    expect(await screen.findByText('temporary network failure')).toBeInTheDocument()
    const first = vi.mocked(api.createRetest).mock.calls[0]?.[1]
    expect(first).toMatchObject({ sourceStrategy: 'reuse_current', sourceVersionId: 'version-current', source: undefined, authorizedFrom: '', authorizedTo: '' })
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'Renamed source verification' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(2))
    expect(vi.mocked(api.createRetest).mock.calls[1]?.[1]?.idempotencyKey).not.toBe(first?.idempotencyKey)
  })

  it('requires a new archive only after selecting upload and never starts a Re-test scan automatically', async () => {
    vi.mocked(api.uploadedSource).mockResolvedValue({
      versionId: 'version-current', filename: 'current.zip', size: 1234, sha256: 'a'.repeat(64), target: '', uploadedBy: 'alice', uploadedAt: '2026-09-08T00:00:00Z',
    })
    vi.mocked(api.createRetest).mockResolvedValue({ engagement: { id: 'new-retest' } } as never)
    const onCreated = vi.fn()
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={onCreated} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    fireEvent.click(await screen.findByRole('radio', { name: /Upload new source/ }))
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'New source verification' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    expect(await screen.findByText('Choose a source archive to upload.')).toBeInTheDocument()
    expect(api.createRetest).not.toHaveBeenCalled()
    const file = new File(['new revision'], 'updated.tar.gz')
    fireEvent.change(screen.getByLabelText('Re-test source archive'), { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledWith('assessment-1', expect.objectContaining({ source: file, sourceStrategy: 'upload_new', sourceVersionId: undefined })))
    expect(onCreated).toHaveBeenCalledWith({ id: 'new-retest' }, 'retest')
    expect(api.startScan).not.toHaveBeenCalled()
  })

  it('creates a child with a new archive when the predecessor package was lost', async () => {
    vi.mocked(api.uploadedSource).mockRejectedValue(new ApiError(404, 'No source package'))
    vi.mocked(api.getEngagement).mockResolvedValue({ inScope: [{ kind: 'repo', value: `uploaded-source/sha256/${'a'.repeat(64)}` }] } as never)
    vi.mocked(api.createRetest).mockResolvedValue({ engagement: { id: 'new-retest' } } as never)
    render(<CreateEngagementForm assessmentLifecycleEnabled onCreated={vi.fn()} />)
    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('radio', { name: /Use current source/ })).toBeDisabled()
    expect(screen.getByRole('radio', { name: /Upload new source/ })).toBeChecked()
    expect(api.getEngagement).toHaveBeenCalledWith('assessment-1')
    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'Replacement source verification' } })
    const file = new File(['new revision'], 'replacement.zip')
    fireEvent.change(screen.getByLabelText('Re-test source archive'), { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    await waitFor(() => expect(api.createRetest).toHaveBeenCalledWith('assessment-1', expect.objectContaining({
      predecessorAssessmentId: 'assessment-1', scopeStrategy: 'copy', source: file, sourceStrategy: 'upload_new', sourceVersionId: undefined,
    })))
    expect(api.startScan).not.toHaveBeenCalled()
  })

  it('hides Re-test controls outside the tenant lifecycle rollout', () => {
    render(<CreateEngagementForm onCreated={vi.fn()} />)
    expect(screen.queryByRole('radio', { name: /Re-test existing assessment/ })).not.toBeInTheDocument()
  })

  it('reuses one idempotency key when an initial Assessment request is retried', async () => {
    vi.mocked(api.createEngagement).mockRejectedValue(new Error('temporary network failure'))
    render(<CreateEngagementForm onCreated={vi.fn()} />)

    fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value: 'Initial assessment' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Target value for row 1' }), { target: { value: 'app.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Engagement' }))
    expect(await screen.findByText('temporary network failure')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create Engagement' }))

    await waitFor(() => expect(api.createEngagement).toHaveBeenCalledTimes(2))
    const firstKey = vi.mocked(api.createEngagement).mock.calls[0]?.[1]
    const secondKey = vi.mocked(api.createEngagement).mock.calls[1]?.[1]
    expect(firstKey).toBeTruthy()
    expect(secondKey).toBe(firstKey)
  })
})
