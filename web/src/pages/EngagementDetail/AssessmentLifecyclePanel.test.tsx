import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import type { AssessmentClosureManifest, AssessmentLifecycle } from '../../lib/types'
import { AssessmentLifecyclePanel } from './AssessmentLifecyclePanel'

vi.mock('../../lib/api', () => ({
  api: {
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

const lifecycle: AssessmentLifecycle = {
  assessmentId: 'assessment-2',
  cycle: {
    id: 'cycle-1', name: 'Payments lifecycle', boundaryKind: 'asset_project', businessAssetId: 'asset-1', projectId: 'project-1',
    status: 'open', rootAssessmentId: 'assessment-0', selectedHeadAssessmentId: 'assessment-2', nextRetestNumber: 4, version: 7,
    createdAt: '2026-08-01T00:00:00Z', updatedAt: '2026-08-04T00:00:00Z', createdBy: 'alice', updatedBy: 'alice',
  },
  members: [
    { assessmentId: 'assessment-0', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '2026-08-01T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-1', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 1, relationshipVersion: 2, createdAt: '2026-08-02T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-2', assessmentType: 'retest', predecessorAssessmentId: 'assessment-1', retestNumber: 2, relationshipVersion: 3, createdAt: '2026-08-03T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-3', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 3, relationshipVersion: 1, createdAt: '2026-08-04T00:00:00Z', createdBy: 'alice', archivedAt: '2026-08-05T00:00:00Z' },
  ],
  branchHeads: [
    { assessmentId: 'assessment-2', assessmentType: 'retest', predecessorAssessmentId: 'assessment-1', retestNumber: 2, relationshipVersion: 3, createdAt: '2026-08-03T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-3', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 3, relationshipVersion: 1, createdAt: '2026-08-04T00:00:00Z', createdBy: 'alice', archivedAt: '2026-08-05T00:00:00Z' },
  ],
}

function renderPanel(status = 'completed') {
  return render(<MemoryRouter><AssessmentLifecyclePanel assessmentId="assessment-2" engagementStatus={status} /></MemoryRouter>)
}

describe('AssessmentLifecyclePanel', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.assessmentLifecycle).mockResolvedValue(lifecycle)
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

    expect(await screen.findByRole('tree', { name: 'Assessment Cycle history' })).toBeInTheDocument()
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

    expect(await screen.findAllByText('Final')).toHaveLength(2)
    expect(screen.getByText(/Snapshot snapshot-2/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review reopen' })).toHaveAttribute('href', '/assessment-cycles/cycle-1')
    expect(screen.getByRole('button', { name: 'Create Re-test' })).toBeDisabled()
  })

  it('reuses one idempotency key when a non-executable draft is retried', async () => {
    vi.mocked(api.createRetest).mockRejectedValueOnce(new Error('temporary network failure')).mockRejectedValueOnce(new Error('temporary network failure'))
    renderPanel()

    fireEvent.click(await screen.findByRole('button', { name: 'Create Re-test' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'Payments verification' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))
    expect(await screen.findByText('temporary network failure')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save non-executable draft' }))

    await waitFor(() => expect(api.createRetest).toHaveBeenCalledTimes(2))
    const first = vi.mocked(api.createRetest).mock.calls[0]?.[1]
    const second = vi.mocked(api.createRetest).mock.calls[1]?.[1]
    if (!first || !second) throw new Error('expected two Create Re-test calls')
    expect(first).toMatchObject({ name: 'Payments verification', authorizedFrom: '', authorizedTo: '', roe: undefined })
    expect(first.idempotencyKey).toBeTruthy()
    expect(second.idempotencyKey).toBe(first.idempotencyKey)
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

    fireEvent.click(await screen.findByRole('button', { name: 'More · Change relationship' }))
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
