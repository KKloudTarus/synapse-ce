import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../lib/api'
import type { AssessmentCycleSummary } from '../../../lib/types'
import { CreateEngagementForm } from './CreateEngagementForm'

vi.mock('../../../lib/api', () => ({
  api: {
    listBusinessAssets: vi.fn(),
    listAssessmentCycles: vi.fn(),
    createRetest: vi.fn(),
    createEngagement: vi.fn(),
    createEngagementFromSource: vi.fn(),
    startScan: vi.fn(),
  },
}))

const cycle: AssessmentCycleSummary = {
  id: 'cycle-1', name: 'Payments Cycle', boundaryKind: 'asset_project', businessAssetId: 'asset-1', projectId: 'project-1', status: 'open',
  rootAssessmentId: 'assessment-0', selectedHeadAssessmentId: 'assessment-1',
  nextRetestNumber: 2, version: 3, createdAt: '2026-08-20T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z', createdBy: 'operator', updatedBy: 'operator',
  memberCount: 2, activeBranchCount: 1, latestAssessmentId: 'assessment-1', latestRetestNumber: 1,
  members: [
    { assessmentId: 'assessment-0', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '2026-08-20T00:00:00Z', createdBy: 'operator', archivedAt: null },
    { assessmentId: 'assessment-1', assessmentType: 'retest', predecessorAssessmentId: 'assessment-0', retestNumber: 1, relationshipVersion: 1, createdAt: '2026-08-25T00:00:00Z', createdBy: 'operator', archivedAt: null },
  ],
  membersNextCursor: '', rootSnapshotId: 'snapshot-0', currentSnapshotId: 'snapshot-1',
  selectedHeadLastScanAt: '2026-09-01T00:00:00Z', scanStaleness: 'fresh',
}

describe('CreateEngagementForm Re-test purpose', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({ items: [cycle], nextCursor: '', migrationPending: [], migrationPendingTotal: 0 })
  })

  it('submits only lifecycle input and reuses the idempotency key for a draft retry', async () => {
    vi.mocked(api.createRetest).mockRejectedValue(new Error('temporary network failure'))
    render(<CreateEngagementForm onCreated={vi.fn()} />)

    fireEvent.click(screen.getByRole('radio', { name: /Re-test existing assessment/ }))
    expect(await screen.findByRole('combobox', { name: 'Based on Assessment' })).toHaveTextContent('Payments Cycle · Re-test #1')
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
})
