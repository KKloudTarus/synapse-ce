import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { AssessmentCycleSummary } from '../../lib/types'
import { AssessmentCyclesPage } from './AssessmentCyclesPage'

vi.mock('../../lib/api', () => ({ api: { listAssessmentCycles: vi.fn(), listAssessmentCycleMembers: vi.fn() } }))

const cycle: AssessmentCycleSummary = {
  id: 'cycle-1', name: 'Payments Cycle', boundaryKind: 'asset', businessAssetId: 'asset-1', projectId: '', status: 'open',
  rootAssessmentId: 'assessment-root', selectedHeadAssessmentId: 'assessment-head', nextRetestNumber: 3, version: 4,
  createdAt: '2026-08-01T00:00:00Z', updatedAt: '2026-08-03T00:00:00Z', createdBy: 'alice', updatedBy: 'alice',
  memberCount: 3, activeBranchCount: 2, latestAssessmentId: 'assessment-head', latestRetestNumber: 2,
  members: [
    { assessmentId: 'assessment-root', assessmentType: 'initial', predecessorAssessmentId: '', retestNumber: 0, relationshipVersion: 1, createdAt: '2026-08-01T00:00:00Z', createdBy: 'alice', archivedAt: null },
    { assessmentId: 'assessment-head', assessmentType: 'retest', predecessorAssessmentId: 'assessment-root', retestNumber: 1, relationshipVersion: 1, createdAt: '2026-08-02T00:00:00Z', createdBy: 'alice', archivedAt: null },
  ],
  membersNextCursor: 'member-cursor', rootSnapshotId: '', currentSnapshotId: '',
  selectedHeadLastScanAt: null, scanStaleness: 'missing',
}

describe('AssessmentCyclesPage', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listAssessmentCycles).mockResolvedValue({
      items: [cycle], nextCursor: '', migrationPendingTotal: 1,
      migrationPending: [{ assessmentId: 'legacy-1', name: 'Legacy Assessment', status: 'completed', boundaryKind: 'standalone', businessAssetId: '', updatedAt: '2026-08-04T00:00:00Z' }],
    })
    vi.mocked(api.listAssessmentCycleMembers).mockResolvedValue({
      items: [{ assessmentId: 'assessment-archived', assessmentType: 'retest', predecessorAssessmentId: 'assessment-root', retestNumber: 2, relationshipVersion: 1, createdAt: '2026-08-03T00:00:00Z', createdBy: 'alice', archivedAt: '2026-08-04T00:00:00Z' }],
      nextCursor: '',
    })
  })

  it('renders N/A metrics, expands members, and continues the member cursor', async () => {
    render(<MemoryRouter initialEntries={['/assessment-cycles?expanded=cycle-1']}><AssessmentCyclesPage /></MemoryRouter>)

    expect(await screen.findByText('Payments Cycle')).toBeInTheDocument()
    expect(screen.getAllByText('N/A').length).toBeGreaterThan(0)
    expect(screen.getByText('Initial')).toBeInTheDocument()
    expect(screen.getByText('Selected head')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load more members' }))
    await waitFor(() => expect(api.listAssessmentCycleMembers).toHaveBeenCalledWith('cycle-1', 'member-cursor', 25))
    expect(await screen.findByText('Archived')).toBeInTheDocument()
  })

  it('renders migration-pending assessments without fabricating a Cycle', async () => {
    render(<MemoryRouter initialEntries={['/assessment-cycles']}><AssessmentCyclesPage /></MemoryRouter>)

    expect(await screen.findByText('Migration pending · 1')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Legacy Assessment/ })).toHaveAttribute('href', '/engagements/legacy-1')
    expect(screen.getByText('Migration pending')).toBeInTheDocument()
  })

  it('persists bounded filters in the URL-backed API query and clears them', async () => {
    render(<MemoryRouter initialEntries={['/assessment-cycles?assessment_status=active&assessment_type=retest&selected_head=assessment-head&scan=stale&q=payments']}><AssessmentCyclesPage /></MemoryRouter>)

    await waitFor(() => expect(api.listAssessmentCycles).toHaveBeenCalledWith(expect.objectContaining({
      assessmentStatus: 'active', assessmentType: 'retest', selectedHeadAssessmentId: 'assessment-head', scanStaleness: 'stale', search: 'payments',
    })))
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(api.listAssessmentCycles).toHaveBeenLastCalledWith(expect.objectContaining({
      assessmentStatus: undefined, assessmentType: undefined, selectedHeadAssessmentId: undefined, scanStaleness: undefined, search: undefined,
    })))
  })
})
