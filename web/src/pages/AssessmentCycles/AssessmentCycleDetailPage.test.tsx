import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import type { AssessmentClosureManifest, AssessmentClosurePreview, AssessmentCycleDetail } from '../../lib/types'
import { AssessmentCycleDetailPage } from './AssessmentCycleDetailPage'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: {
      assessmentCycle: vi.fn(), listAssessmentClosureManifests: vi.fn(), me: vi.fn(), downloadAssessmentClosureReport: vi.fn(),
      previewAssessmentClosure: vi.fn(), commitAssessmentClosure: vi.fn(), previewAssessmentReopen: vi.fn(), commitAssessmentReopen: vi.fn(),
    },
  }
})

const detail: AssessmentCycleDetail = {
  cycle: {
    id: 'cycle-1', name: 'Payments Cycle', boundaryKind: 'standalone', businessAssetId: '', projectId: '', status: 'completed',
    rootAssessmentId: 'assessment-root', selectedHeadAssessmentId: 'assessment-final', activeClosureManifestId: 'manifest-active', activeClosureCycleVersion: 5,
    nextRetestNumber: 2, version: 5, createdAt: '2026-08-30T07:00:00Z', updatedAt: '2026-09-01T07:00:00Z', createdBy: 'owner', updatedBy: 'reviewer',
  },
  members: [], branchHeads: [],
}

const activeManifest: AssessmentClosureManifest = manifest('manifest-active', 'active', 2)
const supersededManifest: AssessmentClosureManifest = { ...manifest('manifest-old', 'superseded', 1), supersededAt: '2026-08-31T07:00:00Z' }

describe('AssessmentCycleDetailPage', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.assessmentCycle).mockResolvedValue(detail)
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([activeManifest, supersededManifest])
    vi.mocked(api.me).mockResolvedValue({ id: 'reviewer', name: 'Reviewer', role: 'reviewer' })
    vi.mocked(api.downloadAssessmentClosureReport).mockResolvedValue()
  })

  it('renders final path, superseded history, and report metadata', async () => {
    renderPage()

    expect(await screen.findByRole('heading', { name: 'Payments Cycle' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Frozen root-to-final path' })).toBeInTheDocument()
    expect(screen.getAllByText('Closure v2')).toHaveLength(2)
    expect(screen.getByText(/prior closure remain available/)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Download report' })[0]!)
    await waitFor(() => expect(api.downloadAssessmentClosureReport).toHaveBeenCalledWith('cycle-1', 'manifest-active'))
  })

  it('never renders hard blockers or unknown coverage as success', async () => {
    vi.mocked(api.assessmentCycle).mockResolvedValue({ ...detail, cycle: { ...detail.cycle, status: 'open', version: 4, activeClosureManifestId: '', activeClosureCycleVersion: 0 } })
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([])
    vi.mocked(api.previewAssessmentClosure).mockResolvedValue(preview({
      commitAllowed: false,
      blockers: [{ id: 'coverage:unknown', code: 'coverage_incomplete', message: 'Coverage is incomplete.', overrideable: false, overridden: false }],
      coverageDecisions: { initial: [], final: [{ snapshotId: 'snapshot-final', dimensionId: 'sca:vulnerability', state: 'unknown', reasonCode: 'legacy_provenance', waived: false }] },
    }))
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: 'Review closure' }))
    fireEvent.click(screen.getByRole('button', { name: 'Preview server policy' }))
    expect(await screen.findByText('Hard blocker')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Coverage is not complete')
    expect(screen.getByRole('button', { name: 'Close from authoritative preview' })).toBeDisabled()
    expect(screen.queryByText('No policy blocker is active.')).not.toBeInTheDocument()
  })

  it('shows refresh-review flow and preserves reason after a two-operator conflict', async () => {
    vi.mocked(api.assessmentCycle).mockResolvedValue({ ...detail, cycle: { ...detail.cycle, status: 'open', version: 4, activeClosureManifestId: '', activeClosureCycleVersion: 0 } })
    vi.mocked(api.listAssessmentClosureManifests).mockResolvedValue([])
    vi.mocked(api.previewAssessmentClosure).mockResolvedValue(preview())
    vi.mocked(api.commitAssessmentClosure).mockRejectedValue(new ApiError(409, 'cycle_version_conflict'))
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: 'Review closure' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Closure reason' }), { target: { value: 'Release accepted' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview server policy' }))
    await screen.findByText('No policy blocker is active.')
    fireEvent.click(screen.getByRole('button', { name: 'Close from authoritative preview' }))

    expect(await screen.findByText(/Another operator changed, closed, reopened, or consumed this preview/)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Closure reason' })).toHaveValue('Release accepted')
    expect(screen.getByRole('button', { name: 'Close from authoritative preview' })).toBeDisabled()
    expect(api.commitAssessmentClosure).toHaveBeenCalledWith('cycle-1', 4, expect.objectContaining({ reason: 'Release accepted' }), 'signed-close', expect.any(String))
  })

  it('preserves the reopen reason and requires a new preview after a conflict', async () => {
    vi.mocked(api.previewAssessmentReopen).mockResolvedValue({
      cycleId: 'cycle-1', cycleVersion: 5, manifest: activeManifest,
      impact: 'The Cycle returns to open while the manifest remains immutable.',
      expiresAt: '2026-09-01T07:05:00Z', previewToken: 'signed-reopen',
    })
    vi.mocked(api.commitAssessmentReopen).mockRejectedValue(new ApiError(409, 'cycle_version_conflict'))
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: 'Review reopen' }))
    await screen.findByText(/Cycle returns to open/)
    fireEvent.change(screen.getByRole('textbox', { name: 'Reopen reason' }), { target: { value: 'Additional evidence arrived' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reopen from authoritative preview' }))

    expect(await screen.findByText(/Another operator changed or reopened this Cycle/)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Reopen reason' })).toHaveValue('Additional evidence arrived')
    expect(screen.getByRole('button', { name: 'Reopen from authoritative preview' })).toBeDisabled()
    expect(api.commitAssessmentReopen).toHaveBeenCalledWith('cycle-1', 5, 'signed-reopen', 'Additional evidence arrived', expect.any(String))
  })
})

function renderPage() {
  return render(<MemoryRouter initialEntries={['/assessment-cycles/cycle-1']}><Routes><Route path="/assessment-cycles/:cycleId" element={<AssessmentCycleDetailPage />} /></Routes></MemoryRouter>)
}

function preview(policy: Partial<AssessmentClosurePreview['policy']> = {}): AssessmentClosurePreview {
  return {
    cycleId: 'cycle-1', cycleVersion: 4, manifestVersion: 2, finalAssessmentId: 'assessment-final',
    path: activeManifest.path, nonFinalBranches: [], initialSnapshotId: 'snapshot-root', finalSnapshotId: 'snapshot-final', comparisonId: 'comparison-1',
    policy: { policyVersion: 'closure-policy-v1', blockers: [], warnings: [], coverageDecisions: { initial: [], final: [] }, commitAllowed: true, ...policy },
    references: [], scopeProfileChanges: [], rendererContractVersion: 'assessment-cycle-report-v1', expiresAt: '2026-09-01T07:05:00Z', previewToken: 'signed-close',
  }
}
function manifest(id: string, lifecycle: AssessmentClosureManifest['lifecycle'], manifestVersion: number): AssessmentClosureManifest {
  return {
    id, cycleId: 'cycle-1', manifestVersion, lifecycle, cycleVersion: manifestVersion + 3, rootAssessmentId: 'assessment-root', finalAssessmentId: 'assessment-final',
    initialSnapshotId: 'snapshot-root', finalSnapshotId: 'snapshot-final', comparisonId: 'comparison-1', initialSnapshotHash: 'a'.repeat(64), finalSnapshotHash: 'b'.repeat(64),
    comparisonHash: 'c'.repeat(64), canonicalInputHash: 'd'.repeat(64), contentHash: 'e'.repeat(64), policyVersion: 'closure-policy-v1', algorithmVersion: 'comparison-v1',
    fingerprintVersion: 'fingerprint-v1', riskVersion: 'risk-v1', rendererContractVersion: 'assessment-cycle-report-v1', coverageDecisions: { initial: [], final: [] },
    scopeProfileChanges: [], overrideBlockerIds: [], nonFinalBranches: [], path: [
      { pathPosition: 0, assessmentId: 'assessment-root', assessmentType: 'initial', retestNumber: 0, relationshipVersion: 1, snapshotId: 'snapshot-root' },
      { pathPosition: 1, assessmentId: 'assessment-final', assessmentType: 'retest', retestNumber: 1, relationshipVersion: 1, snapshotId: 'snapshot-final' },
    ], references: [], reason: 'release accepted', overrideReason: '', asOfAt: '2026-09-01T07:00:00Z', createdAt: '2026-09-01T07:00:00Z', createdBy: 'reviewer',
    sealedAt: '2026-09-01T07:00:00Z', sealedBy: 'reviewer', supersededAt: null,
  }
}
