import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import type { ScanRun } from '../../lib/types'
import { FinalizeSnapshotDialog } from './FinalizeSnapshotDialog'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: { scanRuns: vi.fn(), finalizeAssessmentSnapshot: vi.fn() },
  }
})

function run(id: string, laneCount: number): ScanRun {
  return {
    id,
    engagementId: 'engagement-1',
    createdAt: '2026-09-10T07:00:00Z',
    manifest: {} as ScanRun['manifest'],
    findingKeys: [],
    provenance: 'native',
    terminalStatus: 'completed',
    sealedAt: '2026-09-10T07:05:00Z',
    manifestHash: 'a'.repeat(64),
    laneCount,
    completeCoverage: true,
  }
}

function renderDialog(onFinalized = () => {}) {
  return render(
    <FinalizeSnapshotDialog
      assessmentId="engagement-1"
      expectedDefaultVersion={2}
      onClose={() => {}}
      onFinalized={onFinalized}
    />,
  )
}

describe('FinalizeSnapshotDialog', () => {
  beforeEach(() => vi.resetAllMocks())

  it('finalizes the selected runs against the current default version', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3), run('run-2', 1)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockResolvedValue({
      snapshot: { id: 'snapshot-1' } as never,
      defaultVersion: 3,
    })
    const onFinalized = vi.fn()
    renderDialog(onFinalized)

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    // Lane keys are omitted so the server expands the run to all of its provenance lanes.
    await waitFor(() => expect(api.finalizeAssessmentSnapshot).toHaveBeenCalledWith('engagement-1', {
      selectedRuns: [{ runId: 'run-1' }],
      expectedDefaultVersion: 2,
    }))
    expect(onFinalized).toHaveBeenCalled()
  })

  it('cannot submit without a run, because the server requires at least one', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    renderDialog()

    expect(await screen.findByRole('button', { name: /Finalize snapshot/ })).toBeDisabled()
  })

  // A run with no provenance lane is rejected server-side, so offering it would produce an error
  // the operator could not have predicted.
  it('omits runs that carry no provenance lane', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3), run('run-empty', 0)])
    renderDialog()

    expect(await screen.findByLabelText('Include scan run run-1')).toBeInTheDocument()
    expect(screen.queryByLabelText('Include scan run run-empty')).not.toBeInTheDocument()
  })

  it('says a scan is needed rather than showing an empty selection', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([])
    renderDialog()

    expect(await screen.findByText(/No scan run with provenance lanes is available/)).toBeInTheDocument()
  })

  it('names the concurrent finalize instead of a raw conflict status', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockRejectedValue(new ApiError(409, 'snapshot_conflict'))
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    expect(await screen.findByText(/Another operator finalized a snapshot/)).toBeInTheDocument()
  })

  it('surfaces a scan-run load failure instead of an empty run list', async () => {
    vi.mocked(api.scanRuns).mockRejectedValue(new Error('scan runs unavailable'))
    renderDialog()

    expect(await screen.findByText(/scan runs unavailable/)).toBeInTheDocument()
    expect(screen.queryByText(/No scan run with provenance lanes is available/)).not.toBeInTheDocument()
  })
})
