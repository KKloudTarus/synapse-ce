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

    await waitFor(() => expect(api.finalizeAssessmentSnapshot).toHaveBeenCalledTimes(1))
    const [assessmentId, input] = vi.mocked(api.finalizeAssessmentSnapshot).mock.calls[0]
    expect(assessmentId).toBe('engagement-1')
    expect(input.expectedDefaultVersion).toBe(2)
    expect(input.idempotencyKey).toBeTruthy()
    // Lane keys must be absent from the wire body, not present-and-undefined: the server expands a
    // run with no lane keys to all of its provenance lanes. Vitest equality ignores undefined
    // properties, so this asserts the key is genuinely missing.
    expect(input.selectedRuns).toHaveLength(1)
    expect(input.selectedRuns[0].runId).toBe('run-1')
    expect(Object.prototype.hasOwnProperty.call(input.selectedRuns[0], 'laneKeys')).toBe(false)
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

  it('says a scan is needed when the Assessment has no runs at all', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([])
    renderDialog()

    expect(await screen.findByText(/No scan run is available for this Assessment/)).toBeInTheDocument()
  })

  // Silently filtering runs makes "no runs" indistinguishable from "runs exist but none qualify",
  // which leaves the operator with no way to tell what to do next.
  it('says how many runs were excluded when every run lacks provenance lanes', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-a', 0), run('run-b', 0)])
    renderDialog()

    expect(await screen.findByText(/2 scan runs exist for this Assessment, but none carry sealed provenance lanes/)).toBeInTheDocument()
  })

  it('says how many runs were excluded alongside the selectable ones', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 2), run('run-empty', 0)])
    renderDialog()

    expect(await screen.findByLabelText('Include scan run run-1')).toBeInTheDocument()
    expect(screen.getByText(/1 run is not listed: they carry no sealed provenance lanes/)).toBeInTheDocument()
  })

  // snapshot_conflict covers both a moved default pointer and a still-running scan job, and the
  // response carries nothing that separates them, so the message must not assert one of them.
  it('names both causes a snapshot_conflict can have', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockRejectedValue(new ApiError(409, 'conflict', { error: 'snapshot_conflict' }))
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    expect(await screen.findByText(/either another operator finalized a snapshot first, or a scan job/)).toBeInTheDocument()
  })

  it('names a reused request key separately from a moved pointer', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockRejectedValue(new ApiError(409, 'conflict', { error: 'idempotency_body_mismatch' }))
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    expect(await screen.findByText(/already submitted with a different run selection/)).toBeInTheDocument()
  })

  // Once the expected default version is known stale, resending it can only conflict again.
  it('stops offering the submit after a conflict', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockRejectedValue(new ApiError(409, 'conflict', { error: 'snapshot_conflict' }))
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    await screen.findByText(/either another operator finalized a snapshot first/)
    expect(screen.getByRole('button', { name: /Finalize snapshot/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Close and refresh' })).toBeInTheDocument()
  })

  // A retry after a lost response must replay the retained request, not arrive as a second,
  // differently-keyed finalize that the version precondition then rejects.
  it('reuses one idempotency key across attempts', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot)
      .mockRejectedValueOnce(new Error('network reset'))
      .mockResolvedValue({ snapshot: { id: 'snapshot-1' } as never, defaultVersion: 3 })
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))
    await screen.findByText('network reset')
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    await waitFor(() => expect(api.finalizeAssessmentSnapshot).toHaveBeenCalledTimes(2))
    const [, first] = vi.mocked(api.finalizeAssessmentSnapshot).mock.calls[0]
    const [, second] = vi.mocked(api.finalizeAssessmentSnapshot).mock.calls[1]
    expect(second.idempotencyKey).toBe(first.idempotencyKey)
  })

  it('names the missing capability on a 403 rather than a raw status', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([run('run-1', 3)])
    vi.mocked(api.finalizeAssessmentSnapshot).mockRejectedValue(new ApiError(403, 'forbidden'))
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Include scan run run-1'))
    fireEvent.click(screen.getByRole('button', { name: /Finalize snapshot/ }))

    expect(await screen.findByText(/requires the operate capability/)).toBeInTheDocument()
  })

  it('surfaces a scan-run load failure instead of an empty run list', async () => {
    vi.mocked(api.scanRuns).mockRejectedValue(new Error('scan runs unavailable'))
    renderDialog()

    expect(await screen.findByText(/scan runs unavailable/)).toBeInTheDocument()
    expect(screen.queryByText(/No scan run with provenance lanes is available/)).not.toBeInTheDocument()
  })
})
