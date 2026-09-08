import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { DetectionProvenanceTab } from './DetectionProvenanceTab'

vi.mock('../../lib/api', () => ({
  api: {
    detectionProvenance: vi.fn(),
    detectionProvenanceTransitions: vi.fn(),
  },
}))

describe('DetectionProvenanceTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists provenance rows and expands a detection to its hash-chained transitions', async () => {
    vi.mocked(api.detectionProvenance).mockResolvedValue([
      { detectionId: 'det-1', status: 'complete', evidenceId: 'ev-1', updatedAt: '2026-09-05T09:00:00Z' },
      { detectionId: 'det-2', status: 'broken', evidenceId: '', updatedAt: '2026-09-05T08:00:00Z' },
    ] as never)
    vi.mocked(api.detectionProvenanceTransitions).mockResolvedValue([
      { detectionId: 'det-1', sequence: 1, kind: 'received', status: 'pending', evidenceId: '', agentId: 'a1', assetId: 's1', reason: '', previousHash: '', hash: 'h1aaaaaaaaaaaaaaaa', occurredAt: '2026-09-05T08:59:00Z' },
      { detectionId: 'det-1', sequence: 2, kind: 'commitment_sealed', status: 'complete', evidenceId: 'ev-1', agentId: 'a1', assetId: 's1', reason: '', previousHash: 'h1aaaaaaaaaaaaaaaa', hash: 'h2bbbbbbbbbbbbbbbb', occurredAt: '2026-09-05T09:00:00Z' },
    ] as never)

    render(<DetectionProvenanceTab engagementId="eng-1" />)
    expect(await screen.findByText('det-1')).toBeInTheDocument()
    expect(screen.getByText('det-2')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /det-1/ }))
    expect(await screen.findByText('Commitment sealed')).toBeInTheDocument()
    expect(api.detectionProvenanceTransitions).toHaveBeenCalledWith('eng-1', 'det-1')
    expect(screen.getByText('Received')).toBeInTheDocument()
  })

  it('shows an empty state when there is no provenance', async () => {
    vi.mocked(api.detectionProvenance).mockResolvedValue([] as never)
    render(<DetectionProvenanceTab engagementId="eng-1" />)
    expect(await screen.findByText('No detection provenance yet')).toBeInTheDocument()
  })
})
