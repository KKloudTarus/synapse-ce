import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../lib/api'
import type { AssessmentRelationshipCandidate } from '../../lib/types'
import { AssessmentRelationships } from './AssessmentRelationships'

vi.mock('../../lib/api', () => {
  class MockApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
      this.name = 'ApiError'
    }
  }
  return {
    ApiError: MockApiError,
    api: {
      listAssessmentRelationshipCandidates: vi.fn(),
      generateAssessmentRelationshipCandidate: vi.fn(),
      decideAssessmentRelationshipCandidate: vi.fn(),
    },
  }
})

const candidate: AssessmentRelationshipCandidate = {
  id: 'candidate-1',
  predecessorCycleId: 'cycle-predecessor',
  predecessorAssessmentId: 'assessment-predecessor',
  predecessorRelationshipVersion: 1,
  predecessorSnapshotId: 'snapshot-predecessor',
  successorCycleId: 'cycle-successor',
  successorAssessmentId: 'assessment-successor',
  successorRelationshipVersion: 1,
  successorSnapshotId: 'snapshot-successor',
  boundaryKeyHash: 'b'.repeat(64),
  signals: [
    { kind: 'exact_frozen_boundary', evidenceHash: 'b'.repeat(64), matchCount: 0, scoreMilli: 0, schemaVersion: 1 },
    { kind: 'explicit_imported_reference', evidenceHash: 'a'.repeat(64), matchCount: 1, scoreMilli: 1000, schemaVersion: 1 },
  ],
  inputHash: 'c'.repeat(64),
  confidence: 'medium',
  status: 'open',
  version: 1,
  expiresAt: '2026-10-01T12:00:00Z',
  createdBy: 'operator',
  createdAt: '2026-09-01T12:00:00Z',
}

const confirmed: AssessmentRelationshipCandidate = {
  ...candidate,
  status: 'confirmed',
  version: 2,
  decision: { id: 'decision-1', action: 'confirm', actor: 'reviewer', reason: 'Validated deterministic evidence', version: 2, createdAt: '2026-09-01T12:05:00Z' },
  repairPlan: {
    id: 'plan-1', inputHash: candidate.inputHash, planHash: 'd'.repeat(64), createdBy: 'reviewer', createdAt: '2026-09-01T12:05:00Z',
    body: { command: 'assessment_cycle.merge_legacy_relationship', execution: 'blocked', requires: 'separately_approved_move_merge_command' },
  },
}

describe('Assessment relationship settings', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders loading and empty states with accessible generation controls', async () => {
    let resolveList: (items: AssessmentRelationshipCandidate[]) => void = () => undefined
    vi.mocked(api.listAssessmentRelationshipCandidates).mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    render(<AssessmentRelationships />)

    expect(screen.getByText('Loading relationship candidates…')).toBeInTheDocument()
    expect(screen.getByLabelText('Predecessor Cycle ID')).toBeRequired()
    expect(screen.getByLabelText('Successor Cycle ID')).toBeRequired()
    expect(screen.getByLabelText(/Imported reference SHA-256/)).toHaveAttribute('pattern', '[0-9a-f]{64}')
    expect(screen.getByRole('combobox', { name: 'Filter relationship candidates by status' })).toBeInTheDocument()

    await act(async () => resolveList([]))
    expect(await screen.findByText('No relationship candidates')).toBeInTheDocument()
  })

  it('renders an error and retries the queue load', async () => {
    vi.mocked(api.listAssessmentRelationshipCandidates).mockRejectedValueOnce(new ApiError(403, 'forbidden')).mockResolvedValueOnce([])

    render(<AssessmentRelationships />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Review permission is required')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No relationship candidates')).toBeInTheDocument()
    expect(api.listAssessmentRelationshipCandidates).toHaveBeenCalledTimes(2)
  })

  it('reviews and confirms a candidate with an audit reason', async () => {
    const user = userEvent.setup()
    vi.mocked(api.listAssessmentRelationshipCandidates).mockResolvedValue([candidate])
    vi.mocked(api.decideAssessmentRelationshipCandidate).mockResolvedValue(confirmed)

    render(<AssessmentRelationships />)

    expect(await screen.findByText(candidate.id)).toBeInTheDocument()
    expect(screen.getByLabelText('Candidate evidence signals')).toHaveTextContent('Exact frozen boundary')
    await user.click(screen.getByRole('button', { name: 'Review candidate' }))
    const reason = screen.getByLabelText('Audit reason')
    await user.type(reason, 'Validated deterministic evidence')
    await user.click(screen.getByRole('button', { name: 'Confirm and seal plan' }))

    await waitFor(() => expect(api.decideAssessmentRelationshipCandidate).toHaveBeenCalledWith(candidate, 'confirm', 'Validated deterministic evidence'))
    expect(await screen.findByText(`Candidate ${candidate.id} was confirmed.`)).toBeInTheDocument()
  })

  it('refreshes the queue after a decision conflict', async () => {
    const user = userEvent.setup()
    vi.mocked(api.listAssessmentRelationshipCandidates).mockResolvedValueOnce([candidate]).mockResolvedValueOnce([{ ...candidate, version: 1 }])
    vi.mocked(api.decideAssessmentRelationshipCandidate).mockRejectedValue(new ApiError(409, 'version conflict'))

    render(<AssessmentRelationships />)

    await user.click(await screen.findByRole('button', { name: 'Review candidate' }))
    await user.type(screen.getByLabelText('Audit reason'), 'Conflicting review')
    await user.click(screen.getByRole('button', { name: 'Reject' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('changed or expired')
    await waitFor(() => expect(api.listAssessmentRelationshipCandidates).toHaveBeenCalledTimes(2))
  })
})
