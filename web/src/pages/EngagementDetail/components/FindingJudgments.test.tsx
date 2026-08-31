import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Judgment } from '../../../lib/types'
import { JudgmentReviewForm } from '../ReviewsTab'
import { JudgmentClaim } from './FindingJudgments'

const investigation: Judgment = {
  id: 'judgment-1',
  engagementId: 'engagement-1',
  capability: 'investigation',
  subjectKind: 'incident',
  subjectId: 'incident-7',
  state: 'proposed',
  evidenceScore: 0,
  proposedBy: 'agent:session-1',
  version: 1,
  claim: {
    incident_id: 'incident-7',
    tactic: 'lateral_movement',
    confidence: 82,
    drivers: ['new_exec_paths', 'network_fanout_spike'],
    relevant_event_ids: ['event-1', 'event-2'],
    suggested_next_step: 'retro_hunt_similar_activity',
  },
}

describe('investigation judgment review', () => {
  it('renders a structured AI hypothesis without presenting it as fact', () => {
    render(<JudgmentClaim judgment={investigation} />)

    expect(screen.getByText('AI investigation hypothesis')).toBeInTheDocument()
    expect(screen.getByText('lateral movement')).toBeInTheDocument()
    expect(screen.getByText('82% confidence')).toBeInTheDocument()
    expect(screen.getByText('network_fanout_spike')).toBeInTheDocument()
    expect(screen.getByText(/only a distinct reviewer's sealed verdict can confirm it/i)).toBeInTheDocument()
    expect(screen.getByText(/cannot change incident facts, risk, disposition, or response actions/i)).toBeInTheDocument()
    expect(screen.getByText(/event-1, event-2/)).toBeInTheDocument()
    expect(screen.getByText('retro hunt similar activity')).toBeInTheDocument()
  })

  it('requires an evidence-scored analyst verdict without incident mutation authority', () => {
    render(
      <JudgmentReviewForm
        engagementId="engagement-1"
        judgment={investigation}
        onCancel={vi.fn()}
        onSettled={vi.fn()}
        onConflict={vi.fn()}
      />,
    )

    expect(screen.getByText(/Record a distinct analyst verdict on this AI hypothesis/i)).toBeInTheDocument()
    expect(screen.getByText(/cannot mutate incident facts, risk, disposition, or response actions/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Seal verdict' })).toBeDisabled()
  })
})
