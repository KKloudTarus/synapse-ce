import { describe, expect, it, vi } from 'vitest'

import { assessmentComparisonsApi } from './assessment-comparisons'

describe('assessmentComparisonsApi', () => {
  it('maps comparison pages and sends review concurrency headers', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'comparison-1', cycle_id: 'cycle-1', baseline_snapshot_id: 'snapshot-1', current_snapshot_id: 'snapshot-2', mode: 'lifecycle',
        input_hash: 'a'.repeat(64), algorithm_version: 1, fingerprint_version: 1, risk_model_version: 1, coverage_policy_version: 1,
        status: 'needs_review', version: 3, attempts: 1, summary: { fixed_rate: { numerator: 1, denominator: 2 } },
        created_at: '2026-09-01T07:00:00Z', updated_at: '2026-09-01T07:01:00Z',
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{
          id: 'item-1', position: 0, identity_id: 'identity-1', presence: 'needs_review', change_flags: ['severity_increased'],
          baseline_actionable: true, current_actionable: true, comparable_baseline: true, baseline_risk_milli: 1000, current_risk_milli: 2000,
          review_candidate_ids: ['candidate-1'],
          review_candidates: [{ id: 'candidate-1', source_observation_ids: ['observation-1'] }],
        }], next_cursor: 'next-1',
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        override_event_id: 'override-1', superseded_comparison_id: 'comparison-1', replacement_comparison_id: 'comparison-2', replacement_status: 'queued',
      }), { status: 202, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const comparison = await assessmentComparisonsApi.assessmentComparison('comparison/1')
    const page = await assessmentComparisonsApi.assessmentComparisonItems('comparison/1', { limit: 25, presence: 'needs_review' })
    const review = await assessmentComparisonsApi.reviewAssessmentComparisonItem({
      comparisonId: comparison.id, itemId: page.items[0].id, comparisonVersion: comparison.version, action: 'confirm',
      candidateId: page.items[0].reviewCandidateIds[0], sourceObservationId: 'observation-1', reason: 'confirmed match', idempotencyKey: 'review-1',
    })

    expect(comparison.summary.fixedRate).toEqual({ numerator: 1, denominator: 2, naReason: '' })
    expect(page.items[0].changeFlags).toEqual(['severity_increased'])
    expect(page.items[0].reviewCandidates).toEqual([{ id: 'candidate-1', sourceObservationIds: ['observation-1'] }])
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/assessment-comparisons/comparison%2F1/items?limit=25&presence=needs_review', expect.anything())
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/api/v1/assessment-comparisons/comparison-1/items/item-1/confirm', expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({ 'Idempotency-Key': 'review-1', 'If-Match': '"3"' }),
    }))
    expect(review.replacementComparisonId).toBe('comparison-2')
  })
})
