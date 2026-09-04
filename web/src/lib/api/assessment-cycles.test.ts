import { describe, expect, it, vi } from 'vitest'
import { assessmentCyclesApi } from './assessment-cycles'

describe('assessmentCyclesApi', () => {
  it('sends a retained re-test request and maps the lifecycle response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      engagement: { ID: 'assessment-2', Scope: {}, RoE: {} },
      cycle: { id: 'cycle-1', name: 'Payments', boundary_kind: 'asset', version: 2 },
      member: { assessment_id: 'assessment-2', assessment_type: 'retest', retest_number: 1 },
      inheritance_diff: { scope: 'copy', authorization: 'explicit_only', roe: 'explicit_only', scanner_profile: 'none' },
      warnings: ['authorization_not_inherited'],
    }), { status: 201, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await assessmentCyclesApi.createRetest('assessment/1', {
      name: 'Payments Re-test', predecessorAssessmentId: 'assessment-1', idempotencyKey: 'request-1',
    })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/assessment%2F1/retests', expect.objectContaining({
      method: 'POST', headers: expect.objectContaining({ 'Idempotency-Key': 'request-1' }),
    }))
    expect(result.cycle.id).toBe('cycle-1')
    expect(result.member.assessmentType).toBe('retest')
  })

  it('uses only Cycle and Snapshot filters in list queries', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], migration_pending: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await assessmentCyclesApi.listAssessmentCycles({
      status: 'open', assessmentStatus: 'completed', assessmentType: 'retest', scanStaleness: 'stale', search: 'payments', limit: 25,
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/assessment-cycles?status=open&assessment_status=completed&assessment_type=retest&scan_staleness=stale&q=payments&limit=25',
      expect.any(Object),
    )
  })
})
