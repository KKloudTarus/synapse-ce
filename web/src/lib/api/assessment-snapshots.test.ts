import { describe, expect, it, vi } from 'vitest'

import { assessmentSnapshotsApi } from './assessment-snapshots'

describe('assessmentSnapshotsApi', () => {
  it('sends concurrency headers and maps immutable snapshot fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      snapshot: {
        id: 'snapshot-1', cycle_id: 'cycle-1', assessment_id: 'assessment-1', snapshot_number: 1,
        lifecycle: 'finalized', provenance: 'native', boundary: { boundary_kind: 'standalone' },
        run_references: [{ run_id: 'run-1', manifest_hash: 'a'.repeat(64), lane_refs: [{ lane_key: 'sca', manifest_hash: 'b'.repeat(64) }] }],
        dimensions: [{
          run_id: 'run-1', lane_key: 'sca', lane_manifest_hash: 'b'.repeat(64), producer: 'sca', finding_kind: 'vulnerability',
          target: { kind: 'repository', schema_version: 1, canonical: 'https://example.com/repo', evaluated_revision: 'abc' },
          state: 'complete', reason_code: 'trusted_terminal_lane', included_scope: ['src/**'], excluded_scope: [],
          versions: [{ kind: 'scanner', name: 'sca', version: '1' }],
        }],
        schema_version: 1, content_hash: 'c'.repeat(64), created_at: '2026-09-01T07:00:00Z', created_by: 'operator',
        finalized_at: '2026-09-01T07:00:00Z', finalized_by: 'operator',
      },
      default_version: 1,
    }), { status: 201, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await assessmentSnapshotsApi.finalizeAssessmentSnapshot('assessment/1', {
      selectedRuns: [{ runId: 'run-1', laneKeys: ['sca'] }], expectedDefaultVersion: 0, idempotencyKey: 'snapshot-request-1',
    })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/assessment%2F1/snapshots/finalize', expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({ 'Idempotency-Key': 'snapshot-request-1', 'If-Match': '0' }),
      body: JSON.stringify({ selected_runs: [{ run_id: 'run-1', lane_keys: ['sca'] }] }),
    }))
    expect(result.defaultVersion).toBe(1)
    expect(result.snapshot.runReferences[0].laneReferences[0].laneKey).toBe('sca')
    expect(result.snapshot.dimensions[0].target.schemaVersion).toBe(1)
    expect(result.snapshot.supersededAt).toBeNull()
  })
})
