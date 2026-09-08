import { describe, expect, it, vi } from 'vitest'

import { assessmentCyclesApi } from './assessment-cycles'

const manifest = {
  id: 'manifest-1', cycle_id: 'cycle-1', manifest_version: 1, lifecycle: 'active', cycle_version: 5,
  root_assessment_id: 'assessment-root', final_assessment_id: 'assessment-final', initial_snapshot_id: 'snapshot-root',
  final_snapshot_id: 'snapshot-final', comparison_id: 'comparison-1', initial_snapshot_hash: 'a'.repeat(64),
  final_snapshot_hash: 'b'.repeat(64), comparison_hash: 'c'.repeat(64), canonical_input_hash: 'd'.repeat(64), content_hash: 'e'.repeat(64),
  policy_version: 'closure-policy-v1', algorithm_version: 'comparison-v1', fingerprint_version: 'fingerprint-v1', risk_version: 'risk-v1',
  renderer_contract_version: 'assessment-cycle-report-v1', coverage_decisions: { initial: [], final: [] }, scope_profile_changes: [],
  override_blocker_ids: [], non_final_branches: [], path: [{ path_position: 0, assessment_id: 'assessment-root', assessment_type: 'initial', retest_number: 0, relationship_version: 1, snapshot_id: 'snapshot-root' }],
  references: [], reason: 'release accepted', as_of_at: '2026-09-01T07:00:00Z', created_at: '2026-09-01T07:00:00Z', created_by: 'reviewer',
  sealed_at: '2026-09-01T07:00:00Z', sealed_by: 'reviewer',
}

describe('assessmentCyclesApi closure workflow', () => {
  it('creates a default Re-test draft without a name, dates, or execution authorization', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      engagement: { id: 'retest', name: 'Payments Re-test', status: 'draft', requires_explicit_execution_authorization: true },
      cycle: cycle('open', 2), member: { assessment_id: 'retest', assessment_status: 'draft' },
    }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const result = await assessmentCyclesApi.createRetest('root', { predecessorAssessmentId: 'root', idempotencyKey: 'draft-key' })
    const request = fetchMock.mock.calls[0]?.[1]
    expect(JSON.parse(request.body)).toEqual({
      name: '', planned_date: '', predecessor_assessment_id: 'root', scope_strategy: 'copy', profile_strategy: 'none',
      authorized_from: '', authorized_to: '', timezone: '',
    })
    expect(new Headers(request.headers).get('Idempotency-Key')).toBe('draft-key')
    expect(result.engagement).toMatchObject({ name: 'Payments Re-test', status: 'draft', requiresExplicitExecutionAuthorization: true })
  })

  it('uploads an explicit Re-test revision with bounded metadata and the same retry key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({engagement: {id: 'retest'}, cycle: cycle('open', 2), member: {assessment_id: 'retest'}}, 201))
    vi.stubGlobal('fetch', fetchMock)
    const source = new File(['revision'], 'source.zip', {type: 'application/zip'})
    await assessmentCyclesApi.createRetest('root', {name: 'Revision', source, sourceStrategy: 'upload_new', idempotencyKey: 'upload-key'})
    const request = fetchMock.mock.calls[0]?.[1]
    expect(request.body).toBeInstanceOf(FormData)
    expect(request.body.get('source')).toBe(source)
    expect(JSON.parse(request.body.get('metadata'))).toMatchObject({name: 'Revision', scope_strategy: 'copy', source_strategy: 'upload_new'})
    expect(new Headers(request.headers).get('Idempotency-Key')).toBe('upload-key')
    expect(new Headers(request.headers).has('Content-Type')).toBe(false)
  })

  it('reuses a pinned predecessor source using JSON and maps the retained selection receipt', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      engagement: { id: 'retest' }, cycle: cycle('open', 2), member: { assessment_id: 'retest' },
      source_selection: { strategy: 'reuse_current', version_id: 'child-version', filename: 'current.zip', size: 4096, sha256: 'a'.repeat(64), reused_from_version_id: 'parent-version', source_assessment_id: 'root' },
    }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const result = await assessmentCyclesApi.createRetest('root', { sourceStrategy: 'reuse_current', sourceVersionId: 'parent-version', idempotencyKey: 'reuse-key' })
    const request = fetchMock.mock.calls[0]?.[1]
    expect(typeof request.body).toBe('string')
    expect(JSON.parse(request.body)).toMatchObject({ source_strategy: 'reuse_current', source_version_id: 'parent-version', scope_strategy: 'copy' })
    expect(JSON.parse(request.body)).not.toHaveProperty('source')
    expect(new Headers(request.headers).get('Idempotency-Key')).toBe('reuse-key')
    expect(result.sourceSelection).toEqual({ strategy: 'reuse_current', versionId: 'child-version', filename: 'current.zip', size: 4096, sha256: 'a'.repeat(64), reusedFromVersionId: 'parent-version', sourceAssessmentId: 'root' })
  })

  it('persists a date-only Re-test plan separately from execution authorization', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      engagement: { id: 'retest' }, cycle: cycle('open', 2),
      member: { assessment_id: 'retest', assessment_status: 'draft', planned_date: '2026-09-21' },
    }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const result = await assessmentCyclesApi.createRetest('root', { plannedDate: '2026-09-21', idempotencyKey: 'plan-key' })
    const body = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body)
    expect(body).toMatchObject({ planned_date: '2026-09-21', authorized_from: '', authorized_to: '' })
    expect(result.member).toMatchObject({ plannedDate: '2026-09-21', assessmentStatus: 'draft' })
  })

  it('maps previews and sends retained concurrency headers for close and reopen', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        cycle_id: 'cycle-1', cycle_version: 4, manifest_version: 1, final_assessment_id: 'assessment-final',
        path: manifest.path, policy: { policy_version: 'closure-policy-v1', blockers: [], warnings: [], coverage_decisions: { initial: [], final: [] }, commit_allowed: true },
        references: [], scope_profile_changes: [], renderer_contract_version: 'assessment-cycle-report-v1', expires_at: '2026-09-01T07:05:00Z', preview_token: 'signed-close',
      }))
      .mockResolvedValueOnce(jsonResponse({ cycle: cycle('completed', 5, 'manifest-1'), manifest, report_job_id: 'job-1' }, 201))
      .mockResolvedValueOnce(jsonResponse({ cycle_id: 'cycle-1', cycle_version: 5, manifest, impact: 'Manifest remains immutable.', expires_at: '2026-09-01T07:05:00Z', preview_token: 'signed-reopen' }))
      .mockResolvedValueOnce(jsonResponse({ cycle: cycle('open', 6), superseded_manifest: { ...manifest, lifecycle: 'superseded', superseded_at: '2026-09-01T07:02:00Z' } }))
      .mockResolvedValueOnce(jsonResponse({ items: [manifest] }))
    vi.stubGlobal('fetch', fetchMock)

    const input = { reason: 'release accepted', overrideBlockerIds: [], overrideReason: '' }
    const preview = await assessmentCyclesApi.previewAssessmentClosure('cycle/1', input)
    const committed = await assessmentCyclesApi.commitAssessmentClosure('cycle/1', preview.cycleVersion, input, preview.previewToken, 'close-key')
    const reopenPreview = await assessmentCyclesApi.previewAssessmentReopen('cycle/1')
    const reopened = await assessmentCyclesApi.commitAssessmentReopen('cycle/1', reopenPreview.cycleVersion, reopenPreview.previewToken, 'more testing', 'reopen-key')
    const manifests = await assessmentCyclesApi.listAssessmentClosureManifests('cycle/1')

    expect(preview.policy.commitAllowed).toBe(true)
    expect(committed.manifest.finalSnapshotId).toBe('snapshot-final')
    expect(committed.cycle.activeClosureManifestId).toBe('manifest-1')
    expect(reopened.supersededManifest.lifecycle).toBe('superseded')
    expect(manifests[0]?.rendererContractVersion).toBe('assessment-cycle-report-v1')
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/assessment-cycles/cycle%2F1/closure-commits', expect.objectContaining({
      method: 'POST', headers: expect.objectContaining({ 'If-Match': '"4"', 'Idempotency-Key': 'close-key' }),
      body: JSON.stringify({ reason: 'release accepted', override_blocker_ids: [], override_reason: '', preview_token: 'signed-close' }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/api/v1/assessment-cycles/cycle%2F1/reopen-commits', expect.objectContaining({
      method: 'POST', headers: expect.objectContaining({ 'If-Match': '"5"', 'Idempotency-Key': 'reopen-key' }),
    }))
  })
})

function cycle(status: 'open' | 'completed', version: number, activeClosureManifestId = '') {
  return {
    id: 'cycle-1', name: 'Payments', boundary_kind: 'standalone', status, root_assessment_id: 'assessment-root',
    selected_head_assessment_id: 'assessment-final', active_closure_manifest_id: activeClosureManifestId,
    active_closure_cycle_version: activeClosureManifestId ? version : 0, next_retest_number: 2, version,
    created_at: '2026-09-01T06:00:00Z', updated_at: '2026-09-01T07:00:00Z', created_by: 'owner', updated_by: 'reviewer',
  }
}

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}
