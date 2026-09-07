import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '.'

// Exercises the real mappers for the engagement drill-down adapters. Detection provenance is
// snake_case-tagged; occurrence events and the risk assessment have no Go json tags (PascalCase).
describe('engagement drill-down adapters', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('maps the batch auto-verify counts', async () => {
    respond({ attempted: 5, confirmed: 3, refuted: 1, skipped: 1, errors: 0 })
    const r = await api.autoVerifyJudgments('eng-1')
    expect(r).toEqual({ attempted: 5, confirmed: 3, refuted: 1, skipped: 1, errors: 0 })
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('POST')
  })

  it('maps snake_case detection provenance and its transitions', async () => {
    respond({ provenance: [{ tenant_id: 't', engagement_id: 'eng-1', detection_id: 'det-1', status: 'complete', evidence_id: 'ev-1', updated_at: '2026-09-05T09:00:00Z' }] })
    const cur = await api.detectionProvenance('eng-1')
    expect(cur[0]).toMatchObject({ detectionId: 'det-1', status: 'complete', evidenceId: 'ev-1' })

    respond({ transitions: [{ detection_id: 'det-1', sequence: 2, kind: 'commitment_sealed', status: 'complete', evidence_id: 'ev-1', agent_id: 'a1', asset_id: 's1', previous_hash: 'h1', hash: 'h2', occurred_at: '2026-09-05T09:00:00Z' }] })
    const trans = await api.detectionProvenanceTransitions('eng-1', 'det-1')
    expect(trans[0]).toMatchObject({ sequence: 2, kind: 'commitment_sealed', hash: 'h2', previousHash: 'h1' })
  })

  it('maps PascalCase occurrence events', async () => {
    respond([{ ID: 'ev-1', OccurrenceID: 'occ-1', EventType: 'detected', AdvisoryRevision: 1, FromState: '', ToState: 'detected', CreatedAt: '2026-09-05T09:00:00Z' }])
    const events = await api.engagementVulnerabilityOccurrenceEvents('eng-1', 'occ-1')
    expect(events[0]).toMatchObject({ id: 'ev-1', eventType: 'detected', toState: 'detected' })
  })

  it('maps the current risk and returns null on 404', async () => {
    respond({ ID: 'ra-1', OccurrenceID: 'occ-1', Severity: 'high', CVSSScore: 7.5, KEV: true, RiskScore: 8.1, Priority: 1, ReasonCodes: ['kev'], AssessedAt: '2026-09-05T09:00:00Z' })
    const risk = await api.engagementVulnerabilityOccurrenceRisk('eng-1', 'occ-1')
    expect(risk).toMatchObject({ id: 'ra-1', severity: 'high', kev: true, riskScore: 8.1, priority: 1 })

    respond({ error: 'not found' }, 404)
    expect(await api.engagementVulnerabilityOccurrenceRisk('eng-1', 'occ-1')).toBeNull()
  })

  it('maps the paged risk history', async () => {
    respond({ items: [{ ID: 'ra-0', OccurrenceID: 'occ-1', RiskScore: 6, Priority: 2, AssessedAt: '2026-09-01T09:00:00Z' }], next: null })
    const hist = await api.engagementVulnerabilityOccurrenceRiskHistory('eng-1', 'occ-1')
    expect(hist).toHaveLength(1)
    expect(hist[0]).toMatchObject({ id: 'ra-0', riskScore: 6, priority: 2 })
  })
})
