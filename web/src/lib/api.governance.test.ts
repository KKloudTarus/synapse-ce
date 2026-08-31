import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from './api'

// Privacy & data governance (#635). legalhold.Hold is untagged PascalCase; the export bundle mixes a
// snake_case view with PascalCase holds. These pin both mappings + the request shapes.
describe('governance API (#635)', () => {
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('maps the PascalCase legal-hold list', async () => {
    respond({
      holds: [
        {
          TenantID: 'default',
          EngagementID: 'eng-1',
          Reason: 'litigation',
          PlacedBy: 'operator',
          PlacedAt: '2026-08-30T00:00:00Z',
          ReleasedBy: '',
          ReleasedAt: '0001-01-01T00:00:00Z',
        },
      ],
    })
    const holds = await api.listLegalHolds()
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/fleet/legal-holds', expect.any(Object))
    expect(holds[0]).toEqual({
      tenantId: 'default',
      engagementId: 'eng-1',
      reason: 'litigation',
      placedBy: 'operator',
      placedAt: '2026-08-30T00:00:00Z',
      releasedBy: '',
      releasedAt: '0001-01-01T00:00:00Z',
    })
  })

  it('places a hold with a reason body (PUT)', async () => {
    respond({ TenantID: 'default', EngagementID: 'eng-1', Reason: 'r', PlacedBy: 'op' })
    await api.placeLegalHold('eng-1', 'r')
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/fleet/engagements/eng-1/legal-hold')
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('PUT')
    expect(JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string)).toEqual({ reason: 'r' })
  })

  it('maps the export bundle (snake_case view + PascalCase holds)', async () => {
    respond({
      engagement_id: 'eng-1',
      generated_at: '2026-08-30T00:00:00Z',
      detection_count: 5,
      legal_holds: [{ EngagementID: 'eng-1', Reason: 'hold' }],
    })
    const b = await api.privacyExport('eng-1')
    expect(b.engagementId).toBe('eng-1')
    expect(b.detectionCount).toBe(5)
    expect(b.legalHolds[0].reason).toBe('hold')
  })

  it('purges detection data with a reason body (DELETE) and reads the purged count', async () => {
    respond({ purged: 3 })
    const res = await api.purgeEngagementDetectionData('eng-1', 'erasure')
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/fleet/engagements/eng-1/detection-data')
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('DELETE')
    expect(JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string)).toEqual({ reason: 'erasure' })
    expect(res.purged).toBe(3)
  })
})
