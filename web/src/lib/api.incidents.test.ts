import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from './api'

// The incident + timeline handlers serialize the Go domain structs with NO json tags, so the wire
// shape is PascalCase. These tests pin that mapping — a backend field rename (or a frontend regression
// back to snake_case) would surface here instead of silently blanking the analyst view.
describe('incidents API mapping', () => {
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('maps the PascalCase incident list into the camelCase view', async () => {
    respond({
      incidents: [
        {
          ID: 'inc-1',
          AssetID: 'asset-1',
          Title: 'Suspicious beacon',
          Severity: 'high',
          State: 'open',
          Disposition: 'unknown',
          OwnerID: 'analyst-1',
          DetectionIDs: ['det-1', 'det-2'],
          Risk: {
            AssessmentID: 'ra-1',
            Risk: 88,
            Confidence: 61,
            Coverage: 43,
            CoverageVector: { Process: 90, Network: 40, File: 0, Privilege: 0, Reasons: ['no_file_sensor'] },
            FactorContributions: [{ Factor: 'threat', Points: 50, Detail: 'beacon' }],
            ReasonCodes: ['beacon_confirmed'],
            CreatedAt: '2026-08-30T00:00:00Z',
          },
          Comments: [{ At: '2026-08-30T01:00:00Z', Actor: 'analyst-1', Text: 'looking' }],
          Responses: [{ ActionID: 'act-1', Verified: true }],
          Revision: 3,
          CreatedAt: '2026-08-30T00:00:00Z',
          UpdatedAt: '2026-08-30T02:00:00Z',
        },
      ],
      truncated: true,
    })

    const res = await api.listIncidents({ state: 'open', limit: 50 })

    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/fleet/incidents?state=open&limit=50', expect.any(Object))
    expect(res.truncated).toBe(true)
    const inc = res.incidents[0]
    expect(inc.id).toBe('inc-1')
    expect(inc.title).toBe('Suspicious beacon')
    expect(inc.severity).toBe('high')
    expect(inc.state).toBe('open')
    expect(inc.ownerId).toBe('analyst-1')
    expect(inc.detectionIds).toEqual(['det-1', 'det-2'])
    // The tri-score axes are independent — a low coverage must survive the mapping, not collapse.
    expect(inc.risk?.risk).toBe(88)
    expect(inc.risk?.confidence).toBe(61)
    expect(inc.risk?.coverage).toBe(43)
    expect(inc.risk?.coverageVector.process).toBe(90)
    expect(inc.risk?.coverageVector.reasons).toEqual(['no_file_sensor'])
    expect(inc.risk?.factorContributions[0]).toEqual({ factor: 'threat', points: 50, detail: 'beacon' })
    expect(inc.comments[0]).toEqual({ at: '2026-08-30T01:00:00Z', actor: 'analyst-1', text: 'looking' })
    expect(inc.responses[0]).toEqual({ actionId: 'act-1', verified: true })
  })

  it('tolerates a null Risk (an unscored incident) without throwing', async () => {
    respond({ incidents: [{ ID: 'inc-2', Title: 'x', Risk: null }], truncated: false })
    const res = await api.listIncidents()
    expect(res.incidents[0].risk).toBeNull()
    expect(res.incidents[0].detectionIds).toEqual([])
  })

  it('posts analyst mutations with the exact request bodies the handlers expect', async () => {
    respond({ ID: 'inc-1', State: 'triaged' })
    await api.changeIncidentStatus('inc-1', 'triaged')
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/fleet/incidents/inc-1/status')
    expect(JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string)).toEqual({ to: 'triaged' })

    respond({ ID: 'inc-1', Disposition: 'false_positive' })
    await api.setIncidentDisposition('inc-1', 'false_positive')
    expect(fetchSpy.mock.calls[1][0]).toBe('/api/v1/fleet/incidents/inc-1/disposition')
    expect(JSON.parse((fetchSpy.mock.calls[1][1] as RequestInit).body as string)).toEqual({ disposition: 'false_positive' })

    respond({ ID: 'inc-1' })
    await api.commentIncident('inc-1', 'note')
    expect(JSON.parse((fetchSpy.mock.calls[2][1] as RequestInit).body as string)).toEqual({ text: 'note' })

    respond({ ID: 'inc-1' })
    await api.assignIncidentOwner('inc-1', 'analyst-2')
    expect(JSON.parse((fetchSpy.mock.calls[3][1] as RequestInit).body as string)).toEqual({ owner: 'analyst-2' })
  })

  it('maps the PascalCase State Timeline entries', async () => {
    respond({
      entries: [
        { OccurredAt: '2026-08-30T00:00:00Z', AssetID: 'asset-1', EntityKind: 'process', EntityID: 'p1', Kind: 'process_start', EventID: 'e1', Summary: 'nginx started' },
      ],
    })

    const entries = await api.assetTimeline('asset-1', { limit: 100 })

    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/fleet/assets/asset-1/timeline?limit=100', expect.any(Object))
    expect(entries[0]).toEqual({
      occurredAt: '2026-08-30T00:00:00Z',
      assetId: 'asset-1',
      entityKind: 'process',
      entityId: 'p1',
      kind: 'process_start',
      eventId: 'e1',
      summary: 'nginx started',
    })
  })
})
