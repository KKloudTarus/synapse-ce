import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from './api'

describe('fleet desired-capability gaps mapping (#633)', () => {
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  // ReconciliationRow is snake_case-tagged; this pins the field reads.
  it('maps the snake_case gap rows into the camelCase view', async () => {
    respond({
      gaps: [
        {
          asset_id: 'asset-1',
          capability: 'edr.process',
          covered: false,
          agent_id: 'agent-2',
          agent_health: 'stale',
          gap_reason: 'no_agent',
          detail: 'no agent advertises this capability',
          last_seen: '2026-08-30T00:00:00Z',
        },
      ],
    })

    const gaps = await api.fleetDesiredGaps()

    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/fleet/desired-capabilities/gaps', expect.any(Object))
    expect(gaps[0]).toEqual({
      assetId: 'asset-1',
      capability: 'edr.process',
      covered: false,
      agentId: 'agent-2',
      agentHealth: 'stale',
      gapReason: 'no_agent',
      detail: 'no agent advertises this capability',
      lastSeen: '2026-08-30T00:00:00Z',
    })
  })

  it('returns an empty list when the response has no gaps array', async () => {
    respond({})
    await expect(api.fleetDesiredGaps()).resolves.toEqual([])
  })
})
