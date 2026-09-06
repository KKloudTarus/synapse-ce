import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, daysToNs, nsToDays } from '.'
import type { SLAConfig } from '.'

const DAY = 86_400_000_000_000

function policyWire() {
  return {
    tenant_id: 'tenant-dev',
    sha256: 'deadbeef',
    created_by: 'admin@dev',
    created_at: '2026-08-01T00:00:00Z',
    config: {
      version: 'sla-v1',
      weights: { severity: 35, exploitability: 25, threat_intel: 10, exposure: 15, criticality: 15, feasibility_relief: 15 },
      thresholds: { emergency: 85, critical: 70, high: 50, medium: 30 },
      due_ranges: {
        emergency: { mitigate_within: 1 * DAY, remediate_within: 7 * DAY },
        critical: { mitigate_within: 3 * DAY, remediate_within: 15 * DAY },
        high: { mitigate_within: 7 * DAY, remediate_within: 30 * DAY },
        medium: { mitigate_within: 30 * DAY, remediate_within: 90 * DAY },
        low: { mitigate_within: 90 * DAY, remediate_within: 180 * DAY },
        exception: { mitigate_within: 30 * DAY, remediate_within: 180 * DAY },
      },
    },
  }
}

describe('sla mapper', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('maps snake_case weights and ns due-ranges into days', async () => {
    respond({ active: policyWire(), policies: [policyWire()] })
    const r = await api.slaPolicies()
    expect(r!.active!.config.weights).toMatchObject({ threatIntel: 10, feasibilityRelief: 15, severity: 35 })
    expect(r!.active!.config.dueRanges.emergency).toEqual({ mitigateDays: 1, remediateDays: 7 })
    expect(r!.active!.config.dueRanges.low).toEqual({ mitigateDays: 90, remediateDays: 180 })
    expect(r!.active!.createdBy).toBe('admin@dev')
  })

  it('nsToDays/daysToNs round-trip exactly on day-granular values', () => {
    for (const d of [0, 1, 3, 7, 15, 30, 90, 180, 365]) {
      expect(nsToDays(daysToNs(d))).toBe(d)
    }
  })

  it('treats a zero/empty active policy as none', async () => {
    respond({ active: { tenant_id: '', created_by: '', created_at: '0001-01-01T00:00:00Z', config: { version: '', weights: {}, thresholds: {}, due_ranges: {} } }, policies: [] })
    const r = await api.slaPolicies()
    expect(r!.active).toBeNull()
  })

  it('POST activate sends day windows back as nanoseconds', async () => {
    respond({ policy: policyWire(), created: true }, 201)
    const cfg: SLAConfig = {
      version: 'sla-v2',
      weights: { severity: 40, exploitability: 20, threatIntel: 10, exposure: 15, criticality: 15, feasibilityRelief: 10 },
      thresholds: { emergency: 90, critical: 70, high: 50, medium: 30 },
      dueRanges: {
        emergency: { mitigateDays: 1, remediateDays: 5 },
        critical: { mitigateDays: 2, remediateDays: 10 },
        high: { mitigateDays: 7, remediateDays: 30 },
        medium: { mitigateDays: 30, remediateDays: 90 },
        low: { mitigateDays: 90, remediateDays: 180 },
        exception: { mitigateDays: 30, remediateDays: 180 },
      },
    }
    const res = await api.activateSLAPolicy(cfg)
    expect(res.created).toBe(true)
    const body = JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body))
    expect(body.config.weights.threat_intel).toBe(10)
    expect(body.config.due_ranges.emergency).toEqual({ mitigate_within: 1 * DAY, remediate_within: 5 * DAY })
    expect(body.config.version).toBe('sla-v2')
  })

  it('returns null when SLA governance is not enabled (404)', async () => {
    respond({ error: 'not found' }, 404)
    expect(await api.slaPolicies()).toBeNull()
  })
})
