import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from './api'

describe('dashboardSecurityOperations', () => {
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  function respond(body: unknown) {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => body } as unknown as Response)
  }

  // The completeness flags decide whether the dashboard tells the operator that part of the picture is
  // missing. Their DEFAULTS therefore matter as much as their values: an older or partial server
  // response must not be read as "everything was included", because the charts would then present an
  // incomplete risk mix as the whole one.
  it('defaults completeness fields to the honest answer when the server omits them', async () => {
    respond({ range_days: 30 })

    const summary = await api.dashboardSecurityOperations()

    expect(summary.externalFindingsIncluded).toBe(false)
    expect(summary.findingsWithoutTimestamp).toBe(0)
  })

  it(`carries the server completeness answer through unchanged`, async () => {
    respond({ range_days: 7, findings_without_timestamp: 4, external_findings_included: true })

    const summary = await api.dashboardSecurityOperations(7)

    expect(summary.rangeDays).toBe(7)
    expect(summary.findingsWithoutTimestamp).toBe(4)
    expect(summary.externalFindingsIncluded).toBe(true)
  })

  it('requests the range the caller asked for', async () => {
    respond({})

    await api.dashboardSecurityOperations(90)

    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/dashboard/security-operations?range=90d', expect.any(Object))
  })
})
