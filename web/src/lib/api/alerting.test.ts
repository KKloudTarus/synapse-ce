import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, AlertNotEnabledError } from '.'

describe('alerting testAlert', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('maps a 200 acknowledged outcome', async () => {
    respond({ outcome: { matched: true, delivered: 2, failed: 0, audit_failed: 0 } })
    const r = await api.testAlert()
    expect(r.acknowledged).toBe(true)
    expect(r.outcome).toEqual({ matched: true, delivered: 2, failed: 0, auditFailed: 0 })
  })

  it('reads the outcome from a 502 no-acknowledgement body', async () => {
    respond({ error: 'no alert sink acknowledged the test alert', outcome: { matched: true, delivered: 0, failed: 3, audit_failed: 1 } }, 502)
    const r = await api.testAlert()
    expect(r.acknowledged).toBe(false)
    expect(r.error).toContain('no alert sink acknowledged')
    expect(r.outcome).toEqual({ matched: true, delivered: 0, failed: 3, auditFailed: 1 })
  })

  it('throws AlertNotEnabledError on 404', async () => {
    respond({ error: 'not found' }, 404)
    await expect(api.testAlert()).rejects.toBeInstanceOf(AlertNotEnabledError)
  })
})
