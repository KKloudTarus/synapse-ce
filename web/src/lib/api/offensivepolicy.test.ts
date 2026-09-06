import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '.'

describe('offensivePolicy mapper', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('reads the snake_case register DTO', async () => {
    respond({
      legal_review: { reviewed: true, date: '2026-08-01', owner: 'sec', counsel_reviewed: true, counsel_date: '2026-08-04' },
      techniques: [
        { technique: 'recon.port_scan', taxonomy_ref: 'TA0043', disruption: 'none', reversibility: 'reversible', risk_class: 'low', approval: 'auto', blast_radius: 'read_only', production_safe: true, prohibited: false },
        { technique: 'impact.data_destruction', taxonomy_ref: 'T1485', disruption: 'high', reversibility: 'irreversible', risk_class: 'prohibited', approval: '', blast_radius: 'destructive', production_safe: false, prohibited: true },
      ],
      prohibited: 1,
      production_safe: 1,
    })
    const r = await api.offensivePolicy()
    expect(r!.legalReview).toMatchObject({ reviewed: true, counselReviewed: true, owner: 'sec', counselDate: '2026-08-04' })
    expect(r!.techniques[0]).toMatchObject({ technique: 'recon.port_scan', taxonomyRef: 'TA0043', riskClass: 'low', blastRadius: 'read_only', productionSafe: true, prohibited: false })
    expect(r!.techniques[1]).toMatchObject({ riskClass: 'prohibited', prohibited: true, productionSafe: false })
    expect(r!.prohibited).toBe(1)
    expect(r!.productionSafe).toBe(1)
  })

  it('returns null when the register is not loaded (404)', async () => {
    respond({ error: 'not found' }, 404)
    expect(await api.offensivePolicy()).toBeNull()
  })
})
