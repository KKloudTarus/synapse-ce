import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '.'

// The DAST scan and runtime-verification adapters. Requests carry json tags (snake_case); the
// Proposal / ApprovalDecision / runner Result responses have no Go json tags (PascalCase). Each
// mapper must read the exact casing.
describe('dast adapters', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }
  const lastBody = () => JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body))

  it('proposes a scan and maps the PascalCase proposal', async () => {
    respond({ Action: { ID: 'act-1', Tool: 'zap', Action: 'scan', Target: { Kind: 'url', Value: 'https://t' }, EgressPreview: 'GET https://t', Risk: 'medium', Rationale: 'crawl and probe' }, Decision: { State: 'pending' } }, 202)
    const p = await api.proposeDastScan('eng-1', { target: 'https://t', maxPages: 10 })
    expect(p).toMatchObject({ actionId: 'act-1', tool: 'zap', targetValue: 'https://t', risk: 'medium', decisionState: 'pending' })
    expect(lastBody()).toMatchObject({ target: 'https://t', crawler: { max_pages: 10 } })
  })

  it('runs a scan and maps the result surface/coverage/proofs', async () => {
    respond({ config_sha256: 'abc123', incomplete: false, surface: { Requests: [{}, {}] }, coverage: { Entries: [{}] }, proofs: [{ check_id: 'xss.reflected', version: '1', normalized_endpoint: 'GET /q', hash: 'deadbeef' }] })
    const r = await api.runDastScan('eng-1', 'act-1', { target: 'https://t' })
    expect(r).toMatchObject({ digest: 'abc123', incomplete: false, requestCount: 2, coverageCount: 1 })
    expect(r.proofs[0]).toMatchObject({ checkId: 'xss.reflected', normalizedEndpoint: 'GET /q', hash: 'deadbeef' })
  })

  it('decides an approval and maps the PascalCase decision', async () => {
    respond({ ActionID: 'act-1', State: 'approved', DecidedBy: 'ana', Reason: 'scoped', DecidedAt: '2026-09-05T09:00:00Z' })
    const d = await api.decideDastApproval('eng-1', 'act-1', true, 'scoped')
    expect(d).toMatchObject({ actionId: 'act-1', state: 'approved', decidedBy: 'ana' })
    expect(lastBody()).toEqual({ approve: true, reason: 'scoped' })
  })

  it('runs a runtime verification in the durable shape (a run to poll)', async () => {
    respond({ id: 'run-1', status: 'queued', verdict: '', started_at: '2026-09-05T09:00:00Z' }, 202)
    const o = await api.runRuntimeVerification('eng-1', 'jud-1', 'act-1', { url: 'https://t', method: 'GET', expectedStatus: 200, scoreIfConfirmed: 90, scoreIfRefuted: 10, version: 3 })
    expect(o.durable).toBe(true)
    expect(o.run).toMatchObject({ id: 'run-1', status: 'queued' })
    expect(lastBody()).toMatchObject({ url: 'https://t', expected_status: 200, score_if_confirmed: 90, version: 3 })
  })

  it('runs a runtime verification in the in-memory shape (a PascalCase result)', async () => {
    respond({ Proof: 'runtime_confirmed', Status: 200, Evidence: 'ev-9' })
    const o = await api.runRuntimeVerification('eng-1', 'jud-1', 'act-1', { url: 'https://t', method: 'GET', expectedStatus: 200, scoreIfConfirmed: 90, scoreIfRefuted: 10, version: 3 })
    expect(o.durable).toBe(false)
    expect(o).toMatchObject({ proof: 'runtime_confirmed', status: 200, evidenceId: 'ev-9' })
  })
})
