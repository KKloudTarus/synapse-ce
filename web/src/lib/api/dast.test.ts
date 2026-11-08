import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '.'

// The DAST scan and runtime-verification adapters. Requests carry json tags (snake_case); the
// Proposals have a lowercase envelope and PascalCase nested fields; older envelopes
// and runner results use PascalCase.
describe('dast adapters', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }
  const lastBody = () => JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body))
  const session = { scheme: 'bearer' as const, credentials: [{ name: 'token', reference: 'vault://engagement/token', field: 'token' }], login_request: { method: 'GET', path: '/' }, success: { status_code: 200 }, check_request: { method: 'GET', path: '/' } }

  it('proposes a scan and maps the PascalCase proposal', async () => {
    respond({ Action: { ID: 'act-1', Tool: 'zap', Action: 'scan', Target: { Kind: 'url', Value: 'https://t' }, EgressPreview: 'GET https://t', Risk: 'medium', Rationale: 'crawl and probe' }, Decision: { State: 'pending' } }, 202)
    const p = await api.proposeDastScan('eng-1', { target: 'https://t', session, maxPages: 10 })
    expect(p).toMatchObject({ actionId: 'act-1', tool: 'zap', targetValue: 'https://t', risk: 'medium', decisionState: 'pending' })
    expect(lastBody()).toMatchObject({ target: 'https://t', session, crawler: { max_pages: 10 } })
  })

  it('preserves the runtime proposal ID from the server envelope for approval', async () => {
    respond({ action: { ID: 'probe-action', Tool: 'run_dast_verifier', Target: { Kind: 'url', Value: 'https://t/fixture' } }, decision: { State: 'pending' } }, 202)
    const p = await api.proposeRuntimeVerification('eng-1', 'jud-1', { url: 'https://t/fixture', method: 'GET', expectedStatus: 200, scoreIfConfirmed: 90, scoreIfRefuted: 10, version: 1 })
    expect(p).toMatchObject({ actionId: 'probe-action', targetValue: 'https://t/fixture', decisionState: 'pending' })
    respond({ ActionID: 'probe-action', State: 'approved' })
    await api.decideDastApproval('eng-1', p.actionId, true, 'fixture only')
    expect(String(fetchSpy.mock.calls[1][0])).toContain('/dast/approvals/probe-action/decide')
  })

  it('maps queued and terminal scan runs without inventing an empty result', async () => {
    const envelope = { id: 'run-1', kind: 'authenticated_scan', engagement_id: 'eng-1', action_id: 'act-1', actor: 'ana' }
    respond({ ...envelope, status: 'queued' }, 202)
    const queued = await api.runDastScan('eng-1', 'act-1', { target: 'https://t', session })
    expect(queued).toMatchObject({ status: 'queued', result: null })
    expect(String(fetchSpy.mock.calls[0][0])).toContain('/dast/proposals/act-1/run')
    respond({ ...envelope, status: 'incomplete', result: { config_sha256: 'abc123', incomplete: true, reason: 'limit', surface: { Requests: [{}, {}] }, coverage: { Entries: [{}] }, proofs: [{ check_id: 'xss.reflected', version: 2, normalized_endpoint: 'GET /q', hash: 'deadbeef' }] } })
    const run = await api.getDastScanRun('eng-1', queued.id)
    expect(run.result).toMatchObject({ digest: 'abc123', incomplete: true, requestCount: 2, coverageCount: 1, proofs: [{ checkId: 'xss.reflected', version: 2 }] })
    expect(String(fetchSpy.mock.calls[1][0])).toContain('/dast/scans/runs/run-1')
  })

  it('rejects a synthetic string proof version', async () => {
    respond({ id: 'run-1', kind: 'authenticated_scan', engagement_id: 'eng-1', action_id: 'act-1', actor: 'ana', status: 'succeeded', result: { config_sha256: 'abc', incomplete: false, surface: {}, coverage: {}, proofs: [{ check_id: 'xss.reflected', version: '2', normalized_endpoint: 'GET /q', hash: 'deadbeef' }] } })
    await expect(api.getDastScanRun('eng-1', 'run-1')).rejects.toThrow('Invalid authenticated scan proof')
  })

  it('rejects malformed scan status, kind and terminal results', async () => {
    const envelope = { id: 'run-1', kind: 'authenticated_scan', engagement_id: 'eng-1', action_id: 'act-1', actor: 'ana', status: 'succeeded' }
    for (const bad of [{ ...envelope, status: 'unknown' }, { ...envelope, kind: 'verifier' }, envelope, { ...envelope, result: { config_sha256: 'abc', incomplete: true, surface: {}, coverage: {} } }, { ...envelope, status: 'queued', result: {} }]) {
      respond(bad)
      await expect(api.getDastScanRun('eng-1', 'run-1')).rejects.toThrow(/Invalid authenticated scan/)
    }
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
