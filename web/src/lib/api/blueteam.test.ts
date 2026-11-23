import { beforeEach, describe, expect, it, vi } from 'vitest'
import { req } from './client'
import { blueteamApi } from './blueteam'

vi.mock('./client', () => ({ req: vi.fn() }))

describe('governed response API', () => {
  beforeEach(() => vi.resetAllMocks())

  it('retains a consumed approval state from the response ledger', async () => {
    vi.mocked(req).mockResolvedValue({ responses: [{ id: 'r', approval_state: 'consumed' }] })
    expect(await blueteamApi.listResponses()).toMatchObject([{ id: 'r', approvalState: 'consumed' }])
  })

  it('retains the durable target binding and serializes apply, decision and reversal', async () => {
    const target = `pe_${'a'.repeat(32)}`
    const fingerprint = { kind: 'process', process_asset_id: 'asset-1', process_entity_id: target }
    vi.mocked(req).mockResolvedValue({ id: 'r', kind: 'stop_process', target, state: 'applied', target_kind: 'process', fingerprint, submitted_by: 'alice', reversal_requested_by: 'bob', approval_state: 'approved' })
    const body = { kind: 'stop_process' as const, target, target_kind: 'process', fingerprint }
    const { record } = await blueteamApi.applyResponse('eng-1', body)
    expect(req).toHaveBeenLastCalledWith('/blueteam/engagements/eng-1/response/apply', { method: 'POST', body: JSON.stringify(body) })
    expect(record).toMatchObject({ targetKind: 'process', fingerprint, submittedBy: 'alice', reversalRequestedBy: 'bob', approvalState: 'approved' })
    await blueteamApi.decideResponse('r', { approve: false, reason: 'no' })
    expect(req).toHaveBeenLastCalledWith('/blueteam/response/r/decide', { method: 'POST', body: JSON.stringify({ approve: false, reason: 'no' }) })
    await blueteamApi.revertResponse('r', { target, target_kind: 'process', fingerprint })
    expect(req).toHaveBeenLastCalledWith('/blueteam/response/r/revert', { method: 'POST', body: JSON.stringify({ target, target_kind: 'process', fingerprint }) })
  })
})
