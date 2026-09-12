import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ownershipApi } from './ownership'

function response(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

describe('ownership API contract', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('encodes inbox filters and pagination without leaking empty values', async () => {
    fetchSpy.mockResolvedValueOnce(response({ items: [], total: 0 }))
    await ownershipApi.ownershipInbox(
      { engagement_id: 'eng/a', my_teams: true, severity: 'critical', team_id: undefined },
      'finding/1',
    )

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/v1/ownership/findings?engagement_id=eng%2Fa&my_teams=true&severity=critical&cursor=finding%2F1&limit=100')
    expect(init).toMatchObject({ credentials: 'same-origin' })
  })

  it('sends an exact idempotency key and frozen preview id for reroute', async () => {
    fetchSpy.mockResolvedValueOnce(response({ id: 'run-1' }))
    await ownershipApi.startOwnershipRun(
      'policy/a',
      'reroute',
      { version: 3, policy_revision: 5, policy_hash: 'sha256', preview_id: 'preview-1', filter: { engagement_id: 'eng-1' } },
      'operation-123',
    )

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/v1/ownership/policies/policy%2Fa/reroute')
    expect(init).toMatchObject({
      method: 'POST',
      headers: expect.objectContaining({ 'Idempotency-Key': 'operation-123' }),
    })
    expect(JSON.parse(String(init?.body))).toMatchObject({ preview_id: 'preview-1', policy_revision: 5 })
  })

  it('unwraps independent bulk outcomes and preserves optimistic versions', async () => {
    const outcomes = [
      { engagement_id: 'eng-1', finding_id: 'finding-1', status: 200 },
      { engagement_id: 'eng-1', finding_id: 'finding-2', status: 409, error: 'conflict' },
    ]
    fetchSpy.mockResolvedValueOnce(response({ items: outcomes }))
    const input = [{
      engagement_id: 'eng-1', finding_id: 'finding-2', action: 'release' as const,
      finding_version: 11, ownership_revision: 7, manual_generation: 4,
    }]

    await expect(ownershipApi.bulkOwnership(input, 'bulk-1')).resolves.toEqual(outcomes)
    const [, init] = fetchSpy.mock.calls[0]
    expect(JSON.parse(String(init?.body))).toEqual({ items: input })
    expect(init?.headers).toMatchObject({ 'Idempotency-Key': 'bulk-1' })
  })

  it('requires explicit diagnostic acceptance when approving an exact snapshot hash', async () => {
    fetchSpy.mockResolvedValueOnce(response({ id: 'snapshot-1' }))
    await ownershipApi.approveOwnershipSnapshot('snapshot/1', 'hash-1', true)

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/v1/ownership/snapshots/snapshot%2F1/approve')
    expect(JSON.parse(String(init?.body))).toEqual({ content_hash: 'hash-1', accept_diagnostics: true })
  })
})
