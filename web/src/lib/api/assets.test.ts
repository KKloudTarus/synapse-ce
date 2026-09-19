import { beforeEach, describe, expect, it, vi } from 'vitest'
import { assetsApi } from './assets'

describe('business asset finding reader compatibility', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('opts into the external finding kind and maps the reader projection', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [{
        finding: { ID: 'if-1', Kind: 'external', Title: 'Imported SQL injection', Severity: 'high', Status: 'triage' },
        external: true,
        can_self_promote: false,
        suppressed_by_tool: false,
        reachability: { state: 'unknown', tier: 'tier-0', confidence: 0, source: 'external', history: [] },
        engagement_id: 'eng-1',
        engagement_name: 'Assessment',
      }],
    } as Response)

    const rows = await assetsApi.businessAssetFindings('asset one')
    const [url, init] = fetchSpy.mock.calls[0]

    expect(url).toBe('/api/v1/appsec/assets/asset%20one/findings')
    expect((init as RequestInit).headers).toMatchObject({
      'X-Synapse-Client-Capabilities': 'external-finding-kind-v1',
    })
    expect(rows[0]).toMatchObject({
      external: true,
      canSelfPromote: false,
      finding: { id: 'if-1', kind: 'external', status: 'triage' },
      reachability: { state: 'unknown', tier: 'tier-0', source: 'external' },
    })
  })
})
