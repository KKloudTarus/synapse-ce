import { afterEach, describe, expect, it, vi } from 'vitest'
import { siemApi } from './siem'

describe('siem API', () => {
  afterEach(() => vi.restoreAllMocks())

  it('treats a missing route as an unavailable feature', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: 'not found' }),
    } as Response)
    expect(await siemApi.listSIEMSinks()).toBeNull()
  })

  it('creates a sink without reading the secret back', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({ id: 's1', name: 'Main', secret_version: 1, version: 1 }),
    } as Response)
    const sink = await siemApi.createSIEMSink({
      name: 'Main',
      provider: 'splunk_hec',
      origin: 'https://splunk.example:8088',
      secret: 'splunk-token',
    })
    expect(sink.id).toBe('s1')
    expect(JSON.stringify(sink)).not.toContain('splunk-token')
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/siem/sinks',
      expect.objectContaining({ method: 'POST' }),
    )
  })
})
