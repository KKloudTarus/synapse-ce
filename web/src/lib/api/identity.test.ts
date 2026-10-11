import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './client'
import { identityApi } from './identity'

describe('identityApi', () => {
  const fetchSpy = vi.fn<typeof fetch>()

  beforeEach(() => {
    fetchSpy.mockReset()
    vi.stubGlobal('fetch', fetchSpy)
  })

  function respond(body: unknown, status = 200): void {
    fetchSpy.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(),
      json: async () => body,
    } as Response)
  }

  it('maps the identity connection contract fields used by activation', async () => {
    respond({
      connections: [{
        id: 'connection-a',
        display_name: 'Primary identity',
        issuer: 'https://issuer.example',
        enabled: false,
        revision: 2,
        draft_revision: 3,
        version: 7,
        test_passed: true,
      }],
    })

    await expect(identityApi.connections()).resolves.toEqual([{
      id: 'connection-a',
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      enabled: false,
      revision: 2,
      draftRevision: 3,
      version: 7,
      testPassed: true,
    }])
  })

  it('sends the display name and bootstrap proof without persisting either', async () => {
    respond({ id: 'connection-a' })

    await identityApi.draftConnection({
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      clientId: 'client-id',
      clientSecret: 'client-secret',
    }, 'proof')

    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/identity/connections/draft', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        display_name: 'Primary identity',
        issuer: 'https://issuer.example',
        client_id: 'client-id',
        client_secret: 'client-secret',
        bootstrap_eligibility: 'proof',
      }),
    }))
  })

  it('preserves a conflict response so callers can refresh the optimistic value', async () => {
    respond({ error: 'stale version', code: 'conflict' }, 409)

    const error = await identityApi.savePolicy({ requirement: 'required', version: 5 }).catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(409)
  })

  it('accepts the recovery alert projection returned by the current server', async () => {
    respond({ alerts: [{ ID: 'alert-a', State: 'delivered', Attempts: 1, MaxAttempts: 3, CreatedAt: '2026-10-02T00:00:00Z' }] })

    await expect(identityApi.alerts()).resolves.toEqual([{
      id: 'alert-a',
      membershipId: '',
      sessionId: '',
      state: 'delivered',
      attempts: 1,
      maxAttempts: 3,
      nextAttemptAt: '',
      createdAt: '2026-10-02T00:00:00Z',
    }])
  })

  it('returns only a server-provided HTTPS authorization destination for connection tests', async () => {
    respond({ authorization_url: 'https://issuer.example/authorize?state=opaque' })
    await expect(identityApi.testConnection('connection-a', 'proof')).resolves.toEqual({ authorizationURL: 'https://issuer.example/authorize?state=opaque' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/identity/connections/test', expect.objectContaining({ method: 'POST', body: JSON.stringify({ id: 'connection-a', bootstrap_eligibility: 'proof' }) }))
  })

  it.each([{}, { authorization_url: 'http://issuer.example/authorize' }, { authorization_url: 'not a url' }])('rejects a missing or unsafe connection-test destination', async (body) => {
    respond(body)
    await expect(identityApi.testConnection('connection-a')).rejects.toThrow()
  })
})
