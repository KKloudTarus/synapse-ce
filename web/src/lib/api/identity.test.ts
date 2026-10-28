import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, setCSRFToken, setToken } from './client'
import { identityApi } from './identity'

describe('identityApi', () => {
  const fetchSpy = vi.fn<typeof fetch>()

  beforeEach(() => {
    setToken('')
    setCSRFToken('')
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

  it('round trips Entra discovery modes independently for active and draft revisions', async () => {
    respond({ connections: [{ id: 'entra', issuer: 'https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0', entra_discovery_mode: 'common', draft_entra_discovery_mode: 'organizations' }] })
    const [connection] = await identityApi.connections()
    expect(connection).toMatchObject({ entraDiscoveryMode: 'common', draftEntraDiscoveryMode: 'organizations' })
    respond({})
    await identityApi.draftConnection({ displayName: 'Entra', issuer: connection.issuer, clientId: 'client', clientSecret: 'secret', entraDiscoveryMode: 'organizations' })
    expect(JSON.parse(fetchSpy.mock.calls.at(-1)![1]!.body as string)).toHaveProperty('entra_discovery_mode', 'organizations')
  })

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

  it('decodes an optional Auth0 organization restriction without exposing connection settings', async () => {
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
        auth0_organization_id: 'org_CaseSensitive',
        settings: { client_secret: 'must-not-be-projected' },
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
      auth0OrganizationId: 'org_CaseSensitive',
    }])
  })

  it('maps an administrative native client ID only for connection updates', async () => {
    respond({
      connections: [
        {
          id: 'legacy', display_name: 'Imported identity', issuer: 'https://issuer.example', enabled: false,
          revision: 1, draft_revision: 2, version: 2, test_passed: false,
          configuration_pending: true, client_id: 'pinned-client',
        },
        {
          id: 'native', display_name: 'Native identity', issuer: 'https://native.example', enabled: false,
        revision: 1, draft_revision: 1, version: 1, test_passed: false, client_id: 'native-client',
        },
      ],
    })

    await expect(identityApi.connections()).resolves.toEqual([
      {
        id: 'legacy', displayName: 'Imported identity', issuer: 'https://issuer.example', enabled: false,
        revision: 1, draftRevision: 2, version: 2, testPassed: false,
        configurationPending: true, clientId: 'pinned-client',
      },
      {
        id: 'native', displayName: 'Native identity', issuer: 'https://native.example', enabled: false,
        revision: 1, draftRevision: 1, version: 1, testPassed: false,
        clientId: 'native-client',
      },
    ])
  })

  it('does not retain connection settings from the public sign-in context', async () => {
    respond({
      enabled: true,
      tenant_id: 'tenant-a',
      requirement: 'required',
      connections: [{ id: 'connection-a', name: 'Primary identity', client_id: 'must-not-project', configuration_pending: true }],
    })

    await expect(identityApi.context()).resolves.toEqual(expect.objectContaining({
      connections: [expect.not.objectContaining({ clientId: expect.anything() })],
    }))
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

  it('sends an exact optional Auth0 organization ID and omits it for old empty drafts', async () => {
    respond({ id: 'connection-a' })
    await identityApi.draftConnection({
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      auth0OrganizationId: 'org_CaseSensitive',
    })

    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections/draft', expect.objectContaining({
      body: JSON.stringify({
        display_name: 'Primary identity',
        issuer: 'https://issuer.example',
        client_id: 'client-id',
        client_secret: 'client-secret',
        auth0_organization_id: 'org_CaseSensitive',
      }),
    }))

    respond({ id: 'connection-b' })
    await identityApi.draftConnection({
      displayName: 'Primary identity',
      issuer: 'https://issuer.example',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      auth0OrganizationId: '',
    })

    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections/draft', expect.objectContaining({
      body: JSON.stringify({
        display_name: 'Primary identity',
        issuer: 'https://issuer.example',
        client_id: 'client-id',
        client_secret: 'client-secret',
      }),
    }))
  })

  it('sends explicit selected legacy ID and version only for a configuration correction', async () => {
    respond({ id: 'legacy-connection' })
    await identityApi.draftConnection({
      id: 'legacy-connection',
      version: 2,
      displayName: 'Imported identity',
      issuer: 'https://issuer.example',
      clientId: 'pinned-client',
      clientSecret: 'replacement-secret',
      auth0OrganizationId: '',
    })

    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections/draft', expect.objectContaining({
      body: JSON.stringify({
        id: 'legacy-connection', version: 2, display_name: 'Imported identity', issuer: 'https://issuer.example',
        client_id: 'pinned-client', client_secret: 'replacement-secret',
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

  it('retains the caller-binding nonce cookie for a bearer-authenticated connection test', async () => {
    setToken('sandbox-token')
    respond({ authorization_url: 'https://issuer.example/authorize?state=opaque' })

    await identityApi.testConnection('connection-a', 'proof')

    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections/test', expect.objectContaining({
      credentials: 'same-origin',
      headers: expect.objectContaining({ authorization: 'Bearer sandbox-token' }),
    }))

    respond({ connections: [] })
    await identityApi.connections()
    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections', expect.objectContaining({
      credentials: 'omit',
    }))
  })

  it('retains CSRF authentication for a session-authenticated connection test', async () => {
    setCSRFToken('csrf-proof')
    respond({ authorization_url: 'https://issuer.example/authorize?state=opaque' })

    await identityApi.testConnection('connection-a')

    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/connections/test', expect.objectContaining({
      credentials: 'same-origin',
      headers: expect.objectContaining({ 'X-CSRF-Token': 'csrf-proof' }),
    }))
  })

  it.each([{}, { authorization_url: 'http://issuer.example/authorize' }, { authorization_url: 'not a url' }])('rejects a missing or unsafe connection-test destination', async (body) => {
    respond(body)
    await expect(identityApi.testConnection('connection-a')).rejects.toThrow()
  })
})
