import { beforeEach, describe, expect, it, vi } from 'vitest'
import { setCSRFToken, setToken } from './client'
import { identityProvisioningApi } from './identityProvisioning'

describe('identity provisioning API contract', () => {
  const fetchSpy = vi.fn<typeof fetch>()

  beforeEach(() => {
    fetchSpy.mockReset()
    vi.stubGlobal('fetch', fetchSpy)
    setToken('')
    setCSRFToken('csrf-for-test')
  })

  function respond(body: unknown, status = 200): void {
    fetchSpy.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(),
      json: async () => body,
    } as Response)
  }

  const snapshot = {
    id: 'provisioning-1', tenant_id: 'sandbox-b', recipient: 'admin@example.test', state: 'draft', version: 2,
    connection: { id: 'connection-1', display_name: 'Sandbox identity', issuer: 'https://issuer.example/', client_id: 'client-id', enabled: false, revision: 1, draft_revision: 2, version: 3, test_passed: false, auth0_organization_id: 'org-sandbox-b' },
    invitation: null,
  }

  it('round trips Entra discovery mode in provisioning', async () => {
    respond({ ...snapshot, connection: { ...snapshot.connection, entra_discovery_mode: 'common', draft_entra_discovery_mode: 'organizations' } })
    const result = await identityProvisioningApi.draft({ capability: 'capability', displayName: 'Entra', issuer: 'https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0', clientId: 'client', clientSecret: 'secret', auth0OrganizationId: '', entraDiscoveryMode: 'organizations', version: 0 })
    expect(result.connection).toMatchObject({ entraDiscoveryMode: 'common', draftEntraDiscoveryMode: 'organizations' })
    expect(JSON.parse(fetchSpy.mock.calls.at(-1)![1]!.body as string)).toHaveProperty('entra_discovery_mode', 'organizations')
  })

  it('sends only a target and recipient to begin and maps the safe snapshot', async () => {
    respond({ provisioning: snapshot, capability: 'capability-opaque' })
    await expect(identityProvisioningApi.begin('sandbox-b', 'admin@example.test')).resolves.toEqual({ provisioning: expect.objectContaining({ tenantId: 'sandbox-b', recipient: 'admin@example.test' }), capability: 'capability-opaque' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/identity/provisioning/begin', expect.objectContaining({ method: 'POST', body: JSON.stringify({ tenant_id: 'sandbox-b', recipient: 'admin@example.test' }) }))
  })

  it('accepts the terminal completion snapshot without asking the server for more authority', async () => {
    respond({ provisioning: { ...snapshot, state: 'closed' } })
    await expect(identityProvisioningApi.begin('sandbox-b', '')).resolves.toEqual({ provisioning: expect.objectContaining({ state: 'closed' }), capability: '' })
    respond({ provisioning: snapshot })
    await expect(identityProvisioningApi.begin('sandbox-b', '')).rejects.toThrow('provisioning capability')
  })

  it('uses the exact same-origin nonce path for a provider test while normal provisioning calls omit bearer cookies', async () => {
    setToken('bootstrap-bearer')
    respond({ authorization_url: 'https://issuer.example/authorize?state=opaque' })
    await identityProvisioningApi.test('capability-opaque')
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/identity/provisioning/test', expect.objectContaining({ method: 'POST', credentials: 'same-origin', body: JSON.stringify({ capability: 'capability-opaque' }) }))
    respond({ provisioning: snapshot })
    await identityProvisioningApi.status('capability-opaque')
    expect(fetchSpy).toHaveBeenLastCalledWith('/api/v1/identity/provisioning/status', expect.objectContaining({ method: 'POST', credentials: 'omit', body: JSON.stringify({ capability: 'capability-opaque' }) }))
  })

  it('sends secret material only for the draft request and does not expose it in parsed state', async () => {
    respond(snapshot)
    const result = await identityProvisioningApi.draft({ capability: 'capability-opaque', displayName: 'Sandbox identity', issuer: 'https://issuer.example/', clientId: 'client-id', clientSecret: 'client-secret', auth0OrganizationId: 'org-sandbox-b', version: 2 })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/identity/provisioning/draft', expect.objectContaining({ method: 'POST', body: JSON.stringify({ capability: 'capability-opaque', display_name: 'Sandbox identity', issuer: 'https://issuer.example/', client_id: 'client-id', client_secret: 'client-secret', auth0_organization_id: 'org-sandbox-b', version: 2 }) }))
    expect(result.connection?.clientId).toBe('client-id')
    expect(JSON.stringify(result)).not.toContain('client-secret')
  })

  it.each(['http://issuer.example/authorize', 'https://user@issuer.example/authorize', 'https://issuer.example:password@issuer.example/authorize'])('rejects a provider destination that is not a credential-free HTTPS URL', async (authorizationURL) => {
    respond({ authorization_url: authorizationURL })
    await expect(identityProvisioningApi.test('capability-opaque')).rejects.toThrow('unsafe authorization destination')
  })
})
