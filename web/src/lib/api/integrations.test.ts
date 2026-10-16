import { afterEach, describe, expect, it, vi } from 'vitest'
import { integrationsApi } from './integrations'

afterEach(() => vi.unstubAllGlobals())

describe('integration operation API contract', () => {
  it('maps operation revisions so callers can reject tests from a replaced credential', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify([{
      id: 'operation-1', integration_id: 'jira-1', connection_revision: 4, credential_revision: 3,
      type: 'test', state: 'succeeded', counts: {}, errors: [], pipelines: [], job_id: '', actor: '', created_at: '', updated_at: '',
    }]), { status: 200, headers: { 'content-type': 'application/json' } })))

    await expect(integrationsApi.listIntegrationOperations('jira-1')).resolves.toMatchObject([{
      id: 'operation-1', connectionRevision: 4, credentialRevision: 3,
    }])
  })

  it('keeps absent revisions distinguishable for an older server response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify([{
      id: 'operation-1', integration_id: 'jira-1', type: 'test', state: 'succeeded', counts: {}, errors: [], pipelines: [], job_id: '', actor: '', created_at: '', updated_at: '',
    }]), { status: 200, headers: { 'content-type': 'application/json' } })))

    await expect(integrationsApi.listIntegrationOperations('jira-1')).resolves.toMatchObject([{
      id: 'operation-1', connectionRevision: undefined, credentialRevision: undefined,
    }])
  })
})
