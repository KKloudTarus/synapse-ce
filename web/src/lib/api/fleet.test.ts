import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '.'

// Exercises the REAL fleet adapter mappers (page tests mock the barrel). The desired-capabilities
// State and the process snapshot arrive PascalCase (no Go json tags); the key, token and rollout
// payloads are snake_case. Each mapper must read the exact casing the server sends.
describe('fleet management adapters', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }
  const lastBody = () => JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body))
  const lastUrl = () => String(fetchSpy.mock.calls[0][0])

  it('maps the PascalCase desired-capabilities State', async () => {
    respond({ TenantID: 't', AssetID: 'asset-1', PolicyID: 'p1', Capabilities: ['edr.process', 'edr.network'], Version: 3, Audit: { UpdatedBy: 'ana', UpdatedAt: '2026-09-05T09:00:00Z' } })
    const s = await api.getDesiredCapabilities('asset-1')
    expect(s).toMatchObject({ assetId: 'asset-1', policyId: 'p1', capabilities: ['edr.process', 'edr.network'], version: 3, updatedBy: 'ana', updatedAt: '2026-09-05T09:00:00Z' })
  })

  it('returns null when no desired capabilities are declared (404)', async () => {
    respond({ error: 'not found' }, 404)
    expect(await api.getDesiredCapabilities('asset-1')).toBeNull()
  })

  it('PUTs the capabilities array when setting desired capabilities', async () => {
    respond({ AssetID: 'asset-1', Capabilities: ['edr.file'], Version: 4, Audit: {} })
    await api.setDesiredCapabilities('asset-1', ['edr.file'])
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('PUT')
    expect(lastBody()).toEqual({ capabilities: ['edr.file'] })
  })

  it('maps the PascalCase process snapshots', async () => {
    respond({ processes: [{ EntityID: 'e1', PID: 1234, Comm: 'nginx', Path: '/usr/sbin/nginx', Running: true, LastSeenAt: '2026-09-05T09:00:00Z' }] })
    const procs = await api.listEndpointProcesses('asset-1')
    expect(procs).toHaveLength(1)
    expect(procs[0]).toMatchObject({ entityId: 'e1', pid: 1234, comm: 'nginx', path: '/usr/sbin/nginx', running: true, lastSeenAt: '2026-09-05T09:00:00Z' })
  })

  it('rebaselines the behavior baseline', async () => {
    respond({ asset_id: 'asset-1', rebaselined: true })
    const r = await api.rebaselineBehavior('asset-1')
    expect(r).toEqual({ assetId: 'asset-1', rebaselined: true })
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('POST')
  })

  it('mints an enrolment token and forwards the ttl', async () => {
    respond({ enrolment_token: 'ENROL-xyz' }, 201)
    const token = await api.mintEnrolToken(900)
    expect(token).toBe('ENROL-xyz')
    expect(lastBody()).toEqual({ ttl_seconds: 900 })
  })

  it('maps the snake_case agent signing keys', async () => {
    respond({ agent_id: 'agent-1', keys: [{ key_id: 'k1', purpose: 'signing', algorithm: 'ed25519', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', revoked: false, replaced_by: '' }] })
    const keys = await api.listAgentKeys('agent-1')
    expect(keys[0]).toMatchObject({ keyId: 'k1', purpose: 'signing', algorithm: 'ed25519', revoked: false })
  })

  it('reads the not-configured rollout shape', async () => {
    respond({ channel: 'stable', configured: false, reason: 'no rollout plan is configured for this channel' })
    const s = await api.getFleetRollout('stable')
    expect(s.configured).toBe(false)
    expect(s.rollout).toBeNull()
    expect(s.reason).toContain('no rollout plan')
  })

  it('reads the configured rollout view', async () => {
    respond({ configured: true, rollout: { channel: 'stable', target_version: '1.4.2', canary_groups: ['canary-a'], promoted_to_all: false, paused: false, updated_by: 'ana', updated_at: '2026-09-05T09:00:00Z' } })
    const s = await api.getFleetRollout('stable')
    expect(s.configured).toBe(true)
    expect(s.rollout).toMatchObject({ targetVersion: '1.4.2', canaryGroups: ['canary-a'], promotedToAll: false, paused: false })
  })

  it('sets a rollout target with the channel query and snake_case body', async () => {
    respond({ configured: true, rollout: { channel: 'beta', target_version: '2.0.0', canary_groups: [], promoted_to_all: false, paused: false, updated_at: '' } })
    await api.setFleetRolloutTarget('2.0.0', ['g1'], 'beta')
    expect(lastUrl()).toContain('channel=beta')
    expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe('PUT')
    expect(lastBody()).toEqual({ target_version: '2.0.0', canary_groups: ['g1'] })
  })
})
