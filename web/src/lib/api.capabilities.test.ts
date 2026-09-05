import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import { capabilityHint, disabledCapability, loadCapabilities, resetCapabilityCache } from './capabilities'

/**
 * Wire shape: `capabilityView` in internal/adapter/httpapi/capability_handler.go.
 * The payload below is a verbatim slice of `GET /api/v1/capabilities` from a running synapse-api.
 */
const wire = {
  capabilities: [
    { key: 'fleet', name: 'Agent fleet transport', enabled: false, switch: 'SYNAPSE_FLEET_ENABLED' },
    { key: 'ai_triage', name: 'AI false-positive triage', enabled: false, switch: 'SYNAPSE_FP_TRIAGE_ENABLED' },
    { key: 'judgments', name: 'Judgment lifecycle', enabled: true, switch: 'SYNAPSE_JUDGMENTS_ENABLED' },
    {
      key: 'cspm', name: 'Cloud security posture management', enabled: false,
      switch: 'SYNAPSE_CSPM_ENABLED', requires: ['fleet_assets'],
    },
  ],
}

describe('capabilities API', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    resetCapabilityCache()
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('maps the catalog and defaults an absent requires to empty', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => wire } as Response)
    const list = await api.listCapabilities()
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/capabilities', expect.any(Object))
    expect(list).toEqual([
      { key: 'fleet', name: 'Agent fleet transport', enabled: false, switch: 'SYNAPSE_FLEET_ENABLED', requires: [] },
      { key: 'ai_triage', name: 'AI false-positive triage', enabled: false, switch: 'SYNAPSE_FP_TRIAGE_ENABLED', requires: [] },
      { key: 'judgments', name: 'Judgment lifecycle', enabled: true, switch: 'SYNAPSE_JUDGMENTS_ENABLED', requires: [] },
      { key: 'cspm', name: 'Cloud security posture management', enabled: false, switch: 'SYNAPSE_CSPM_ENABLED', requires: ['fleet_assets'] },
    ])
  })

  it('reports null on a server that does not serve the route', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response)
    await expect(api.listCapabilities()).resolves.toBeNull()
  })

  it('reports null when the API is unreachable', async () => {
    fetchSpy.mockRejectedValueOnce(new TypeError('network down'))
    await expect(api.listCapabilities()).resolves.toBeNull()
  })

  it('reads the catalog once per page load', async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => wire } as Response)
    const [a, b] = await Promise.all([loadCapabilities(), loadCapabilities()])
    expect(a).toBe(b)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})

describe('capability gating', () => {
  const index = new Map(
    wire.capabilities.map((c) => [c.key, { ...c, requires: c.requires ?? [] }]),
  )

  it('gates a disabled subsystem and lets an enabled one through', () => {
    expect(disabledCapability(index, 'fleet')?.switch).toBe('SYNAPSE_FLEET_ENABLED')
    expect(disabledCapability(index, 'judgments')).toBeNull()
  })

  it('shows everything when the deployment reports no catalog', () => {
    expect(disabledCapability(null, 'fleet')).toBeNull()
  })

  it('shows a key the catalog does not know', () => {
    expect(disabledCapability(index, 'time_travel')).toBeNull()
  })

  it('names the switch, and the dependencies when there are any', () => {
    expect(capabilityHint(index.get('fleet')!)).toBe(
      'Agent fleet transport is disabled. Set SYNAPSE_FLEET_ENABLED=true on the API and restart it.',
    )
    expect(capabilityHint(index.get('cspm')!)).toContain('It also needs: fleet_assets.')
  })
})
