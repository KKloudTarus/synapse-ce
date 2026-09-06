import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '.'

// Exercises the REAL attackPaths mapper (page tests mock the barrel and never run it). Nested
// asset.Asset / finding.Finding arrive PascalCase (no Go json tags); the mapper must read that.
describe('attackPaths mapper', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })
  function respond(body: unknown, status = 200) {
    fetchSpy.mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as unknown as Response)
  }

  it('reads PascalCase asset/finding nodes and step evidence', async () => {
    respond({
      paths: [
        {
          id: 'ap-1',
          confident: true,
          uncertainties: [],
          nodes: [
            { asset: { asset: { ID: 'a-edge', TenantID: 't', Kind: 'host', Key: 'edge', Name: 'edge-gw-01' } } },
            { finding: { input: { target: { ID: 'f-1', Kind: 'canonical' }, finding: { ID: 'f-1', Title: 'RCE', Severity: 'CRITICAL' }, reachability: 'reachable', confirmed: true, external: false } } },
          ],
          steps: [{ from: 'a-edge', to: 'f-1', kind: 'hosts', observed: true, toFinding: true, evidence: [{ producer: 'sca', provenance: 'ev', confidence: 'observed' }] }],
        },
      ],
      bounds: { truncated: true, pathsHit: true, lengthHit: false, wallClockHit: false, maxLength: 8, maxPaths: 100 },
    })
    const r = await api.attackPaths()
    expect(r).not.toBeNull()
    const p = r!.paths[0]
    expect(p.nodes[0]).toMatchObject({ id: 'a-edge', kind: 'asset', label: 'edge-gw-01', sublabel: 'host' })
    expect(p.nodes[1]).toMatchObject({ id: 'f-1', kind: 'finding', label: 'RCE', severity: 'critical', reachability: 'reachable', confirmed: true })
    expect(p.steps[0]).toMatchObject({ from: 'a-edge', to: 'f-1', kind: 'hosts', observed: true, toFinding: true, evidenceCount: 1 })
    expect(r!.bounds.truncated).toBe(true)
    expect(r!.bounds.pathsHit).toBe(true)
  })

  it('falls back to asset Key when Name is empty and defaults bounds', async () => {
    respond({ paths: [{ id: 'ap-2', confident: false, uncertainties: ['inferred_edge'], nodes: [{ asset: { asset: { ID: 'a', TenantID: 't', Kind: 'container_image', Key: 'sha256:x', Name: '' } } }], steps: [] }] })
    const r = await api.attackPaths()
    expect(r!.paths[0].nodes[0].label).toBe('sha256:x')
    expect(r!.paths[0].uncertainties).toEqual(['inferred_edge'])
    expect(r!.bounds.truncated).toBe(false)
  })

  it('returns null when the route is not registered (404)', async () => {
    respond({ error: 'not found' }, 404)
    expect(await api.attackPaths()).toBeNull()
  })

  it('encodes the finding query params', async () => {
    respond({ paths: [], bounds: {} })
    await api.attackPaths({ finding: 'f-9', findingKind: 'imported' })
    const url = String(fetchSpy.mock.calls[0][0])
    expect(url).toContain('/attack-paths?')
    expect(url).toContain('finding=f-9')
    expect(url).toContain('finding_kind=imported')
  })
})
