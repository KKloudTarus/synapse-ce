import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

// Wire shape: hostSummaryDTO / hostVulnerabilitiesDTO in internal/adapter/httpapi/host_vulnerability_handler.go.
describe('fleet host vulnerabilities', () => {
  let fetchSpy: any

  beforeEach(() => { fetchSpy = vi.spyOn(globalThis, 'fetch') })

  const row = {
    asset: { ID: 'asset-1', TenantID: 't', Kind: 'host', Key: 'machine-id/abc', Name: 'web01', Attributes: { os: 'linux', os_version: '12', packages: '412' } },
    engagement_id: 'ctx-1', packages: 412, recorded_at: '2026-09-05T09:00:00Z',
    last_scan: { job_id: 'job-1', status: 'succeeded', stage: 'done', started_at: '2026-09-05T09:00:00Z', finished_at: '2026-09-05T09:02:00Z' },
    summary: { total: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0, fixable: 2, kev: 1 },
  }

  it('maps the host list, including a host that never reported packages', async () => {
    const quiet = { asset: { ID: 'asset-2', Kind: 'host', Key: 'hostname/db01', Name: 'db01', Attributes: {} }, packages: 0, summary: { total: 0 } }
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [row, quiet] } as Response)
    const hosts = await api.listHosts()
    expect(fetchSpy.mock.calls[0][0]).toContain('/assets/hosts')
    expect(hosts).toHaveLength(2)
    expect(hosts[0].asset).toEqual({ id: 'asset-1', kind: 'host', key: 'machine-id/abc', name: 'web01', attributes: { os: 'linux', os_version: '12', packages: '412' } })
    expect(hosts[0].engagementId).toBe('ctx-1')
    expect(hosts[0].lastScan).toEqual({ jobId: 'job-1', status: 'succeeded', stage: 'done', error: '', startedAt: '2026-09-05T09:00:00Z', finishedAt: '2026-09-05T09:02:00Z' })
    expect(hosts[0].summary).toEqual({ total: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0, fixable: 2, kev: 1 })
    expect(hosts[1].engagementId).toBe('')
    expect(hosts[1].lastScan).toBeNull()
    expect(hosts[1].recordedAt).toBeNull()
    expect(hosts[1].summary.total).toBe(0)
  })

  it('maps one host with its findings and the computed CVSS score', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({
      ...row,
      findings: [{
        ID: 'f1', EngagementID: 'ctx-1', Title: 'CVE-2024-0001 in openssl@3.0.11-1~deb12u2', Severity: 'critical', Kind: 'sca', Status: 'open',
        CVSSVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8, FixedVersion: '3.0.13-1~deb12u1', KEV: true, RiskScore: 8.7,
        AdvisoryID: 'CVE-2024-0001', Sources: ['osv', 'grype'], Confidence: 'high', DetectionState: 'active', DedupKey: 'vuln:CVE-2024-0001:openssl:3.0.11-1~deb12u2',
      }],
    }) } as Response)
    const host = await api.hostVulnerabilities('asset 1')
    expect(fetchSpy.mock.calls[0][0]).toContain('/assets/asset%201/vulnerabilities')
    expect(host.asset.name).toBe('web01')
    expect(host.findings).toHaveLength(1)
    const f = host.findings[0]
    expect(f.id).toBe('f1')
    expect(f.severity).toBe('critical')
    expect(f.cvssScore).toBe(9.8)
    expect(f.fixedVersion).toBe('3.0.13-1~deb12u1')
    expect(f.kev).toBe(true)
    expect(f.advisoryId).toBe('CVE-2024-0001')
    expect(f.sources).toEqual(['osv', 'grype'])
  })
})
