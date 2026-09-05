import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api } from '../../lib/api'
import type { HostFinding, HostVulnerabilities } from '../../lib/types'
import { installVirtualViewport } from '../../test/virtualize'
import { HostDetail } from './HostDetail'
import { hostFindingAdvisory, hostFindingPackage } from './hostShared'

vi.mock('../../lib/api', () => {
  class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.name = 'ApiError'
      this.status = status
    }
  }
  return { ApiError, api: { hostVulnerabilities: vi.fn() } }
})

const finding: HostFinding = {
  id: 'f1', engagementId: 'ctx-1', title: 'CVE-2024-0001 in openssl@3.0.11-1~deb12u2', description: '', severity: 'critical',
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: '', status: 'open', dedupKey: 'vuln:CVE-2024-0001:openssl:3.0.11-1~deb12u2',
  kev: true, riskScore: 8.7, class: 'third_party', scope: 'runtime', reachability: 'unknown', impact: '', priority: 1, assignee: '', version: 1,
  kind: 'sca', evidenceScore: 0, proposedBy: '', complianceControls: [],
  cvssScore: 9.8, fixedVersion: '3.0.13-1~deb12u1', advisoryId: 'CVE-2024-0001', sources: ['osv', 'grype'], confidence: 'high', detectionState: 'active',
}

const host: HostVulnerabilities = {
  asset: { id: 'asset-1', kind: 'host', key: 'machine-id/abc', name: 'web01', attributes: { os: 'linux', os_version: '12', arch: 'amd64', kernel: '6.1.0-18-amd64', packages: '412', machine_id: 'abc', reporting_agent_id: 'agent-1', coverage_gaps: '4' } },
  engagementId: 'ctx-1',
  packages: 412,
  recordedAt: '2026-09-05T09:00:00Z',
  lastScan: { jobId: 'job-1', status: 'succeeded', stage: 'done', error: '', startedAt: '2026-09-05T09:00:00Z', finishedAt: '2026-09-05T09:02:00Z' },
  summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0, fixable: 1, kev: 1 },
  findings: [finding],
}

function renderPage(id = 'asset-1') {
  return render(
    <MemoryRouter initialEntries={[`/fleet/hosts/${id}`]}>
      <Routes>
        <Route path="/fleet/hosts/:id" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('HostDetail', () => {
  let restoreViewport: () => void
  beforeEach(() => {
    vi.resetAllMocks()
    restoreViewport = installVirtualViewport()
  })
  afterEach(() => restoreViewport())

  it('renders the host, its exposure and the findings table', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue(host)
    renderPage()
    expect(await screen.findByRole('heading', { name: 'web01' })).toBeInTheDocument()
    expect(vi.mocked(api.hostVulnerabilities)).toHaveBeenCalledWith('asset-1')
    expect(screen.getByText('Scanned')).toBeInTheDocument()
    expect(screen.getByText('Vulnerabilities (1)')).toBeInTheDocument()
    // Advisory, package, installed and fixed version, CVSS, sources.
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument()
    expect(screen.getByText('openssl')).toBeInTheDocument()
    expect(screen.getByText('3.0.11-1~deb12u2')).toBeInTheDocument()
    expect(screen.getByText('3.0.13-1~deb12u1')).toBeInTheDocument()
    expect(screen.getByText('9.8')).toBeInTheDocument()
    expect(screen.getByText('osv, grype')).toBeInTheDocument()
    expect(screen.getByText('Known exploited', { selector: 'span' })).toBeInTheDocument()
    // Host facts.
    expect(screen.getByText('6.1.0-18-amd64')).toBeInTheDocument()
    expect(screen.getByText('agent-1')).toBeInTheDocument()
  })

  it('tells the operator when the host never reported packages', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, engagementId: '', packages: 0, recordedAt: null, lastScan: null, findings: [], summary: { ...host.summary, total: 0, critical: 0, fixable: 0, kev: 0 } })
    renderPage()
    expect(await screen.findByText('No packages reported yet')).toBeInTheDocument()
    expect(screen.queryByText('Last scan')).not.toBeInTheDocument()
  })

  it('distinguishes a running scan from a clean result', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, findings: [], lastScan: { ...host.lastScan!, status: 'running', stage: 'vulnerabilities' } })
    const { unmount } = renderPage()
    expect(await screen.findByText('Scan in progress')).toBeInTheDocument()
    unmount()

    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, findings: [], summary: { ...host.summary, total: 0, critical: 0, fixable: 0, kev: 0 } })
    renderPage()
    expect(await screen.findByText('No known vulnerabilities')).toBeInTheDocument()
  })

  it('shows the error with a way back', async () => {
    vi.mocked(api.hostVulnerabilities).mockRejectedValue(new Error('HTTP 500: boom'))
    renderPage()
    expect(await screen.findByText(/HTTP 500: boom/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Hosts/ })).toHaveAttribute('href', '/fleet/hosts')
  })
})

describe('host finding helpers', () => {
  it('reads package and version from the pipeline title, with the dedup key as fallback', () => {
    expect(hostFindingPackage(finding)).toEqual({ name: 'openssl', version: '3.0.11-1~deb12u2' })
    expect(hostFindingPackage({ title: 'Renamed', dedupKey: 'vuln:CVE-1:zlib1g:1:1.2.13.dfsg-1' })).toEqual({ name: 'zlib1g', version: '1:1.2.13.dfsg-1' })
    expect(hostFindingPackage({ title: 'Renamed', dedupKey: 'x' })).toEqual({ name: '', version: '' })
  })

  it('prefers the recorded advisory id over the title prefix', () => {
    expect(hostFindingAdvisory(finding)).toBe('CVE-2024-0001')
    expect(hostFindingAdvisory({ title: 'GHSA-xxxx in pkg@1', advisoryId: '' })).toBe('GHSA-xxxx')
    expect(hostFindingAdvisory({ title: 'Plain', advisoryId: '' })).toBe('Plain')
  })
})
