import { fireEvent, render, screen } from '@testing-library/react'
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
  return { ApiError, api: { hostVulnerabilities: vi.fn(), hostPackages: vi.fn() } }
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

  it('renders the host, its exposure strip and the findings table', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue(host)
    renderPage()
    expect(await screen.findByRole('heading', { name: 'web01' })).toBeInTheDocument()
    expect(vi.mocked(api.hostVulnerabilities)).toHaveBeenCalledWith('asset-1')
    expect(screen.getAllByText('Scanned').length).toBeGreaterThan(0)
    expect(screen.getByRole('tab', { name: /Vulnerabilities 1/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Packages 412/ })).toBeInTheDocument()
    // Exposure strip.
    expect(screen.getByLabelText('Open findings: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Critical: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Known exploited: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Fixable: 1')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Packages\s*412/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Coverage gaps: 4')).toBeInTheDocument()
    // Advisory, package, installed and fixed version, CVSS, KEV, sources.
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument()
    expect(screen.getByText('openssl')).toBeInTheDocument()
    expect(screen.getByText('3.0.11-1~deb12u2')).toBeInTheDocument()
    expect(screen.getByText('3.0.13-1~deb12u1')).toBeInTheDocument()
    expect(screen.getByText('9.8')).toBeInTheDocument()
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByText('osv, grype')).toBeInTheDocument()
    // Host facts in the header.
    expect(screen.getByText('6.1.0-18-amd64')).toBeInTheDocument()
    expect(screen.getByText('agent-1')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /copy machine id/i })).toBeInTheDocument()
  })

  it('filters findings by severity, fix state and search', async () => {
    const low: HostFinding = { ...finding, id: 'f2', title: 'CVE-2023-0002 in zlib1g@1:1.2.13', severity: 'low', kev: false, fixedVersion: '', cvssScore: 0, advisoryId: 'CVE-2023-0002', dedupKey: 'vuln:CVE-2023-0002:zlib1g:1:1.2.13' }
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, findings: [finding, low], summary: { ...host.summary, total: 2, low: 1 } })
    renderPage()
    await screen.findByText('CVE-2024-0001')
    expect(screen.getByText('CVE-2023-0002')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Fix available' }))
    expect(screen.queryByText('CVE-2023-0002')).not.toBeInTheDocument()
    expect(screen.getByText('1 of 2 findings')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Any fix state' }))
    fireEvent.click(screen.getByRole('button', { name: /^Low/ }))
    expect(screen.queryByText('CVE-2024-0001')).not.toBeInTheDocument()
    expect(screen.getByText('CVE-2023-0002')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'All severities' }))
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'openssl' } })
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument()
    expect(screen.queryByText('CVE-2023-0002')).not.toBeInTheDocument()
  })

  it('names the missing package inventory and the unrecorded state separately', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, engagementId: '', packages: 0, recordedAt: null, lastScan: null, findings: [], summary: { ...host.summary, total: 0, critical: 0, fixable: 0, kev: 0 }, asset: { ...host.asset, attributes: { ...host.asset.attributes, packages: '0' } } })
    const { unmount } = renderPage()
    expect(await screen.findByText('Package inventory missing')).toBeInTheDocument()
    expect(screen.getAllByText('No package inventory').length).toBeGreaterThan(0)
    unmount()

    // The agent reported 427 packages but nothing was recorded: the page says so instead of "no packages".
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, engagementId: '', packages: 0, recordedAt: null, lastScan: null, findings: [], summary: { ...host.summary, total: 0, critical: 0, fixable: 0, kev: 0 }, asset: { ...host.asset, attributes: { ...host.asset.attributes, packages: '427' } } })
    renderPage()
    expect(await screen.findByText('Packages reported, none recorded')).toBeInTheDocument()
    expect(screen.getAllByText('Packages not recorded').length).toBeGreaterThan(0)
    expect(screen.getByRole('tab', { name: /Packages\s*427/ })).toBeInTheDocument()
  })

  it('distinguishes a running scan from a clean result', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, findings: [], lastScan: { ...host.lastScan!, status: 'running', stage: 'vulnerabilities' } })
    const { unmount } = renderPage()
    expect(await screen.findByText('Scan in progress')).toBeInTheDocument()
    unmount()

    vi.mocked(api.hostVulnerabilities).mockResolvedValue({ ...host, findings: [], summary: { ...host.summary, total: 0, critical: 0, fixable: 0, kev: 0 } })
    renderPage()
    expect(await screen.findByText('No vulnerable OS packages found')).toBeInTheDocument()
  })

  it('lists the recorded packages on the Packages tab', async () => {
    vi.mocked(api.hostVulnerabilities).mockResolvedValue(host)
    vi.mocked(api.hostPackages).mockResolvedValue({ assetId: 'asset-1', engagementId: 'ctx-1', recordedAt: '2026-09-05T09:00:00Z', packages: [
      { name: 'openssl', version: '3.0.11-1~deb12u2', purl: 'pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12' },
      { name: 'zlib1g', version: '1:1.2.13.dfsg-1', purl: '' },
    ] })
    renderPage()
    await screen.findByRole('heading', { name: 'web01' })
    fireEvent.click(screen.getByRole('tab', { name: /Packages/ }))
    expect(await screen.findByText('zlib1g')).toBeInTheDocument()
    expect(vi.mocked(api.hostPackages)).toHaveBeenCalledWith('asset-1')
    expect(screen.getByText(/2 packages/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'zlib' } })
    expect(screen.queryByText('pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12')).not.toBeInTheDocument()
    expect(screen.getByText('1 of 2 packages', { exact: false })).toBeInTheDocument()
  })

  it('shows a framed error with a way back', async () => {
    vi.mocked(api.hostVulnerabilities).mockRejectedValue(new Error('HTTP 500: boom'))
    renderPage()
    expect(await screen.findByText('Could not load this host')).toBeInTheDocument()
    expect(screen.getByText(/HTTP 500: boom/)).toBeInTheDocument()
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
