import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import type { HostRow } from '../../lib/types'
import { installVirtualViewport } from '../../test/virtualize'
import { Hosts } from './Hosts'

vi.mock('../../lib/api', () => {
  class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.name = 'ApiError'
      this.status = status
    }
  }
  return { ApiError, api: { listHosts: vi.fn() } }
})

const scanned: HostRow = {
  asset: { id: 'asset-1', kind: 'host', key: 'machine-id/abc', name: 'web01', attributes: { os: 'linux', os_version: '12', packages: '412' } },
  engagementId: 'ctx-1',
  packages: 412,
  recordedAt: '2026-09-05T09:00:00Z',
  lastScan: { jobId: 'job-1', status: 'succeeded', stage: 'done', error: '', startedAt: '2026-09-05T09:00:00Z', finishedAt: '2026-09-05T09:02:00Z' },
  summary: { total: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0, fixable: 2, kev: 1 },
}

const quiet: HostRow = {
  asset: { id: 'asset-2', kind: 'host', key: 'hostname/db01', name: 'db01', attributes: { os: 'linux', degraded: 'true', packages: '0' } },
  engagementId: '',
  packages: 0,
  recordedAt: null,
  lastScan: null,
  summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, fixable: 0, kev: 0 },
}

function renderPage() {
  return render(<MemoryRouter><Hosts /></MemoryRouter>)
}

describe('Hosts', () => {
  let restoreViewport: () => void
  beforeEach(() => {
    vi.resetAllMocks()
    restoreViewport = installVirtualViewport()
  })
  afterEach(() => restoreViewport())

  it('shows a loading state while the list is in flight', () => {
    vi.mocked(api.listHosts).mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading hosts…')).toBeInTheDocument()
  })

  it('lists hosts with their severity counts, scan state and fleet totals', async () => {
    vi.mocked(api.listHosts).mockResolvedValue([scanned, quiet])
    renderPage()
    expect(await screen.findByText('web01')).toBeInTheDocument()
    expect(screen.getByText('machine-id/abc')).toBeInTheDocument()
    expect(screen.getByText('linux 12')).toBeInTheDocument()
    expect(screen.getByText('Scanned')).toBeInTheDocument()
    expect(screen.getByText('db01')).toBeInTheDocument()
    expect(screen.getByText('No packages reported')).toBeInTheDocument()
    // The incomplete inventory is marked on the package count.
    expect(screen.getByText('0*')).toBeInTheDocument()
    // Header totals: 2 hosts, 1 scanned, 1 critical, 2 high, 1 KEV.
    expect(screen.getByText('· 1 scanned')).toBeInTheDocument()
    expect(screen.getByRole('row', { name: 'Open host web01' })).toBeInTheDocument()
  })

  it('shows the empty state when no host is inventoried', async () => {
    vi.mocked(api.listHosts).mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('No hosts inventoried')).toBeInTheDocument()
  })

  it('explains the disabled feature on a 404', async () => {
    vi.mocked(api.listHosts).mockRejectedValue(new Error('HTTP 404: not found'))
    renderPage()
    await waitFor(() => expect(screen.getByText(/SYNAPSE_FLEET_HOST_INGEST_ENABLED/)).toBeInTheDocument())
  })

  it('shows the error with a retry on any other failure', async () => {
    vi.mocked(api.listHosts).mockRejectedValue(new Error('HTTP 500: boom'))
    renderPage()
    expect(await screen.findByText(/HTTP 500: boom/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
