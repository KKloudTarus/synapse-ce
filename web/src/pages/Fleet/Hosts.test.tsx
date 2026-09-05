import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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

  it('keeps the table frame while the list is in flight', () => {
    vi.mocked(api.listHosts).mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByLabelText('Loading')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Hosts' })).toBeInTheDocument()
  })

  it('lists hosts with their severity counts, scan state and fleet totals', async () => {
    vi.mocked(api.listHosts).mockResolvedValue([scanned, quiet])
    renderPage()
    expect(await screen.findByText('web01')).toBeInTheDocument()
    expect(screen.getByText('machine-id/abc')).toBeInTheDocument()
    expect(screen.getByText(/linux 12/)).toBeInTheDocument()
    expect(screen.getByText('Scanned')).toBeInTheDocument()
    expect(screen.getByText('db01')).toBeInTheDocument()
    // db01 reported no packages: the scan badge and the package cell both say so.
    expect(screen.getByText('No package inventory')).toBeInTheDocument()
    expect(screen.getByText(/^none/)).toBeInTheDocument()
    // The fleet strip: 2 hosts, 1 with findings, 1 critical, 2 high, 1 KEV, 1 without inventory.
    expect(screen.getByLabelText('Hosts: 2')).toBeInTheDocument()
    expect(screen.getByLabelText('With findings: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Critical: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('High: 2')).toBeInTheDocument()
    expect(screen.getByLabelText('Known exploited: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('No inventory: 1')).toBeInTheDocument()
    expect(screen.getByRole('row', { name: 'Open host web01' })).toBeInTheDocument()
    expect(screen.getByText(/Last package set recorded/)).toBeInTheDocument()
  })

  it('filters by state and by search', async () => {
    vi.mocked(api.listHosts).mockResolvedValue([scanned, quiet])
    renderPage()
    await screen.findByText('web01')
    fireEvent.click(screen.getByRole('button', { name: 'No inventory' }))
    expect(screen.queryByText('web01')).not.toBeInTheDocument()
    expect(screen.getByText('db01')).toBeInTheDocument()
    expect(screen.getByText('1 of 2 hosts')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'All' }))
    fireEvent.change(screen.getByLabelText('Search hosts'), { target: { value: 'machine-id/abc' } })
    expect(screen.getByText('web01')).toBeInTheDocument()
    expect(screen.queryByText('db01')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Search hosts'), { target: { value: 'nothing-matches' } })
    expect(screen.getByText('No hosts match')).toBeInTheDocument()
  })

  it('shows the empty state inside the table frame when no host is inventoried', async () => {
    vi.mocked(api.listHosts).mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('No hosts received yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open fleet agents' })).toBeInTheDocument()
  })

  it('explains the disabled feature on a 404', async () => {
    vi.mocked(api.listHosts).mockRejectedValue(new Error('HTTP 404: not found'))
    renderPage()
    await waitFor(() => expect(screen.getByText(/SYNAPSE_FLEET_HOST_INGEST_ENABLED/)).toBeInTheDocument())
  })

  it('shows a framed error with the cause and a retry on any other failure', async () => {
    vi.mocked(api.listHosts).mockRejectedValue(new Error('HTTP 500: boom'))
    renderPage()
    expect(await screen.findByText('Could not load hosts')).toBeInTheDocument()
    expect(screen.getByText(/HTTP 500: boom/)).toBeInTheDocument()
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
