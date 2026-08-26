import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api, ApiError } from '../../lib/api'
import type { FleetCoverageSummary } from '../../lib/types'
import { installVirtualViewport } from '../../test/virtualize'
import { FleetCoverage } from './FleetCoverage'

vi.mock('../../lib/api', () => {
  class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.name = 'ApiError'
      this.status = status
    }
  }
  return {
    ApiError,
    api: {
      listFleetCoverage: vi.fn(),
      fleetCoverageSummary: vi.fn(),
      exportFleetCoverage: vi.fn(),
      listFleetAgents: vi.fn(),
      getFleetAgent: vi.fn(),
    },
  }
})

const emptySummary: FleetCoverageSummary = {
  agentsByState: {},
  rowsByVerdict: {},
  oldestPerCapability: {},
  assetsWithoutAgent: 0,
}

function renderPage() {
  return render(
    <MemoryRouter>
      <FleetCoverage />
    </MemoryRouter>,
  )
}

describe('FleetCoverage', () => {
  let restoreViewport: () => void
  beforeEach(() => {
    vi.resetAllMocks()
    restoreViewport = installVirtualViewport()
    vi.mocked(api.fleetCoverageSummary).mockResolvedValue(emptySummary)
    vi.mocked(api.listFleetAgents).mockResolvedValue([])
  })
  afterEach(() => restoreViewport())

  it('shows a loading state while data is in flight', () => {
    vi.mocked(api.listFleetCoverage).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.fleetCoverageSummary).mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading fleet coverage…')).toBeInTheDocument()
  })

  it('shows an empty state when there are no coverage rows', async () => {
    vi.mocked(api.listFleetCoverage).mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('No coverage rows')).toBeInTheDocument()
  })

  it('shows an error and retries', async () => {
    vi.mocked(api.listFleetCoverage)
      .mockRejectedValueOnce(new ApiError(500, 'coverage exploded'))
      .mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('coverage exploded')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No coverage rows')).toBeInTheDocument()
  })

  it('renders non-covered verdicts distinctly and exports CSV', async () => {
    vi.mocked(api.listFleetCoverage).mockResolvedValue([
      { assetId: 'asset-A', capability: 'scan.host', verdict: 'covered', detail: '', lastRun: '2026-01-01T00:00:00Z', agentId: 'ag1' },
      { assetId: 'asset-B', capability: 'scan.host', verdict: 'unauthorized', detail: 'out of scope', lastRun: '', agentId: '' },
    ])
    vi.mocked(api.fleetCoverageSummary).mockResolvedValue({
      ...emptySummary,
      rowsByVerdict: { covered: 1, unauthorized: 1 },
    })
    renderPage()
    expect(await screen.findByText('asset-A')).toBeInTheDocument()
    expect(screen.getByText('asset-B')).toBeInTheDocument()
    // The unauthorized verdict is surfaced as its own label, never folded into covered.
    expect(screen.getAllByText('Unauthorized').length).toBeGreaterThan(0)

    fireEvent.click(screen.getByRole('button', { name: /Export CSV/ }))
    await waitFor(() => expect(api.exportFleetCoverage).toHaveBeenCalledTimes(1))
  })
})
