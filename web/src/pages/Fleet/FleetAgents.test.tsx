import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api, ApiError } from '../../lib/api'
import type { FleetAgentRow } from '../../lib/types'
import { installVirtualViewport } from '../../test/virtualize'
import { FleetAgents } from './FleetAgents'

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
      listFleetAgents: vi.fn(),
      getFleetAgent: vi.fn(),
    },
  }
})

const agent: FleetAgentRow = {
  id: 'ag-1',
  name: 'edge-01',
  platform: 'linux/amd64',
  agentVersion: '1.2.0',
  state: 'healthy',
  lastSeen: '2026-01-01T00:00:00Z',
  capabilities: ['scan.host'],
  currentWork: 2,
}

function renderPage() {
  return render(
    <MemoryRouter>
      <FleetAgents />
    </MemoryRouter>,
  )
}

describe('FleetAgents', () => {
  let restoreViewport: () => void
  beforeEach(() => {
    vi.resetAllMocks()
    restoreViewport = installVirtualViewport()
  })
  afterEach(() => restoreViewport())

  it('shows a loading state while agents are in flight', () => {
    vi.mocked(api.listFleetAgents).mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading fleet agents…')).toBeInTheDocument()
  })

  it('shows an empty state when there are no agents', async () => {
    vi.mocked(api.listFleetAgents).mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('No agents')).toBeInTheDocument()
  })

  it('shows an error and retries', async () => {
    vi.mocked(api.listFleetAgents).mockRejectedValueOnce(new ApiError(503, 'agents down')).mockResolvedValue([])
    renderPage()
    expect(await screen.findByText('agents down')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No agents')).toBeInTheDocument()
  })

  it('applies the state filter', async () => {
    vi.mocked(api.listFleetAgents).mockResolvedValue([])
    renderPage()
    await screen.findByText('No agents')
    fireEvent.click(screen.getByRole('button', { name: 'Stale' }))
    await waitFor(() => expect(api.listFleetAgents).toHaveBeenLastCalledWith('stale'))
  })

  it('opens agent detail with recent work on row click', async () => {
    vi.mocked(api.listFleetAgents).mockResolvedValue([agent])
    vi.mocked(api.getFleetAgent).mockResolvedValue({
      agent,
      recentWork: [{ id: 'wo-1', capability: 'scan.host', assetId: 'asset-A', state: 'succeeded', updatedAt: '2026-01-01T00:00:00Z' }],
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'ag-1' }))
    expect(await screen.findByText('Recent work orders')).toBeInTheDocument()
    expect(screen.getByText('asset-A')).toBeInTheDocument()
    expect(api.getFleetAgent).toHaveBeenCalledWith('ag-1')
  })
})
