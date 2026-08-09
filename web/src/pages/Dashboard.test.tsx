import { render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../lib/api'
import type { BusinessAsset, Engagement, FleetCoverageSummary } from '../lib/types'
import { Dashboard } from './Dashboard'

vi.mock('../lib/api', () => ({
  api: {
    listBusinessAssets: vi.fn(),
    listEngagements: vi.fn(),
    fleetCoverageSummary: vi.fn(),
  },
}))

const assets: BusinessAsset[] = [
  {
    id: 'asset-critical', key: 'payments', name: 'Payments Platform', description: '', type: 'system', criticality: 'critical', lifecycle: 'active', owner: 'Payments Security', metadata: {}, version: 1, createdAt: null, updatedAt: null, posture: 'critical',
  },
  {
    id: 'asset-unknown', key: 'mobile', name: 'Mobile Banking', description: '', type: 'application', criticality: 'high', lifecycle: 'active', owner: 'Mobile Team', metadata: {}, version: 1, createdAt: null, updatedAt: null, posture: 'unknown',
  },
  {
    id: 'asset-good', key: 'portal', name: 'Customer Portal', description: '', type: 'product', criticality: 'medium', lifecycle: 'active', owner: 'Web Team', metadata: {}, version: 1, createdAt: null, updatedAt: null, posture: 'good',
  },
]

const engagements: Engagement[] = [
  {
    id: 'eng-active', name: 'Payment API Review', client: 'Internal', status: 'active', inScope: [{ kind: 'repo', value: 'payments' }], outOfScope: [], authorizedFrom: null, authorizedTo: null, roe: { allowedToolClasses: [], blackouts: [] }, liveReconEnabled: false, createdAt: '2026-08-01T00:00:00Z', businessAssetId: 'asset-critical',
  },
  {
    id: 'eng-unassigned', name: 'New Service Review', client: 'Internal', status: 'draft', inScope: [{ kind: 'service', value: 'new-service' }], outOfScope: [], authorizedFrom: null, authorizedTo: null, roe: { allowedToolClasses: [], blackouts: [] }, liveReconEnabled: false, createdAt: '2026-08-02T00:00:00Z', businessAssetId: '',
  },
]

const fleet: FleetCoverageSummary = {
  agentsByState: { connected: 2 },
  rowsByVerdict: { covered: 5, stale: 2, unauthorized: 1 },
  oldestPerCapability: {},
  assetsWithoutAgent: 1,
}

function renderDashboard() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: assets, total: assets.length, limit: 200, offset: 0 })
    vi.mocked(api.listEngagements).mockResolvedValue(engagements)
    vi.mocked(api.fleetCoverageSummary).mockResolvedValue(fleet)
  })

  it('renders operational metrics and priority queues from API data', async () => {
    renderDashboard()

    expect(await screen.findByRole('heading', { name: 'Security Operations' })).toBeInTheDocument()
    expect(screen.getByLabelText('Total assets: 3')).toBeInTheDocument()
    expect(screen.getByLabelText('High-risk assets: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Active engagements: 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Coverage gaps: 3')).toBeInTheDocument()
    expect(screen.getByLabelText('Unassigned: 1')).toBeInTheDocument()

    const priorityAssets = screen.getByText('Priority Assets').closest('section')!
    expect(within(priorityAssets).getByText('Payments Platform')).toBeInTheDocument()
    expect(within(priorityAssets).getByText('Mobile Banking')).toBeInTheDocument()
    expect(within(priorityAssets).queryByText('Customer Portal')).not.toBeInTheDocument()

    expect(screen.getByText('Payment API Review')).toBeInTheDocument()
    expect(screen.getByText('Payments Platform', { selector: 'p' })).toBeInTheDocument()
    expect(screen.getByText('Unassigned Asset')).toBeInTheDocument()
  })

  it('keeps core operations visible when Fleet telemetry fails', async () => {
    vi.mocked(api.fleetCoverageSummary).mockRejectedValue(new Error('fleet disabled'))
    renderDashboard()

    expect(await screen.findByLabelText('Total assets: 3')).toBeInTheDocument()
    expect(screen.getByLabelText('Coverage gaps: —')).toBeInTheDocument()
    expect(screen.getAllByText('Fleet telemetry unavailable').length).toBeGreaterThan(0)
    expect(screen.getByText(/Coverage is not assumed clean/)).toBeInTheDocument()
  })
})
