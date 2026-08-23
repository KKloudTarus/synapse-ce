import { render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import type { BusinessAsset, DashboardSecurityOperations, Engagement, FleetCoverageSummary } from '../../lib/types'
import { DashboardPage as Dashboard } from './DashboardPage'

vi.mock('../../lib/api', () => ({
  api: {
    listBusinessAssets: vi.fn(),
    listEngagements: vi.fn(),
    fleetCoverageSummary: vi.fn(),
    dashboardSecurityOperations: vi.fn(),
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

const analytics: DashboardSecurityOperations = {
  rangeDays: 30,
  generatedAt: '2026-08-10T00:00:00Z',
  assetPosture: { critical: 1, high_risk: 0, attention: 0, unknown: 1, good: 1 },
  assetsByCriticality: { critical: 1, high: 1, medium: 1, low: 0 },
  activeFindingsBySeverity: { critical: 1, high: 2, medium: 3, low: 0, info: 0, unknown: 1 },
  findingsOverTime: [
    { date: '2026-08-09', counts: { critical: 0, high: 1, medium: 0, low: 0 } },
    { date: '2026-08-10', counts: { critical: 1, high: 0, medium: 2, low: 0 } },
  ],
  findingsWithoutTimestamp: 1,
  externalFindingsIncluded: true,
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
    vi.mocked(api.dashboardSecurityOperations).mockResolvedValue(analytics)
  })

  it('renders operational metrics and priority queues from API data', async () => {
    renderDashboard()

    expect(await screen.findByRole('heading', { name: 'Security Operations' })).toBeInTheDocument()
    expect(screen.getByLabelText(/Total assets: 3/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/High-risk assets: 1/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Active engagements: 1/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Coverage gaps: 3/i)).toBeInTheDocument()

    const priorityAssets = screen.getByText('Priority Assets').closest('section')!
    expect(within(priorityAssets).getByText('Payments Platform')).toBeInTheDocument()
    expect(within(priorityAssets).getByText('Mobile Banking')).toBeInTheDocument()
    expect(within(priorityAssets).queryByText('Customer Portal')).not.toBeInTheDocument()

    expect(screen.getByText('Payment API Review')).toBeInTheDocument()
    expect(screen.getAllByText('Payments Platform').length).toBeGreaterThan(0)
    expect(screen.getByText('New Service Review')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Asset Security Posture' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Findings Over Time' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Active Finding Risk Mix' })).toBeInTheDocument()
    expect(screen.getByLabelText('Asset Security Posture: 3 total')).toBeInTheDocument()
    expect(screen.getByLabelText('Active Finding Risk Mix: 7 total')).toBeInTheDocument()
    expect(screen.getByText(/excluded from the trend/)).toBeInTheDocument()
  })

  // The completeness disclosures are the point of these charts: a trend that quietly omits rows, or a
  // risk mix that quietly omits third-party findings, reads as the whole picture. The undated-findings
  // notice is covered above; this covers the other one, and the fail-closed default behind it.
  it('says so when third-party findings are not included', async () => {
    vi.mocked(api.dashboardSecurityOperations).mockResolvedValue({ ...analytics, externalFindingsIncluded: false })
    renderDashboard()

    expect(await screen.findByText('Third-party findings are not included.')).toBeInTheDocument()
  })

  it('keeps core operations visible when Fleet telemetry fails', async () => {
    vi.mocked(api.fleetCoverageSummary).mockRejectedValue(new Error('fleet disabled'))
    renderDashboard()

    expect(await screen.findByLabelText(/Total assets: 3/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Coverage gaps: —/i)).toBeInTheDocument()
    expect(screen.getAllByText('Fleet telemetry unavailable').length).toBeGreaterThan(0)
  })

  it('reloads the finding trend for a selected range', async () => {
    renderDashboard()
    await screen.findByRole('heading', { name: 'Findings Over Time' })
    screen.getByRole('button', { name: '90d' }).click()
    await waitFor(() => expect(api.dashboardSecurityOperations).toHaveBeenLastCalledWith(90))
  })

  it('keeps the operational dashboard visible when analytics fails', async () => {
    vi.mocked(api.dashboardSecurityOperations).mockRejectedValue(new Error('analytics unavailable'))
    renderDashboard()
    expect(await screen.findByLabelText(/Total assets: 3/i)).toBeInTheDocument()
    expect(await screen.findByText('analytics unavailable')).toBeInTheDocument()
  })
})
