import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { EngagementDetail } from './index'

vi.mock('../../lib/api', () => ({
  api: {
    getEngagement: vi.fn(),
    findings: vi.fn(),
    latestScan: vi.fn(),
    scanStatus: vi.fn(),
    importedSBOM: vi.fn(),
    evidence: vi.fn(),
    listBusinessAssets: vi.fn(),
    assignEngagementAsset: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

const mockEngagement = {
  id: 'eng-123456',
  name: 'Acme Core Security Audit',
  client: 'Acme Corp',
  status: 'active',
  inScope: [{ kind: 'repo', value: 'github.com/acme/core-service' }],
  outOfScope: [],
  authorizedFrom: null,
  authorizedTo: null,
  roe: { allowedToolClasses: [], blackouts: [] },
  liveReconEnabled: false,
  createdAt: '2026-08-15T00:00:00Z',
  businessAssetId: '',
}

describe('EngagementDetail Page Shell', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getEngagement).mockResolvedValue(mockEngagement)
    vi.mocked(api.findings).mockResolvedValue([])
    vi.mocked(api.latestScan).mockResolvedValue(null)
    vi.mocked(api.scanStatus).mockResolvedValue(null)
    vi.mocked(api.importedSBOM).mockResolvedValue(null as any)
    vi.mocked(api.evidence).mockResolvedValue(null)
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
  })

  it('renders breadcrumb, engagement name, and status pill', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('heading', { name: 'Acme Core Security Audit' })).toBeInTheDocument()
    expect(screen.getByLabelText('Breadcrumb')).toBeInTheDocument()
    expect(screen.getByText('Engagements')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getAllByTitle('github.com/acme/core-service').length).toBeGreaterThan(0)
  })

  it('renders tab list with accessible roles and switches tabs', async () => {
    render(
      <MemoryRouter initialEntries={['/engagements/eng-123456']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
          <Route path="/engagements/:id/:tabSlug" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('tablist', { name: 'Engagement Views' })).toBeInTheDocument()

    const findingsTab = screen.getByRole('tab', { name: /Findings/i })
    expect(findingsTab).toBeInTheDocument()

    fireEvent.click(findingsTab)

    await waitFor(() => {
      expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'panel-findings')
    })
  })

  it('renders not found state when engagement does not exist', async () => {
    vi.mocked(api.getEngagement).mockResolvedValue(null as any)

    render(
      <MemoryRouter initialEntries={['/engagements/non-existent']}>
        <Routes>
          <Route path="/engagements/:id" element={<EngagementDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByText('Engagement not found')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Back to engagements/i })).toBeInTheDocument()
  })
})
