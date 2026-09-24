import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api } from '../../lib/api'
import { Assets } from './Assets'

vi.mock('../../lib/api', () => ({ api: { listBusinessAssets: vi.fn(), createBusinessAsset: vi.fn(), businessAssetCounts: vi.fn() } }))

const asset = {
  id: 'a1',
  key: 'mobile',
  name: 'Mobile Banking',
  description: 'Banking app',
  type: 'application' as const,
  criticality: 'critical' as const,
  lifecycle: 'active' as const,
  owner: 'team',
  metadata: {},
  version: 1,
  createdAt: null,
  updatedAt: null,
  posture: 'unknown',
}

const counts = { byCriticality: { critical: 37, high: 10, medium: 5, low: 68 }, total: 120 }

describe('Assets', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.businessAssetCounts).mockResolvedValue(counts)
  })

  it('renders honest empty and filtered states', async () => {
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 24, offset: 0 })
    const first = render(<MemoryRouter><Assets /></MemoryRouter>)
    expect(await screen.findByText('No Assets yet')).toBeInTheDocument()
    first.unmount()

    vi.mocked(api.listBusinessAssets).mockImplementation(async (query = '') => query.includes('q=missing')
      ? { items: [], total: 0, limit: 24, offset: 0 }
      : { items: [asset], total: 1, limit: 24, offset: 0 })
    render(<MemoryRouter><Assets /></MemoryRouter>)
    expect(await screen.findByRole('heading', { name: 'Mobile Banking' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Search assets'), { target: { value: 'missing' } })
    expect(await screen.findByText('No matching Assets')).toBeInTheDocument()
  })

  it('creates and navigates to Asset detail', async () => {
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 24, offset: 0 })
    vi.mocked(api.createBusinessAsset).mockResolvedValue(asset)
    render(
      <MemoryRouter initialEntries={['/assets']}>
        <Routes>
          <Route path="/assets" element={<Assets />} />
          <Route path="/assets/:key" element={<div>Asset detail route</div>} />
        </Routes>
      </MemoryRouter>,
    )
    fireEvent.click(await screen.findByRole('button', { name: /New Asset/i }))
    fireEvent.change(screen.getByPlaceholderText('mobile-banking'), { target: { value: 'mobile' } })
    fireEvent.change(screen.getByPlaceholderText('Mobile Banking App'), { target: { value: 'Mobile Banking' } })
    fireEvent.change(screen.getByPlaceholderText('Mobile Platform Team'), { target: { value: 'team' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Asset' }))
    await waitFor(() => expect(api.createBusinessAsset).toHaveBeenCalled())
    expect(await screen.findByText('Asset detail route')).toBeInTheDocument()
  })

  // Counting only the visible page under-reported critical assets across a multi-page estate, which
  // on a security inventory reads as fewer critical assets than exist.
  it('reports the estate-wide critical count, not the visible page', async () => {
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [asset], total: 120, limit: 24, offset: 0 })
    render(<MemoryRouter><Assets /></MemoryRouter>)
    expect(await screen.findByText('120')).toBeInTheDocument()
    // 37 is the estate-wide aggregate, not the single critical row on this page.
    expect(await screen.findByText('37')).toBeInTheDocument()
    // Page-scoped figures state their scope so they are not read as estate-wide.
    expect(screen.getByText('Needs attention on this page')).toBeInTheDocument()
  })

  // Using a filtered list request as a counter cost a second full scan of the tenant's assets on
  // every filter change, measured at 2.09x the page-view cost at 100k assets.
  it('never issues a second list request to count criticality', async () => {
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [asset], total: 120, limit: 24, offset: 0 })
    render(<MemoryRouter><Assets /></MemoryRouter>)

    await screen.findByText('37')
    expect(api.listBusinessAssets).toHaveBeenCalledTimes(1)
    expect(vi.mocked(api.listBusinessAssets).mock.calls.every(([query]) => !String(query ?? '').includes('criticality=critical'))).toBe(true)
    expect(api.businessAssetCounts).toHaveBeenCalledTimes(1)
  })

  // Changing a filter must not refetch the estate-wide histogram: it does not depend on the filter.
  it('does not refetch the count when a filter changes', async () => {
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [asset], total: 120, limit: 24, offset: 0 })
    render(<MemoryRouter><Assets /></MemoryRouter>)

    await screen.findByText('37')
    fireEvent.change(screen.getByLabelText('Search assets'), { target: { value: 'mobile' } })
    await waitFor(() => expect(vi.mocked(api.listBusinessAssets).mock.calls.length).toBeGreaterThan(1))
    expect(api.businessAssetCounts).toHaveBeenCalledTimes(1)
  })

  // A count that failed to load used to render as 0, which on a security inventory is a false
  // all-clear and is the exact bug class this screen was changed to remove.
  it('says the critical count is unavailable when its request fails', async () => {
    vi.mocked(api.businessAssetCounts).mockRejectedValue(new Error('count query failed'))
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [asset], total: 120, limit: 24, offset: 0 })
    render(<MemoryRouter><Assets /></MemoryRouter>)

    expect(await screen.findByText('120')).toBeInTheDocument()
    expect(await screen.findByText('Unavailable')).toBeInTheDocument()
  })

  it('says every count is unavailable when the inventory request fails', async () => {
    vi.mocked(api.businessAssetCounts).mockRejectedValue(new Error('count query failed'))
    vi.mocked(api.listBusinessAssets).mockRejectedValue(new Error('inventory unavailable'))
    render(<MemoryRouter><Assets /></MemoryRouter>)

    await screen.findByText('inventory unavailable')
    // Total, critical, and the two page-scoped figures all read Unavailable rather than 0.
    expect(screen.getAllByText('Unavailable').length).toBe(4)
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })
})
