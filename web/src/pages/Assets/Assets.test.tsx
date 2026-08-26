import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api } from '../../lib/api'
import { Assets } from './Assets'

vi.mock('../../lib/api', () => ({ api: { listBusinessAssets: vi.fn(), createBusinessAsset: vi.fn() } }))

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

describe('Assets', () => {
  beforeEach(() => vi.resetAllMocks())

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
})
