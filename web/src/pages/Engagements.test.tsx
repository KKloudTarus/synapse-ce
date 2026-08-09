import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import { Engagements } from './Engagements'

vi.mock('../lib/api', () => ({
  api: {
    listEngagements: vi.fn(),
    listBusinessAssets: vi.fn(),
    createEngagement: vi.fn(),
    importBundle: vi.fn(),
  },
}))

describe('Engagements', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.listBusinessAssets).mockResolvedValue({
      items: [{
        id: 'a1',
        key: 'mobile',
        name: 'Mobile Banking',
        description: '',
        type: 'application',
        criticality: 'critical',
        lifecycle: 'active',
        owner: 'Mobile Team',
        metadata: {},
        version: 1,
        createdAt: null,
        updatedAt: null,
      }],
      total: 1,
      limit: 200,
      offset: 0,
    })
  })

  it('opens creation and preselects the Asset from query parameters', async () => {
    render(<MemoryRouter initialEntries={['/engagements?create=1&assetId=a1']}><Engagements /></MemoryRouter>)

    expect(screen.getByRole('heading', { name: 'New Engagement' })).toBeInTheDocument()
    expect((await screen.findAllByText('Mobile Banking (mobile)')).length).toBeGreaterThan(0)
    await waitFor(() => expect(api.listBusinessAssets).toHaveBeenCalledWith('limit=200'))
  })
})
