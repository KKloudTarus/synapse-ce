import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../lib/api'
import { AssetDetail } from './AssetDetail'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return { ...actual, api: { getBusinessAsset: vi.fn() } }
})

const { api } = await import('../../lib/api')

function renderRoute() {
  render(
    <MemoryRouter initialEntries={['/assets/some-key']}>
      <Routes>
        <Route path="/assets/:key" element={<AssetDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

// Each of these states fills the whole route, so each carries the only heading the screen has.
// Rendered bare they left the document with no heading at all: a Chromium sweep of
// /assets/:key and its five sub-tabs reported 12 of 12 captures headless, in both themes and at
// both widths, so a screen reader landed on a page it could not name.
describe('AssetDetail whole-route states', () => {
  beforeEach(() => vi.resetAllMocks())

  it('names the page when the asset is absent', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(404, 'HTTP 404'))
    renderRoute()
    expect(await screen.findByRole('heading', { level: 1, name: 'Asset not found' })).toBeInTheDocument()
  })

  it('names the page while it loads', async () => {
    vi.mocked(api.getBusinessAsset).mockReturnValue(new Promise(() => {}) as never)
    renderRoute()
    expect(await screen.findByRole('heading', { level: 1, name: 'Asset' })).toBeInTheDocument()
    expect(screen.getByText(/Loading Asset/)).toBeInTheDocument()
  })

  it('names the page when the fetch fails for another reason', async () => {
    vi.mocked(api.getBusinessAsset).mockRejectedValue(new ApiError(503, 'HTTP 503'))
    renderRoute()
    expect(await screen.findByRole('heading', { level: 1, name: 'Asset' })).toBeInTheDocument()
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument()
  })
})
