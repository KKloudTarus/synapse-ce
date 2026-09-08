import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { AssetGraph } from './AssetGraph'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error {},
  api: {
    listTechnicalAssets: vi.fn(),
    fleetAssetEdges: vi.fn(),
    createAssetEdge: vi.fn(),
    me: vi.fn(),
  },
}))

const ASSETS = [
  { id: 'asset-a', kind: 'host', key: 'machine/aaa', name: 'web01', attributes: {} },
  { id: 'asset-b', kind: 'workload', key: 'shop/checkout', name: 'checkout-api', attributes: {} },
  { id: 'asset-c', kind: 'image', key: 'sha256:deadbeef', name: 'checkout:1.4', attributes: {} },
]
const EDGES = [
  { tenantId: 'default', from: 'asset-a', to: 'asset-b', kind: 'runs', provenance: 'obs-1', confidence: 'observed' },
  { tenantId: 'default', from: 'asset-b', to: 'asset-c', kind: 'depends_on', provenance: 'obs-2', confidence: 'inferred' },
]

describe('AssetGraph', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue(null as never)
  })

  it('renders relationships and resolves asset names', async () => {
    vi.mocked(api.listTechnicalAssets).mockResolvedValue(ASSETS as never)
    vi.mocked(api.fleetAssetEdges).mockResolvedValue(EDGES as never)
    render(<AssetGraph />)
    expect(await screen.findByText('web01')).toBeInTheDocument()
    // checkout-api is both the target of the runs edge and the source of the depends_on edge
    expect(screen.getAllByText('checkout-api').length).toBe(2)
    expect(screen.getByText('checkout:1.4')).toBeInTheDocument()
    expect(screen.getByText('runs')).toBeInTheDocument()
    expect(screen.getByText('depends on')).toBeInTheDocument()
    // observed edge shows a pill; inferred edge hides its reason behind a tooltip trigger
    expect(screen.getByText('observed')).toBeInTheDocument()
    expect(screen.getByText('2 relationships')).toBeInTheDocument()
  })

  it('filters relationships by asset name', async () => {
    vi.mocked(api.listTechnicalAssets).mockResolvedValue(ASSETS as never)
    vi.mocked(api.fleetAssetEdges).mockResolvedValue(EDGES as never)
    render(<AssetGraph />)
    await screen.findByText('web01')
    fireEvent.change(screen.getByLabelText('Filter relationships'), { target: { value: 'web01' } })
    expect(screen.getByText('1 of 2 relationships')).toBeInTheDocument()
  })

  it('shows an empty state when there are no edges', async () => {
    vi.mocked(api.listTechnicalAssets).mockResolvedValue(ASSETS as never)
    vi.mocked(api.fleetAssetEdges).mockResolvedValue([] as never)
    render(<AssetGraph />)
    expect(await screen.findByText('No relationships yet')).toBeInTheDocument()
  })

  it('offers the add-relationship form to an operator and hides it from read-only', async () => {
    vi.mocked(api.listTechnicalAssets).mockResolvedValue(ASSETS as never)
    vi.mocked(api.fleetAssetEdges).mockResolvedValue(EDGES as never)
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'consultant' } as never)
    const { unmount } = render(<AssetGraph />)
    expect(await screen.findByText('Add a relationship')).toBeInTheDocument()
    unmount()

    vi.mocked(api.me).mockResolvedValue({ id: 'u2', name: 'Ro', role: 'readonly' } as never)
    render(<AssetGraph />)
    await screen.findByText('web01')
    await waitFor(() => expect(screen.queryByText('Add a relationship')).not.toBeInTheDocument())
  })
})
