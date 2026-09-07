import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { Workloads } from './Workloads'

vi.mock('../../lib/api', () => ({ api: { fleetWorkloads: vi.fn() } }))

const DIGEST = 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
const WL = [
  { cluster: 'prod', namespace: 'shop', kind: 'Deployment', name: 'checkout-api', serviceAccount: 'checkout', images: [{ ref: 'reg/checkout:1.4', digest: DIGEST }] },
  { cluster: 'prod', namespace: 'data', kind: 'StatefulSet', name: 'postgres', serviceAccount: 'default', images: [{ ref: 'postgres:16', digest: DIGEST }] },
  { cluster: 'prod', namespace: 'shop', kind: 'Deployment', name: 'web', serviceAccount: 'default', images: [{ ref: 'nginx:1.27', digest: 'sha256:2222222222222222222222222222222222222222222222222222222222222222' }] },
]

describe('Workloads', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists workloads grouped by namespace and traces a shared image to other workloads', async () => {
    vi.mocked(api.fleetWorkloads).mockResolvedValue(WL as never)
    render(<Workloads />)
    expect(await screen.findByText('checkout-api')).toBeInTheDocument()
    expect(screen.getByText('postgres')).toBeInTheDocument()
    expect(screen.getByText('StatefulSet')).toBeInTheDocument()
    // The image shared by checkout-api + postgres is flagged on both (so a CVE on it traces to both).
    expect(screen.getAllByText(/also runs in 1 other workload/).length).toBe(2)
  })

  it('filters by image', async () => {
    vi.mocked(api.fleetWorkloads).mockResolvedValue(WL as never)
    render(<Workloads />)
    await screen.findByText('checkout-api')
    fireEvent.change(screen.getByLabelText('Filter workloads'), { target: { value: 'nginx' } })
    expect(screen.getByText('web')).toBeInTheDocument()
    expect(screen.queryByText('checkout-api')).not.toBeInTheDocument()
  })

  it('shows the enrol-a-cluster-agent empty state', async () => {
    vi.mocked(api.fleetWorkloads).mockResolvedValue([] as never)
    render(<Workloads />)
    expect(await screen.findByText('No cluster inventory yet')).toBeInTheDocument()
  })
})
