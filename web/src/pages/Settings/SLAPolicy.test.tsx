import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { SLAPolicy } from './SLAPolicy'

vi.mock('../../lib/api', () => ({ api: { slaPolicies: vi.fn(), activateSLAPolicy: vi.fn(), me: vi.fn() } }))

const POLICY = {
  tenantId: 'tenant-dev',
  sha256: 'a1b2c3d4e5f6ffff',
  createdBy: 'admin@dev',
  createdAt: '2026-08-01T00:00:00Z',
  config: {
    version: 'sla-v1',
    weights: { severity: 35, exploitability: 25, threatIntel: 10, exposure: 15, criticality: 15, feasibilityRelief: 15 },
    thresholds: { emergency: 85, critical: 70, high: 50, medium: 30 },
    dueRanges: {
      emergency: { mitigateDays: 1, remediateDays: 7 },
      critical: { mitigateDays: 3, remediateDays: 15 },
      high: { mitigateDays: 7, remediateDays: 30 },
      medium: { mitigateDays: 30, remediateDays: 90 },
      low: { mitigateDays: 90, remediateDays: 180 },
      exception: { mitigateDays: 30, remediateDays: 180 },
    },
  },
}

describe('SLAPolicy', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders the active policy factors and tier windows', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: POLICY, policies: [POLICY] } as never)
    render(<SLAPolicy />)
    expect(await screen.findByText('Active policy')).toBeInTheDocument()
    expect(screen.getAllByText('sla-v1').length).toBeGreaterThan(0)
    // Positive weight sum is 100 and flagged green as the recommended sum.
    expect(screen.getAllByText('100').length).toBeGreaterThan(0)
  })

  it('an admin can activate a policy version', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: POLICY, policies: [POLICY] } as never)
    vi.mocked(api.activateSLAPolicy).mockResolvedValue({ policy: POLICY, created: true } as never)
    render(<SLAPolicy />)
    await screen.findByText('Activate a policy version')
    fireEvent.click(screen.getByRole('button', { name: /Activate/ }))
    await waitFor(() => expect(api.activateSLAPolicy).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.activateSLAPolicy).mock.calls[0][0]).toMatchObject({ version: 'sla-v1' })
  })

  it('blocks activation when thresholds are not strictly descending', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: POLICY, policies: [POLICY] } as never)
    render(<SLAPolicy />)
    await screen.findByText('Activate a policy version')
    // Push medium above high so the ladder is no longer descending.
    fireEvent.change(screen.getByLabelText('Medium'), { target: { value: '60' } })
    expect(screen.getByText(/strictly descending and positive/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Activate/ })).toBeDisabled()
  })

  it('disables activation for a non-admin', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: POLICY, policies: [POLICY] } as never)
    render(<SLAPolicy />)
    await screen.findByText('Activate a policy version')
    expect(screen.getByRole('button', { name: /Activate/ })).toBeDisabled()
    expect(screen.getByText(/needs the administer permission/)).toBeInTheDocument()
  })

  it('says so when SLA governance is not enabled', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.slaPolicies).mockResolvedValue(null as never)
    render(<SLAPolicy />)
    expect(await screen.findByText('SLA governance is not enabled')).toBeInTheDocument()
  })
})
