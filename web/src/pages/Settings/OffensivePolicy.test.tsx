import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { OffensivePolicy } from './OffensivePolicy'

vi.mock('../../lib/api', () => ({ api: { offensivePolicy: vi.fn() } }))

const POLICY = {
  legalReview: { reviewed: true, date: '2026-08-01', owner: 'security-lead', counselReviewed: true, counselDate: '2026-08-04' },
  techniques: [
    { technique: 'recon.port_scan', taxonomyRef: 'TA0043', disruption: 'none', reversibility: 'reversible', riskClass: 'low', approval: 'auto', blastRadius: 'read_only', productionSafe: true, prohibited: false },
    { technique: 'impact.data_destruction', taxonomyRef: 'T1485', disruption: 'high', reversibility: 'irreversible', riskClass: 'prohibited', approval: '', blastRadius: 'destructive', productionSafe: false, prohibited: true },
  ],
  prohibited: 1,
  productionSafe: 1,
}

describe('OffensivePolicy', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders the technique register with risk class and prohibited state', async () => {
    vi.mocked(api.offensivePolicy).mockResolvedValue(POLICY as never)
    render(<OffensivePolicy />)
    expect(await screen.findByText('recon.port_scan')).toBeInTheDocument()
    expect(screen.getByText('impact.data_destruction')).toBeInTheDocument()
    expect(screen.getByText('Prohibited')).toBeInTheDocument()
    expect(screen.getByText('Prod-safe')).toBeInTheDocument()
    // Legal review is surfaced.
    expect(screen.getByText('Policy reviewed')).toBeInTheDocument()
    expect(screen.getByText('Counsel signed off')).toBeInTheDocument()
  })

  it('says so when the register is not loaded', async () => {
    vi.mocked(api.offensivePolicy).mockResolvedValue(null as never)
    render(<OffensivePolicy />)
    expect(await screen.findByText('Offensive policy is not enabled')).toBeInTheDocument()
  })
})
