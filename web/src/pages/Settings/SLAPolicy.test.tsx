import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/synapse/Toast'
import { api } from '../../lib/api'
import type { SlaConfig, SlaPolicy } from '../../lib/api'
import { SLAPolicy } from './SLAPolicy'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return { ...actual, api: { slaPolicies: vi.fn(), activateSLAPolicy: vi.fn() } }
})

function config(): SlaConfig {
  const dr = { mitigateDays: 1, remediateDays: 7 }
  return {
    version: 'sla-v1',
    weights: { severity: 35, exploitability: 25, threatIntel: 10, exposure: 15, criticality: 15, feasibilityRelief: 15 },
    thresholds: { emergency: 85, critical: 70, high: 50, medium: 30 },
    dueRanges: { emergency: dr, critical: dr, high: dr, medium: dr, low: dr, exception: dr },
  }
}

function policy(): SlaPolicy {
  return { config: config(), sha256: 'a1b2c3d4e5f6', createdBy: 'system', createdAt: '2026-08-01T00:00:00Z' }
}

function renderPage() {
  render(
    <ToastProvider>
      <SLAPolicy />
    </ToastProvider>,
  )
}

describe('SLAPolicy', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows the active policy, its digest, and a balanced weight sum', async () => {
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: policy(), policies: [policy()] })
    renderPage()

    // 'sla-v1' and the digest appear in both the active card and the history, so match all.
    expect((await screen.findAllByText('sla-v1')).length).toBeGreaterThan(0)
    expect(screen.getByText('Active policy')).toBeInTheDocument()
    expect(screen.getAllByText(/a1b2c3d4e5f6/).length).toBeGreaterThan(0)
    // severity+exploitability+threatIntel+exposure+criticality = 100
    expect(screen.getByText(/sums to 100/)).toBeInTheDocument()
  })

  it('blocks activation when the weights no longer sum to 100', async () => {
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: policy(), policies: [policy()] })
    renderPage()

    fireEvent.change(await screen.findByLabelText('Weight Severity'), { target: { value: '50' } })

    expect(await screen.findByText(/cannot activate/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /activate new version/i })).toBeDisabled()
  })

  it('activates a new version after an edit', async () => {
    vi.mocked(api.slaPolicies).mockResolvedValue({ active: policy(), policies: [policy()] })
    vi.mocked(api.activateSLAPolicy).mockResolvedValue({ policy: policy(), created: true })
    renderPage()

    // Keep the five factors summing to 100 (severity +5, exploitability -5) so the config stays valid.
    fireEvent.change(await screen.findByLabelText('Weight Severity'), { target: { value: '40' } })
    fireEvent.change(screen.getByLabelText('Weight Exploitability'), { target: { value: '20' } })

    const activate = screen.getByRole('button', { name: /activate new version/i })
    await waitFor(() => expect(activate).toBeEnabled())
    fireEvent.click(activate)

    await waitFor(() => expect(api.activateSLAPolicy).toHaveBeenCalled())
    const sent = vi.mocked(api.activateSLAPolicy).mock.calls[0][0]
    expect(sent.weights.severity).toBe(40)
    expect(sent.weights.exploitability).toBe(20)
  })
})
