import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, AlertNotEnabledError } from '../../lib/api'
import { Alerting } from './Alerting'

vi.mock('../../lib/api', () => ({
  api: { testAlert: vi.fn(), me: vi.fn() },
  AlertNotEnabledError: class AlertNotEnabledError extends Error {
    constructor() {
      super('Alerting is not enabled in this deployment.')
      this.name = 'AlertNotEnabledError'
    }
  },
}))

describe('Alerting', () => {
  beforeEach(() => vi.resetAllMocks())

  it('an admin sends a test alert and sees the per-sink outcome', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.testAlert).mockResolvedValue({ acknowledged: true, outcome: { matched: true, delivered: 2, failed: 0, auditFailed: 0 } } as never)
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: /Send test alert/ }))
    await waitFor(() => expect(api.testAlert).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('Acknowledged')).toBeInTheDocument()
    expect(screen.getByText('Delivered')).toBeInTheDocument()
  })

  it('renders the no-acknowledgement outcome on a 502-style result', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.testAlert).mockResolvedValue({ acknowledged: false, error: 'no alert sink acknowledged the test alert', outcome: { matched: true, delivered: 0, failed: 2, auditFailed: 0 } } as never)
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: /Send test alert/ }))
    expect(await screen.findByText('No acknowledgement')).toBeInTheDocument()
    expect(screen.getByText(/no alert sink acknowledged/)).toBeInTheDocument()
  })

  it('disables the action for a non-admin', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    render(<Alerting />)
    expect(await screen.findByRole('button', { name: /Send test alert/ })).toBeDisabled()
  })

  it('shows a not-enabled state when the route is absent', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.testAlert).mockRejectedValue(new AlertNotEnabledError())
    render(<Alerting />)
    fireEvent.click(await screen.findByRole('button', { name: /Send test alert/ }))
    expect(await screen.findByText('Alerting is not enabled')).toBeInTheDocument()
  })
})
