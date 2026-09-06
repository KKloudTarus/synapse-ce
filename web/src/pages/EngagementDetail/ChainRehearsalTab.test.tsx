import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import { ChainRehearsalTab } from './ChainRehearsalTab'

vi.mock('../../lib/api', () => ({
  api: { listTechnicalAssets: vi.fn(), rehearseChain: vi.fn() },
}))

describe('ChainRehearsalTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listTechnicalAssets).mockResolvedValue([{ id: 'asset-1', kind: 'host', key: 'web-01', name: 'web-01', attributes: {} }])
  })

  it('labels the rehearsal as a simulation and keeps Rehearse disabled until a step is complete', async () => {
    render(
      <ToastProvider>
        <ChainRehearsalTab engagementId="eng-001" />
      </ToastProvider>,
    )
    // The simulation framing is explicit, not implied.
    expect(await screen.findByText(/Simulation, not real exploitation/i)).toBeInTheDocument()
    // With an empty step, the run is disabled and no rehearsal starts blindly.
    expect(screen.getByRole('button', { name: /run no-host rehearsal/i })).toBeDisabled()
    expect(api.rehearseChain).not.toHaveBeenCalled()
  })
})
