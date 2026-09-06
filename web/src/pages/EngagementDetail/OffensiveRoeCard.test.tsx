import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Engagement } from '../../lib/types'
import { OffensiveRoeCard } from './SettingsTab'

vi.mock('../../lib/api', () => ({
  api: { setOffensiveRoE: vi.fn() },
}))

function engagement(over: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-1',
    name: 'Acme pentest',
    client: 'Acme',
    status: 'active',
    inScope: [{ kind: 'domain', value: 'app.test' }],
    outOfScope: [],
    authorizedFrom: '2026-09-01T00:00:00Z',
    authorizedTo: '2026-10-01T00:00:00Z',
    roe: { allowedToolClasses: [], blackouts: [] },
    liveReconEnabled: false,
    offensiveRoe: { customerContact: '', emergencyContact: '', riskCeiling: '', exclusionsChecked: false },
    createdAt: '2026-09-01T00:00:00Z',
    businessAssetId: '',
    ...over,
  }
}

describe('OffensiveRoeCard', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows Incomplete and lists what is missing when the RoE is unset', () => {
    render(<OffensiveRoeCard eng={engagement()} onUpdated={vi.fn()} />)
    expect(screen.getByText('Incomplete')).toBeInTheDocument()
    expect(screen.getByText(/customer contact/)).toBeInTheDocument()
    expect(screen.getByText(/risk ceiling/)).toBeInTheDocument()
  })

  it('shows Offensive ready when the RoE, window and scope are all set', () => {
    render(
      <OffensiveRoeCard
        eng={engagement({
          offensiveRoe: { customerContact: 'Ops', emergencyContact: '+1', riskCeiling: 'high', exclusionsChecked: true },
        })}
        onUpdated={vi.fn()}
      />,
    )
    expect(screen.getByText('Offensive ready')).toBeInTheDocument()
  })

  it('saves the entered rules of engagement through the API', async () => {
    const updated = engagement({
      offensiveRoe: { customerContact: 'Ops', emergencyContact: '+1', riskCeiling: 'high', exclusionsChecked: true },
    })
    vi.mocked(api.setOffensiveRoE).mockResolvedValue(updated)
    const onUpdated = vi.fn()
    render(<OffensiveRoeCard eng={engagement()} onUpdated={onUpdated} />)

    fireEvent.change(screen.getByLabelText('Customer contact'), { target: { value: 'Ops' } })
    fireEvent.change(screen.getByLabelText('Emergency contact'), { target: { value: '+1' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /out-of-scope list was reviewed/i }))
    fireEvent.click(screen.getByRole('button', { name: /save rules/i }))

    await waitFor(() => expect(api.setOffensiveRoE).toHaveBeenCalledTimes(1))
    expect(api.setOffensiveRoE).toHaveBeenCalledWith('eng-1', {
      customerContact: 'Ops',
      emergencyContact: '+1',
      riskCeiling: '',
      exclusionsChecked: true,
    })
    await waitFor(() => expect(onUpdated).toHaveBeenCalledWith(updated))
  })
})
