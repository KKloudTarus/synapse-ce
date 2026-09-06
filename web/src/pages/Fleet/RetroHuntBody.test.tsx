import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { RetroHuntResult } from '../../lib/api'
import { RetroHuntBody } from './HostDetail'

vi.mock('../../lib/api', () => ({
  api: { retroHunt: vi.fn() },
}))

function result(): RetroHuntResult {
  return {
    assetId: 'ba-001',
    from: '2026-09-01T11:45:00Z',
    to: '2026-09-01T12:15:00Z',
    truncated: true,
    entries: [
      { occurredAt: '2026-09-01T11:50:00Z', entityKind: 'process', entityId: 'pid-4821', kind: 'process_exec', eventId: 'ev-1', summary: 'curl spawned by bash' },
      { occurredAt: '2026-09-01T12:00:00Z', entityKind: 'network', entityId: 'conn-77', kind: 'egress_connect', eventId: 'ev-2', summary: 'outbound 443' },
    ],
  }
}

describe('RetroHuntBody', () => {
  beforeEach(() => vi.resetAllMocks())

  it('hunts the timeline window and renders the transitions and truncation', async () => {
    vi.mocked(api.retroHunt).mockResolvedValue(result())
    render(<RetroHuntBody assetId="ba-001" />)

    fireEvent.click(screen.getByRole('button', { name: /hunt/i }))

    await waitFor(() => expect(api.retroHunt).toHaveBeenCalled())
    const [assetId, req] = vi.mocked(api.retroHunt).mock.calls[0]
    expect(assetId).toBe('ba-001')
    // 15 minutes look-back/forward defaults => 900 seconds.
    expect(req.beforeSeconds).toBe(900)
    expect(req.afterSeconds).toBe(900)

    expect(await screen.findByText('process_exec')).toBeInTheDocument()
    expect(screen.getByText('egress_connect')).toBeInTheDocument()
    expect(screen.getByText(/window capped/)).toBeInTheDocument()
    expect(screen.getByText(/2 transitions/)).toBeInTheDocument()
  })

  it('blocks a zero-width window', () => {
    render(<RetroHuntBody assetId="ba-001" />)
    fireEvent.change(screen.getByLabelText('Retro-hunt look-back minutes'), { target: { value: '0' } })
    fireEvent.change(screen.getByLabelText('Retro-hunt look-forward minutes'), { target: { value: '0' } })
    expect(screen.getByText(/zero-width window is rejected/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /hunt/i })).toBeDisabled()
  })
})
