import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { ResponseOps } from './ResponseOps'

vi.mock('../../lib/api', () => ({
  api: {
    listResponses: vi.fn(),
    listEngagements: vi.fn().mockResolvedValue([]),
    planResponse: vi.fn(),
    applyResponse: vi.fn(),
    revertResponse: vi.fn(),
    decideResponse: vi.fn(),
    haltOffensive: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) {
      super(message)
    }
  },
}))

describe('ResponseOps', () => {
  beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.listEngagements).mockResolvedValue([]); Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() }) })

  it('renders governed responses, the verification notice, and the kill switch', async () => {
    vi.mocked(api.listResponses).mockResolvedValue([
      { id: 'resp-1', kind: 'isolate_host', target: 'host-web-01', state: 'applied', approver: 'alice', verification: 'succeeded' },
    ] as never)
    vi.mocked(api.listEngagements).mockResolvedValue([] as never)
    render(<ResponseOps />)
    expect(await screen.findByText('isolate host')).toBeInTheDocument()
    expect(screen.getByText('host-web-01')).toBeInTheDocument()
    expect(screen.getByText(/Check verification/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Halt offensive work/ })).toBeInTheDocument()
  })

  it.each(['succeeded', 'timeout'])('refreshes pending verification to %s and stops polling', async (result) => {
    let verification = 'pending'
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [{ id: 'r', kind: 'isolate_host', target: 'host', state: 'applied', verification }] : [])
    vi.useFakeTimers()
    await act(async () => { render(<ResponseOps />) })
    expect(screen.getByText('host')).toBeInTheDocument()
    verification = result
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(screen.getByText(result)).toBeInTheDocument()
    const count = vi.mocked(api.listResponses).mock.calls.length
    await act(async () => { await vi.advanceTimersByTimeAsync(20000) })
    expect(api.listResponses).toHaveBeenCalledTimes(count)
    vi.useRealTimers()
  })

  it.each([false, true])('keeps polling through approval and execution handoffs (reversal=%s)', async (reversal) => {
    let phase = 0
    vi.mocked(api.listResponses).mockImplementation(async (state) => {
      const currentState = phase === 5 ? (reversal ? 'reverted' : 'applied') : (reversal || phase >= 3 ? 'applied' : 'pending')
      return state === currentState ? [{
        id: 'handoff', kind: 'stop_process', target: 'process', state: currentState,
        approvalState: phase === 0 ? 'pending' : phase === 1 ? 'approved' : 'consumed',
        reversalRequestedBy: reversal ? 'alice' : undefined,
        verification: phase === 5 ? 'succeeded' : phase === 4 ? 'pending' : reversal ? 'succeeded' : undefined,
      }] : []
    })
    vi.useFakeTimers()
    try {
      await act(async () => { render(<ResponseOps />) })
      for (phase = 1; phase <= 4; phase++) {
        const count = vi.mocked(api.listResponses).mock.calls.length
        await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
        expect(vi.mocked(api.listResponses).mock.calls.length).toBeGreaterThan(count)
      }
      expect(screen.getByRole('cell', { name: 'pending' })).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
      expect(screen.getByText('succeeded')).toBeInTheDocument()
      const count = vi.mocked(api.listResponses).mock.calls.length
      await act(async () => { await vi.advanceTimersByTimeAsync(20000) })
      expect(api.listResponses).toHaveBeenCalledTimes(count)
    } finally { vi.useRealTimers() }
  })

  it('shows an external approval and eventual reversal without reloading', async () => {
    let phase = 0
    vi.mocked(api.listResponses).mockImplementation(async (state) => {
      if (phase === 0 && state === 'applied') return [{ id: 'r', kind: 'stop_process', target: 'host', state: 'applied', approvalState: 'pending', reversalRequestedBy: 'alice' }]
      if (phase === 1 && state === 'applied') return [{ id: 'r', kind: 'stop_process', target: 'host', state: 'applied', approvalState: 'approved', reversalRequestedBy: 'alice', verification: 'pending' }]
      if (phase === 2 && state === 'reverted') return [{ id: 'r', kind: 'stop_process', target: 'host', state: 'reverted', approvalState: 'consumed', reversalRequestedBy: 'alice', verification: 'succeeded' }]
      return []
    })
    vi.useFakeTimers()
    await act(async () => { render(<ResponseOps />) })
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()
    phase = 1
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(screen.getByText('Reversal approval: approved')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    phase = 2
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(screen.getByText('Reversal approval: consumed')).toBeInTheDocument()
    expect(screen.getByText('succeeded')).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('ignores older refresh results and stops polling on unmount', async () => {
    let resolveOld!: (value: never[]) => void
    vi.mocked(api.listResponses).mockResolvedValue([])
    const { unmount } = render(<ResponseOps />)
    await screen.findByText('No response actions')
    vi.mocked(api.listResponses).mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh responses' }))
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [{ id: 'new', kind: 'isolate_host', target: 'new host', state: 'applied', verification: 'pending' }] : [])
    fireEvent.click(screen.getByRole('button', { name: 'Refresh responses' }))
    expect(await screen.findByText('new host')).toBeInTheDocument()
    await act(async () => resolveOld([{ id: 'old', kind: 'isolate_host', target: 'old host', state: 'pending' }] as never[]))
    expect(screen.queryByText('old host')).not.toBeInTheDocument()
    const clearTimer = vi.spyOn(window, 'clearTimeout')
    unmount()
    expect(clearTimer).toHaveBeenCalled()
    clearTimer.mockRestore()
  })

  it('retries a failed refresh and shows consumed approval as nonactionable', async () => {
    vi.mocked(api.listResponses).mockRejectedValueOnce(new Error('Ledger unavailable')).mockResolvedValue([])
    render(<ResponseOps />)
    expect(await screen.findByText('Ledger unavailable')).toBeInTheDocument()
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'pending' ? [{ id: 'r', kind: 'stop_process', target: 'process', state: 'pending', approvalState: 'consumed' }] : [])
    fireEvent.click(screen.getByRole('button', { name: 'Refresh responses' }))
    expect(await screen.findByText('Approval: consumed')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByText('Ledger unavailable')).not.toBeInTheDocument()
  })

  it('says so when governed response is not enabled', async () => {
    vi.mocked(api.listResponses).mockResolvedValue(null as never)
    vi.mocked(api.listEngagements).mockResolvedValue([] as never)
    render(<ResponseOps />)
    expect(await screen.findByText('Governed response is not enabled on this deployment')).toBeInTheDocument()
  })

  it('plans and applies the exact process and asset binding', async () => {
    const processId = `pe_${'a'.repeat(32)}`
    vi.mocked(api.listResponses).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-1', name: 'Test' }] as never)
    vi.mocked(api.planResponse).mockResolvedValue({ kind: 'stop_process', target: processId, steps: [] })
    vi.mocked(api.applyResponse).mockResolvedValue({ record: { id: 'r', kind: 'stop_process', target: processId, state: 'pending' }, pending: true })
    render(<ResponseOps />)
    await screen.findByRole('combobox', { name: 'Response action' })
    fireEvent.click(screen.getByRole('combobox', { name: 'Response action' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Stop process' }))
    fireEvent.change(screen.getByLabelText('Process entity ID'), { target: { value: processId } })
    fireEvent.change(screen.getByLabelText('Process asset ID'), { target: { value: 'asset-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Plan (dry run)' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Apply through the gate' }))
    const body = { kind: 'stop_process', target: processId, target_kind: 'process', fingerprint: { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId } }
    await waitFor(() => expect(api.applyResponse).toHaveBeenCalledWith('eng-1', body))
    expect(api.planResponse).toHaveBeenCalledWith('eng-1', body)
    expect(await screen.findByText('Recorded, awaiting a second human approval')).toBeInTheDocument()
  })

  it('discards a plan that resolves after its process asset changes', async () => {
    let resolve!: (value: { kind: string; target: string; steps: [] }) => void
    const processId = `pe_${'b'.repeat(32)}`
    vi.mocked(api.listResponses).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-1', name: 'Test' }] as never)
    vi.mocked(api.planResponse).mockReturnValue(new Promise((done) => { resolve = done }))
    render(<ResponseOps />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Response action' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Stop process' }))
    fireEvent.change(screen.getByLabelText('Process entity ID'), { target: { value: processId } })
    fireEvent.change(screen.getByLabelText('Process asset ID'), { target: { value: 'asset-1' } })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Plan (dry run)' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Plan (dry run)' }))
    fireEvent.change(screen.getByLabelText('Process asset ID'), { target: { value: 'asset-2' } })
    await act(async () => resolve({ kind: 'stop_process', target: processId, steps: [] }))
    expect(screen.queryByRole('button', { name: 'Apply through the gate' })).not.toBeInTheDocument()
    expect(api.applyResponse).not.toHaveBeenCalled()
  })

  it('shows binding to reviewers and records an explicit denial', async () => {
    const processId = `pe_${'c'.repeat(32)}`
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'pending' ? [{ id: 'r-1', kind: 'stop_process', target: processId, state: 'pending', approvalState: 'pending', submittedBy: 'alice', targetKind: 'process', fingerprint: { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId } }] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.decideResponse).mockResolvedValue({ id: 'r-1', kind: 'stop_process', target: processId, state: 'cancelled' })
    render(<ResponseOps />)
    expect(await screen.findByText('Asset: asset-1')).toBeInTheDocument()
    expect(screen.getByText('Scope: process')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Decision reason for r-1'), { target: { value: 'Not approved' } })
    fireEvent.click(screen.getByRole('button', { name: 'Deny' }))
    await waitFor(() => expect(api.decideResponse).toHaveBeenCalledWith('r-1', { approve: false, reason: 'Not approved' }))
  })

  it('allows a reviewer to resume a requested reversal and surfaces a refused decision', async () => {
    const processId = `pe_${'e'.repeat(32)}`
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [{ id: 'r-2', kind: 'stop_process', target: processId, state: 'applied', targetKind: 'process', approvalState: 'pending', reversalRequestedBy: 'alice', fingerprint: { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId } }] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.decideResponse).mockRejectedValue(new Error('A distinct reviewer is required'))
    render(<ResponseOps />)
    expect(await screen.findByText('Reversal requested by alice')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('A distinct reviewer is required')
    expect(api.decideResponse).toHaveBeenCalledWith('r-2', { approve: true, reason: '' })
    expect(api.revertResponse).not.toHaveBeenCalled()
  })

  it('hides reversal decisions after denial and reload while retaining the requester', async () => {
    const processId = `pe_${'f'.repeat(32)}`
    let approvalState: 'pending' | 'denied' = 'pending'
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [{ id: 'reversal', kind: 'stop_process', target: processId, state: 'applied', targetKind: 'process', approvalState, reversalRequestedBy: 'alice', fingerprint: { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId } }] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.decideResponse).mockImplementation(async () => { approvalState = 'denied'; return { id: 'reversal', kind: 'stop_process', target: processId, state: 'applied' } })
    render(<ResponseOps />)
    fireEvent.click(await screen.findByRole('button', { name: 'Deny' }))
    expect(await screen.findByText('Reversal approval: denied')).toBeInTheDocument()
    expect(screen.getByText('Reversal requested by alice')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Revert' })).not.toBeInTheDocument()
  })

  it('does not ask for another decision after reversal approval while verification is pending', async () => {
    const processId = `pe_${'1'.repeat(32)}`
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [{ id: 'reversal', kind: 'stop_process', target: processId, state: 'applied', targetKind: 'process', approvalState: 'approved', reversalRequestedBy: 'alice', verification: 'pending', fingerprint: { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId } }] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    render(<ResponseOps />)
    expect(await screen.findByText('Reversal approval: approved')).toBeInTheDocument()
    expect(screen.getByText('Reversal requested by alice')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  it('does not guess that an unavailable approval state is pending', async () => {
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'pending' ? [{ id: 'r', kind: 'stop_process', target: `pe_${'2'.repeat(32)}`, state: 'pending' }] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    render(<ResponseOps />)
    expect(await screen.findByText('Approval: unavailable')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  it('does not offer a plan for a malformed process ID', async () => {
    vi.mocked(api.listResponses).mockResolvedValue([])
    vi.mocked(api.listEngagements).mockResolvedValue([{ id: 'eng-1', name: 'Test' }] as never)
    render(<ResponseOps />)
    fireEvent.click(await screen.findByRole('combobox', { name: 'Response action' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Stop process' }))
    fireEvent.change(screen.getByLabelText('Process entity ID'), { target: { value: `pe_${'A'.repeat(32)}` } })
    fireEvent.change(screen.getByLabelText('Process asset ID'), { target: { value: 'asset-1' } })
    expect(screen.getByRole('button', { name: 'Plan (dry run)' })).toBeDisabled()
    expect(api.planResponse).not.toHaveBeenCalled()
  })

  it('refuses reversal without the persisted binding and sends it when present', async () => {
    const processId = `pe_${'d'.repeat(32)}`
    const fingerprint = { kind: 'process', process_asset_id: 'asset-1', process_entity_id: processId }
    vi.mocked(api.listResponses).mockImplementation(async (state) => state === 'applied' ? [
      { id: 'missing', kind: 'stop_process', target: processId, state: 'applied' },
      { id: 'bound', kind: 'stop_process', target: processId, state: 'applied', targetKind: 'process', fingerprint },
    ] : [])
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.revertResponse).mockResolvedValue({ id: 'bound', kind: 'stop_process', target: processId, state: 'applied' })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<ResponseOps />)
    expect(await screen.findByText('Target binding unavailable; cannot revert.')).toBeInTheDocument()
    const buttons = screen.getAllByRole('button', { name: 'Revert' })
    expect(buttons[0]).toBeDisabled()
    fireEvent.click(buttons[1]!)
    await waitFor(() => expect(api.revertResponse).toHaveBeenCalledWith('bound', { target: processId, target_kind: 'process', fingerprint }))
    vi.restoreAllMocks()
  })
})
