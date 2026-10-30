import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/synapse/Toast'
import { api } from '../../lib/api'
import { DASTTab } from './DASTTab'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error {},
  api: {
    me: vi.fn(),
    judgments: vi.fn(),
    proposeDastScan: vi.fn(),
    runDastScan: vi.fn(),
    decideDastApproval: vi.fn(),
    proposeRuntimeVerification: vi.fn(),
    runRuntimeVerification: vi.fn(),
    getDastRun: vi.fn(),
  },
}))

const PROPOSAL_PENDING = { actionId: 'act-1', tool: 'zap', action: 'scan', targetKind: 'url', targetValue: 'https://t', egressPreview: 'GET https://t', risk: 'medium', rationale: 'crawl and probe', proposedAt: '', decisionState: 'pending', decidedBy: '', decisionReason: '' }

function renderTab() {
  return render(<ToastProvider><DASTTab engagementId="eng-1" /></ToastProvider>)
}

describe('DASTTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.judgments).mockResolvedValue([] as never)
  })

  it('proposes, approves and runs a scan as an admin', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'admin' } as never)
    vi.mocked(api.proposeDastScan).mockResolvedValue(PROPOSAL_PENDING as never)
    vi.mocked(api.decideDastApproval).mockResolvedValue({ actionId: 'act-1', state: 'approved', decidedBy: 'Ana', reason: 'scoped', decidedAt: '' } as never)
    vi.mocked(api.runDastScan).mockResolvedValue({ digest: 'abc123def456', incomplete: false, reason: '', requestCount: 5, coverageCount: 3, proofs: [{ checkId: 'xss.reflected', version: '1', normalizedEndpoint: 'GET /q', hash: 'deadbeefdeadbeef00' }] } as never)

    renderTab()
    fireEvent.change(await screen.findByLabelText('DAST target URL'), { target: { value: 'https://staging.example' } })
    fireEvent.click(screen.getByRole('button', { name: /Propose scan/ }))

    expect(await screen.findByText('act-1', { exact: false })).toBeInTheDocument()
    expect(api.proposeDastScan).toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(api.decideDastApproval).toHaveBeenCalledWith('eng-1', 'act-1', true, ''))

    fireEvent.click(await screen.findByRole('button', { name: /Run scan/ }))
    expect(await screen.findByText('xss.reflected')).toBeInTheDocument()
    expect(screen.getByText('Scan result')).toBeInTheDocument()
  })

  it('hides propose from a read-only user', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u2', name: 'Ro', role: 'readonly' } as never)
    renderTab()
    expect(await screen.findByText(/Proposing a scan needs the operator role/)).toBeInTheDocument()
    const propose = screen.getByRole('button', { name: /Propose scan/ }) as HTMLButtonElement
    expect(propose.disabled).toBe(true)
  })

  it('offers runtime verification when a probeable judgment exists', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'admin' } as never)
    vi.mocked(api.judgments).mockResolvedValue([
      { id: 'jud-sast-1', engagementId: 'eng-1', capability: 'sast', subjectKind: 'finding', subjectId: 'f-1', state: 'proposed', evidenceScore: 0, proposedBy: 'model', version: 2, claim: {} },
    ] as never)
    renderTab()
    expect(await screen.findByText('Runtime verification')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Propose probe/ })).toBeInTheDocument()
  })

  async function launchQueuedProbe() {
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'admin' } as never)
    vi.mocked(api.judgments).mockResolvedValue([{ id: 'jud-fixture', capability: 'reachability', version: 1 }] as never)
    vi.mocked(api.proposeRuntimeVerification).mockResolvedValue(PROPOSAL_PENDING as never)
    vi.mocked(api.decideDastApproval).mockResolvedValue({ state: 'approved', decidedBy: 'Ana' } as never)
    vi.mocked(api.runRuntimeVerification).mockResolvedValue({ durable: true, run: { id: 'run-fixture', status: 'queued' } } as never)
    const view = renderTab()
    fireEvent.click(await screen.findByRole('combobox', { name: 'Judgment to verify' }))
    fireEvent.click(screen.getByRole('option', { name: 'reachability · jud-fixt' }))
    fireEvent.change(screen.getByLabelText('Probe URL'), { target: { value: 'https://example.test/fixture' } })
    fireEvent.click(screen.getByRole('button', { name: /Propose probe/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }))
    fireEvent.click(await screen.findByRole('button', { name: /Run probe/ }))
    return view
  }

  it('shows the terminal durable verdict and evidence after enqueue', async () => {
    vi.mocked(api.getDastRun).mockResolvedValue({ id: 'run-fixture', status: 'succeeded', verdict: 'runtime_confirmed', httpStatus: 200, evidenceId: 'sealed-fixture' } as never)
    await launchQueuedProbe()
    expect(await screen.findByText('succeeded')).toBeInTheDocument()
    expect(screen.getByText('verdict runtime_confirmed')).toBeInTheDocument()
    expect(screen.getByText('HTTP 200')).toBeInTheDocument()
    expect(screen.getByText('evidence sealed-fixture')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Run probe/ })).toBeDisabled()
  })

  it('discards an old probe response when navigating to another engagement', async () => {
    let complete!: (value: never) => void
    vi.mocked(api.getDastRun).mockImplementation(() => new Promise((resolve) => { complete = resolve }))
    const view = await launchQueuedProbe()
    await waitFor(() => expect(complete).toBeTypeOf('function'))
    vi.mocked(api.judgments).mockResolvedValue([])
    view.rerender(<ToastProvider><DASTTab engagementId="eng-other" /></ToastProvider>)
    await act(async () => { complete({ id: 'run-fixture', status: 'succeeded', verdict: 'runtime_confirmed', httpStatus: 200 } as never) })
    expect(screen.queryByText('verdict runtime_confirmed')).not.toBeInTheDocument()
    expect(screen.queryByText('run run-fixture')).not.toBeInTheDocument()
  })
})
