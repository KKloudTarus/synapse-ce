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
    getDastScanRun: vi.fn(),
  },
}))

const PROPOSAL_PENDING = { actionId: 'act-1', tool: 'zap', action: 'scan', targetKind: 'url', targetValue: 'https://t', egressPreview: 'GET https://t', risk: 'medium', rationale: 'crawl and probe', proposedAt: '', decisionState: 'pending', decidedBy: '', decisionReason: '' }
const SCAN_RUN = { id: 'scan-1', kind: 'authenticated_scan', engagementId: 'eng-1', actionId: 'act-1', actor: 'ana', status: 'queued', evidenceId: '', errorCode: '', startedAt: '', finishedAt: '', result: null }
const SCAN_RESULT = { digest: 'abc123def456', incomplete: false, reason: '', requestCount: 5, coverageCount: 3, proofs: [{ checkId: 'xss.reflected', version: 2, normalizedEndpoint: 'GET /q', hash: 'deadbeefdeadbeef00' }] }
const SESSION = { scheme: 'bearer', credentials: [{ name: 'token', reference: 'vault://engagement/token', field: 'token' }], login_request: { method: 'GET', path: '/' }, success: { status_code: 200 }, check_request: { method: 'GET', path: '/' } }

function renderTab() {
  return render(<ToastProvider><DASTTab engagementId="eng-1" /></ToastProvider>)
}

describe('DASTTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.judgments).mockResolvedValue([] as never)
  })

  async function launchScan() {
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'admin' } as never)
    vi.mocked(api.proposeDastScan).mockResolvedValue(PROPOSAL_PENDING as never)
    vi.mocked(api.decideDastApproval).mockResolvedValue({ actionId: 'act-1', state: 'approved', decidedBy: 'Ana', reason: 'scoped', decidedAt: '' } as never)
    vi.mocked(api.runDastScan).mockResolvedValue(SCAN_RUN as never)
    const view = renderTab()
    fireEvent.change(await screen.findByLabelText('DAST target URL'), { target: { value: 'https://staging.example' } })
    fireEvent.change(screen.getByLabelText('Session configuration JSON'), { target: { value: JSON.stringify(SESSION) } })
    fireEvent.click(screen.getByRole('button', { name: /Propose scan/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }))
    fireEvent.click(await screen.findByRole('button', { name: /Run scan/ }))
    return view
  }

  it('requires valid session JSON and submits vault references, invalidating the proposal on edit', async () => {
    vi.mocked(api.me).mockResolvedValue({ id: 'u1', name: 'Ana', role: 'admin' } as never)
    vi.mocked(api.proposeDastScan).mockResolvedValue(PROPOSAL_PENDING as never)
    renderTab()
    fireEvent.change(await screen.findByLabelText('DAST target URL'), { target: { value: 'https://staging.example' } })
    const propose = await screen.findByRole('button', { name: /Propose scan/ })
    await waitFor(() => expect(propose).toBeEnabled())
    fireEvent.click(propose)
    expect(screen.getByText(/Enter a valid session configuration JSON/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Session configuration JSON'), { target: { value: '{invalid' } })
    fireEvent.click(propose)
    expect(api.proposeDastScan).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Session configuration JSON'), { target: { value: JSON.stringify(SESSION) } })
    fireEvent.click(propose)
    expect(await screen.findByText('approval act-1')).toBeInTheDocument()
    expect(api.proposeDastScan).toHaveBeenCalledWith('eng-1', expect.objectContaining({ session: SESSION }))
    fireEvent.change(screen.getByLabelText('Max pages'), { target: { value: '10' } })
    expect(screen.queryByText('approval act-1')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Run scan/ })).not.toBeInTheDocument()
  })

  it('shows queued and running without a result, then displays the completed proofs', async () => {
    let running!: (value: never) => void
    let completed!: (value: never) => void
    vi.mocked(api.getDastScanRun)
      .mockImplementationOnce(() => new Promise((resolve) => { running = resolve }))
      .mockImplementationOnce(() => new Promise((resolve) => { completed = resolve }))
    await launchScan()
    expect(await screen.findByText('queued')).toBeInTheDocument()
    expect(screen.queryByText('Scan result')).not.toBeInTheDocument()
    await waitFor(() => expect(running).toBeTypeOf('function'))
    await act(async () => { running({ ...SCAN_RUN, status: 'running' } as never) })
    expect(screen.getByText('running')).toBeInTheDocument()
    expect(screen.queryByText('Scan result')).not.toBeInTheDocument()
    await waitFor(() => expect(completed).toBeTypeOf('function'), { timeout: 3000 })
    await act(async () => { completed({ ...SCAN_RUN, status: 'succeeded', result: SCAN_RESULT } as never) })
    expect(screen.getByText('xss.reflected')).toBeInTheDocument()
    expect(screen.getByText('Scan result')).toBeInTheDocument()
  })

  it('retains proofs while identifying incomplete coverage', async () => {
    vi.mocked(api.getDastScanRun).mockResolvedValue({ ...SCAN_RUN, status: 'incomplete', result: { ...SCAN_RESULT, incomplete: true, reason: 'page limit' } } as never)
    await launchScan()
    expect(await screen.findByText('incomplete: page limit')).toBeInTheDocument()
    expect(screen.getByText('xss.reflected')).toBeInTheDocument()
    expect(screen.queryByText('Scan complete.')).not.toBeInTheDocument()
  })

  it('shows a failed run without a clean result', async () => {
    vi.mocked(api.getDastScanRun).mockResolvedValue({ ...SCAN_RUN, status: 'failed', errorCode: 'worker_lost' } as never)
    await launchScan()
    expect(await screen.findByText('Scan failed: worker_lost')).toBeInTheDocument()
    expect(screen.queryByText('Scan result')).not.toBeInTheDocument()
    expect(screen.queryByText('Scan complete.')).not.toBeInTheDocument()
  })

  it('reports an interrupted status read and allows the operator to retry', async () => {
    vi.mocked(api.getDastScanRun)
      .mockRejectedValueOnce(new Error('Connection interrupted'))
      .mockResolvedValueOnce({ ...SCAN_RUN, status: 'succeeded', result: SCAN_RESULT } as never)
    await launchScan()
    expect(await screen.findByText('Connection interrupted')).toBeInTheDocument()
    expect(screen.queryByText('Scan result')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry scan status' }))
    expect(await screen.findByText('xss.reflected')).toBeInTheDocument()
  })

  it('ignores a scan result from the previous engagement', async () => {
    let complete!: (value: never) => void
    vi.mocked(api.getDastScanRun).mockImplementation(() => new Promise((resolve) => { complete = resolve }))
    const view = await launchScan()
    await waitFor(() => expect(complete).toBeTypeOf('function'))
    view.rerender(<ToastProvider><DASTTab engagementId="eng-other" /></ToastProvider>)
    await act(async () => { complete({ ...SCAN_RUN, status: 'succeeded', result: SCAN_RESULT } as never) })
    expect(screen.queryByText('xss.reflected')).not.toBeInTheDocument()
    expect(screen.queryByText('run scan-1')).not.toBeInTheDocument()
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
