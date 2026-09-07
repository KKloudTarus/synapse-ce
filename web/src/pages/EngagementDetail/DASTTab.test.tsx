import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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
})
