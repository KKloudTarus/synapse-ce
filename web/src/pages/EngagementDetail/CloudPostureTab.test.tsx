import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/synapse/Toast'
import { api } from '../../lib/api'
import type { CSPMRun } from '../../lib/api'
import { CloudPostureTab } from './CloudPostureTab'

vi.mock('../../lib/api', () => ({
  api: { runCSPM: vi.fn(), getCSPMRun: vi.fn() },
}))

function succeededRun(): CSPMRun {
  return {
    id: 'cspm-run-1',
    engagementId: 'eng-001',
    actor: 'you',
    status: 'succeeded',
    complete: true,
    assets: 214,
    findings: 9,
    coverageIssues: [{ scope: 'aws:1', reason: 'x' }],
    errorCode: '',
    evidenceRefs: [{ scopeKey: 'aws:1', id: 'ev-1', hash: 'sha256:abcd' }],
    startedAt: '2026-09-01T00:00:00Z',
    finishedAt: '2026-09-01T00:05:00Z',
  }
}

function renderTab() {
  render(
    <MemoryRouter>
      <ToastProvider>
        <CloudPostureTab engagementId="eng-001" />
      </ToastProvider>
    </MemoryRouter>,
  )
}

describe('CloudPostureTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('requires a root and credential reference before running', async () => {
    renderTab()
    expect(screen.getByRole('button', { name: /run posture scan/i })).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Target 1 root'), { target: { value: '123456789012' } })
    fireEvent.change(screen.getByLabelText('Target 1 credential reference'), { target: { value: 'vault://aws-ro' } })
    await waitFor(() => expect(screen.getByRole('button', { name: /run posture scan/i })).toBeEnabled())
  })

  it('starts a run and renders its status', async () => {
    vi.mocked(api.runCSPM).mockResolvedValue(succeededRun())
    renderTab()

    fireEvent.change(screen.getByLabelText('Target 1 root'), { target: { value: '123456789012' } })
    fireEvent.change(screen.getByLabelText('Target 1 credential reference'), { target: { value: 'vault://aws-ro' } })
    fireEvent.click(screen.getByRole('button', { name: /run posture scan/i }))

    await waitFor(() =>
      expect(api.runCSPM).toHaveBeenCalledWith('eng-001', [
        { provider: 'aws', root: '123456789012', credentialRef: 'vault://aws-ro' },
      ]),
    )
    expect(await screen.findByText('succeeded')).toBeInTheDocument()
    expect(screen.getByText('214')).toBeInTheDocument()
  })
})
