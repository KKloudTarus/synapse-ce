import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../lib/api'
import type { AITriageReview } from '../../lib/types'
import { AITriageReviews } from './AITriageReviews'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error { constructor(public status: number, message: string) { super(message) } },
  api: { aiTriageReviews: vi.fn(), decideAITriageReview: vi.fn(), claimAITriageReview: vi.fn(), listProjects: vi.fn(), me: vi.fn() },
}))

const review: AITriageReview = {
  id: 'r1', tenantId: 'default', engagementId: 'e1', projectId: 'p1', findingId: 'f1', dedupKey: 'sast:key',
  title: 'SQL injection', severity: 'high', cwe: 'CWE-89', owner: 'reviewer', state: 'pending', verdict: 'refuted',
  driver: 'sanitizer', confidence: 91, suspectedFP: true, proposerModel: 'model-a', proposerProvider: 'openai', proposerModelFamily: 'model-a',
  verifierModel: 'model-b', verifierProvider: 'anthropic', verifierModelFamily: 'model-b', independencePolicy: 'provider',
  promptVersion: 'fp-triage-v2', shadow: false, wouldGateExempt: false,
  verified: true, verifierVerdict: 'refuted', verifierDriver: 'sanitizer', verifierConfidence: 90,
  policyVersion: 'fp-gate-v4', policyReason: 'severity_requires_human', gateExempt: false, reviewRequired: true,
  evidenceRef: 'ev1', decidedBy: '', decisionRationale: '', createdAt: '2026-08-09T00:00:00Z',
  updatedAt: '2026-08-09T00:00:00Z', decidedAt: null, version: 1,
}

function renderPage() { return render(<MemoryRouter><AITriageReviews /></MemoryRouter>) }

describe('AITriageReviews', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.aiTriageReviews).mockResolvedValue([review])
    vi.mocked(api.listProjects).mockResolvedValue([{ id: 'p1', name: 'Synapse', key: 'synapse' } as any])
    vi.mocked(api.me).mockResolvedValue({ id: 'reviewer', name: 'Reviewer', role: 'reviewer' })
    vi.mocked(api.decideAITriageReview).mockResolvedValue({ ...review, state: 'rejected', decidedBy: 'reviewer', version: 2 })
    vi.mocked(api.claimAITriageReview).mockResolvedValue({ ...review, owner: 'reviewer', version: 2 })
  })

  it('shows model, policy, evidence, and all applicable triage badges', async () => {
    renderPage()
    expect(await screen.findByText('SQL injection')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /SQL injection/i }))
    expect(screen.getByText(/openai \/ model-a · refuted · 91%/)).toBeInTheDocument()
    expect(screen.getByText('fp-gate-v4')).toBeInTheDocument()
    expect(screen.getByText('provider')).toBeInTheDocument()
    expect(screen.getByText('ev1')).toBeInTheDocument()
    expect(screen.getAllByText('Suspected FP').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Verified').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Review required').length).toBeGreaterThan(0)
  })

  it('requires rationale and sends a rejection back to the gate workflow', async () => {
    renderPage(); await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: /SQL injection/i }))
    const reject = screen.getByRole('button', { name: /Reject & gate/i })
    expect(reject).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Why should the AI recommendation/), { target: { value: 'The source reaches the sink' } })
    fireEvent.click(reject)
    await waitFor(() => expect(api.decideAITriageReview).toHaveBeenCalledWith('r1', 'reject', 'The source reaches the sink', 1))
  })

  it('does not allow an authorized reviewer to take over another owner', async () => {
    vi.mocked(api.aiTriageReviews).mockResolvedValue([{ ...review, owner: 'alice' }])
    renderPage(); await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: /SQL injection/i }))
    expect(screen.queryByRole('button', { name: /Claim review/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Accept FP/i })).toBeDisabled()
  })
})
