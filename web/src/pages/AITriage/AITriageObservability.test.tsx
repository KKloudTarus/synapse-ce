import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { AITriageObservability as Observability } from '../../lib/types'
import { AITriageObservability } from './AITriageObservability'

vi.mock('../../lib/api', () => ({
  ApiError: class ApiError extends Error { constructor(public status: number, message: string) { super(message) } },
  api: { aiTriageObservability: vi.fn() },
}))

const row = {
  value: 'all', requestCount: 4, averageLatencyMillis: 25, timeoutCount: 0, parseFailureCount: 1,
  providerFailureCount: 0, circuitOpenCount: 0, totalTokens: 1200, estimatedCostMicroUSD: 2500,
  comparisons: 2, disagreements: 1, gateExemptions: 1, findings: 4,
}

const dashboard: Observability = {
  generatedAt: '2026-08-12T00:00:00Z', totals: row,
  byModel: [{ ...row, value: 'provider/model (proposer)' }],
  byPromptVersion: [{ ...row, value: 'fp-triage-v2' }],
  byCWE: [{ ...row, value: 'CWE-89' }],
  byProject: [{ ...row, value: 'p1 · Checkout' }],
  distribution: {
    schemaVersion: 'synapse-ai-triage-distribution-v1', sampleSize: 4,
    languageBasisPoints: { go: 7500, typescript: 2500 },
    cweBasisPoints: { 'CWE-89': 10000 }, projectBasisPoints: { p1: 10000 },
  },
  alerts: [{ projectId: 'p1', projectName: 'Checkout', alert: { metric: 'parse_failure_rate', observedBasisPoints: 2500, baselineBasisPoints: 200, deviationBasisPoints: 2300, sampleSize: 4, message: 'Parse failures exceeded baseline' } }],
}

describe('AITriageObservability', () => {
  beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.aiTriageObservability).mockResolvedValue(dashboard) })

  it('shows safety totals, all required dimensions, and persisted alerts', async () => {
    render(<AITriageObservability />)
    expect(await screen.findByText(/Observability/i)).toBeInTheDocument()
    expect(screen.getByText('50.0%')).toBeInTheDocument()
    expect(screen.getByText('provider/model (proposer)')).toBeInTheDocument()
    expect(screen.getByText('fp-triage-v2')).toBeInTheDocument()
    expect(screen.getAllByText('CWE-89')).toHaveLength(2)
    expect(screen.getByText('p1 · Checkout')).toBeInTheDocument()
    expect(screen.getByText('Parse failures exceeded baseline')).toBeInTheDocument()
    expect(screen.getByText('Drift input distribution')).toBeInTheDocument()
    expect(screen.getByText('75.0%')).toBeInTheDocument()
  })
})
