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

describe('AITriageObservability CWE bars', () => {
  // The rows arrive ordered by CWE identifier, not by volume. Taking the denominator from the
  // first row made it whichever CWE sorted first, so a later row with more requests was drawn
  // wider than its own track and ran off the side of the card: with CWE-611 at 2 requests ahead of
  // CWE-776 at 14, that bar was 700% wide.
  it('scales every bar against the largest count, not the first row', async () => {
    vi.mocked(api.aiTriageObservability).mockResolvedValue({
      ...dashboard,
      byCWE: [
        { ...row, value: 'CWE-611', requestCount: 2 },
        { ...row, value: 'CWE-776', requestCount: 14 },
        { ...row, value: 'CWE-915', requestCount: 4 },
      ],
    })
    render(<AITriageObservability />)

    const smallest = await screen.findByText('CWE-611')
    const section = smallest.closest('div.min-w-0')?.parentElement as HTMLElement
    const widths = Array.from(section.querySelectorAll<HTMLElement>('div.bg-brand-solid')).map(
      (bar) => Number.parseFloat(bar.style.width),
    )

    expect(widths).toHaveLength(3)
    for (const width of widths) {
      expect(width).toBeLessThanOrEqual(100)
    }
    // Largest is the full track; the others are its honest proportion.
    expect(Math.max(...widths)).toBe(100)
    expect(widths[0]).toBeCloseTo((2 / 14) * 100, 5)
    expect(widths[2]).toBeCloseTo((4 / 14) * 100, 5)
  })
})
