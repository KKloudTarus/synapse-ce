import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { PurpleCoverageRow } from '../../lib/api'
import { ToastProvider } from '../../components/synapse/Toast'
import { PurpleCoverageTab } from './PurpleCoverageTab'

vi.mock('../../lib/api', () => ({
  api: {
    purpleCoverage: vi.fn(),
    purpleWorkItems: vi.fn(),
    listTechnicalAssets: vi.fn().mockResolvedValue([]),
    runEmulation: vi.fn(),
  },
}))

function row(runId: string, technique: string, verdict: PurpleCoverageRow['verdict'], at: string): PurpleCoverageRow {
  return { runId, assetId: 'a1', techniqueId: technique, taxonomyRef: `attack:${technique}`, expected: 'det', actual: [], verdict, computedAt: at }
}

describe('PurpleCoverageTab', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.listTechnicalAssets).mockResolvedValue([])
  })

  it('summarizes the latest run and lists its detection gaps', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([
      row('emu-feb', 'T1059.001', 'covered', '2026-02-20T00:00:00Z'),
      row('emu-feb', 'T1053.005', 'gap', '2026-02-20T00:00:00Z'),
      row('emu-feb', 'T1021.001', 'unknown', '2026-02-20T00:00:00Z'),
      row('emu-jan', 'T1059.001', 'gap', '2026-01-20T00:00:00Z'),
    ])
    vi.mocked(api.purpleWorkItems).mockResolvedValue([
      { techniqueId: 'T1053.005', taxonomyRef: 'attack:T1053.005', missingDetection: 'det-schtask' },
    ])

    render(<ToastProvider><PurpleCoverageTab engagementId="eng-001" /></ToastProvider>)

    // covered=1, gap=1 over the latest run => 1/(1+1) = 50% (shown in the summary and the run row).
    expect((await screen.findAllByText('50%')).length).toBeGreaterThan(0)
    // The latest run (emu-feb) is auto-selected, so its gap work items load.
    await waitFor(() => expect(api.purpleWorkItems).toHaveBeenCalledWith('eng-001', 'emu-feb'))
    expect(await screen.findByText('T1053.005')).toBeInTheDocument()
    expect(screen.getByText(/write detection: det-schtask/)).toBeInTheDocument()
  })

  it('shows an empty state when no emulation has run', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([])
    render(<ToastProvider><PurpleCoverageTab engagementId="eng-001" /></ToastProvider>)
    expect(await screen.findByText('No purple-team coverage yet')).toBeInTheDocument()
    expect(api.purpleWorkItems).not.toHaveBeenCalled()
    // The run-emulation control is offered even before any coverage exists.
    expect(screen.getByRole('button', { name: /run emulation/i })).toBeInTheDocument()
  })

  it('offers the run-emulation control but keeps Run disabled until a target is chosen', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([])
    vi.mocked(api.listTechnicalAssets).mockResolvedValue([
      { id: 'asset-1', kind: 'host', key: 'web-01', name: 'web-01', attributes: {} },
    ])
    render(<ToastProvider><PurpleCoverageTab engagementId="eng-001" /></ToastProvider>)
    // The Run button is present and disabled with no target selected, so an emulation cannot start blindly.
    const btn = await screen.findByRole('button', { name: /run emulation/i })
    expect(btn).toBeDisabled()
    expect(api.runEmulation).not.toHaveBeenCalled()
  })
})
