import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { PurpleCoverageRow } from '../../lib/api'
import type { Engagement } from '../../lib/types'
import { PurpleCoverageTab } from './PurpleCoverageTab'

vi.mock('../../lib/api', () => ({
  api: {
    purpleCoverage: vi.fn(),
    purpleWorkItems: vi.fn(),
    runEmulation: vi.fn(),
  },
}))

function row(runId: string, technique: string, verdict: PurpleCoverageRow['verdict'], at: string): PurpleCoverageRow {
  return { runId, assetId: 'a1', techniqueId: technique, taxonomyRef: `attack:${technique}`, expected: 'det', actual: [], verdict, computedAt: at }
}

function engagement(overrides: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-001',
    name: 'Acme',
    client: 'Acme',
    status: 'active',
    inScope: [{ kind: 'domain', value: 'app.example.test' }],
    outOfScope: [],
    authorizedFrom: null,
    authorizedTo: null,
    roe: {
      allowedToolClasses: [],
      blackouts: [],
      offensive: {
        customerContact: 'ciso@acme.example',
        emergencyContact: '+1-555-0100',
        riskCeiling: 'high',
        excludedAssets: [],
        exclusionsReviewed: true,
        complete: true,
      },
    },
    liveReconEnabled: false,
    createdAt: null,
    businessAssetId: 'asset-9',
    ...overrides,
  }
}

describe('PurpleCoverageTab', () => {
  beforeEach(() => vi.resetAllMocks())

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

    render(<PurpleCoverageTab engagementId="eng-001" />)

    // covered=1, gap=1 over the latest run => 1/(1+1) = 50% (shown in the summary and the run row).
    expect((await screen.findAllByText('50%')).length).toBeGreaterThan(0)
    // The latest run (emu-feb) is auto-selected, so its gap work items load.
    await waitFor(() => expect(api.purpleWorkItems).toHaveBeenCalledWith('eng-001', 'emu-feb'))
    expect(await screen.findByText('T1053.005')).toBeInTheDocument()
    expect(screen.getByText(/write detection: det-schtask/)).toBeInTheDocument()
  })

  it('shows an empty state when no emulation has run', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([])
    render(<PurpleCoverageTab engagementId="eng-001" />)
    expect(await screen.findByText('No purple-team coverage yet')).toBeInTheDocument()
    expect(api.purpleWorkItems).not.toHaveBeenCalled()
  })

  it('runs an emulation and reloads coverage when the offensive RoE is complete', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([])
    vi.mocked(api.runEmulation).mockResolvedValue({
      runId: 'emu-new',
      engagementId: 'eng-001',
      target: 'app.example.test',
      techniques: 5,
      executed: 4,
      gaps: 4,
      covered: 0,
    })
    render(<PurpleCoverageTab engagementId="eng-001" eng={engagement()} />)

    const run = await screen.findByRole('button', { name: /run emulation/i })
    expect(run).toBeEnabled()
    await userEvent.click(run)

    await waitFor(() => expect(api.runEmulation).toHaveBeenCalledWith('eng-001', 'app.example.test'))
    // onRan triggers a coverage refetch (initial load + reload = 2 calls).
    await waitFor(() => expect(api.purpleCoverage).toHaveBeenCalledTimes(2))
  })

  it('gates the run when the offensive RoE is incomplete', async () => {
    vi.mocked(api.purpleCoverage).mockResolvedValue([])
    const eng = engagement()
    eng.roe.offensive!.complete = false
    render(<PurpleCoverageTab engagementId="eng-001" eng={eng} />)

    expect(await screen.findByText(/offensive roe incomplete/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run emulation/i })).toBeDisabled()
  })
})
