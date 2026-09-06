import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { ScanRun } from '../../lib/types'
import { ScanRunsTab } from './ScanRunsTab'

vi.mock('../../lib/api', () => ({
  api: {
    scanRuns: vi.fn(),
    compareScanRuns: vi.fn(),
  },
}))

function run(id: string, createdAt: string, repro: number, keys: string[], grypeDB = 'v5@2026-02-20'): ScanRun {
  return {
    id,
    engagementId: 'eng-001',
    createdAt,
    manifest: {
      toolVersions: { syft: '1.18.1' },
      vulnDBSnapshot: 'osv.dev@2026-02-20',
      grypeDBVersion: grypeDB,
      correlationVersion: 7,
      sbomSha256: 'abc',
      reproScore: repro,
      pinnedInputs: ['syft', 'grype'],
      unpinnedInputs: ['osv.dev'],
    },
    findingKeys: keys,
  }
}

describe('ScanRunsTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists runs newest-first and compares two selected runs', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([
      run('run-jan', '2026-01-20T00:00:00Z', 82, ['k1', 'k2']),
      run('run-feb', '2026-02-20T00:00:00Z', 82, ['k1', 'k2', 'k3']),
    ])
    vi.mocked(api.compareScanRuns).mockResolvedValue({
      runA: run('run-feb', '2026-02-20T00:00:00Z', 82, ['k1', 'k2', 'k3']),
      runB: run('run-jan', '2026-01-20T00:00:00Z', 82, ['k1', 'k2']),
      added: [],
      removed: ['k3'],
      unchanged: 2,
      explanation: ['grype-db changed: "v5@2026-02-20" -> "v5@2026-01-20"'],
    })

    render(<ScanRunsTab engagementId="eng-001" />)

    // Both runs render; the reproducibility score is surfaced.
    expect(await screen.findByText(/run-feb/)).toBeInTheDocument()
    expect(screen.getByText(/run-jan/)).toBeInTheDocument()
    expect(screen.getByText('Select two runs to compare')).toBeInTheDocument()

    const rows = screen.getAllByRole('button', { pressed: false })
    await userEvent.click(rows[0])
    await userEvent.click(rows[1])

    const compareBtn = await screen.findByRole('button', { name: /Compare A and B/ })
    await userEvent.click(compareBtn)

    await waitFor(() => expect(api.compareScanRuns).toHaveBeenCalledWith('eng-001', 'run-feb', 'run-jan'))
    expect(await screen.findByText('1 removed')).toBeInTheDocument()
    expect(screen.getByText('2 unchanged')).toBeInTheDocument()
    expect(screen.getByText(/grype-db changed/)).toBeInTheDocument()
  })

  it('shows an empty state when there is no scan history', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([])
    render(<ScanRunsTab engagementId="eng-001" />)
    expect(await screen.findByText('No scan runs yet')).toBeInTheDocument()
  })
})
