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
    provenance: 'native',
    terminalStatus: 'succeeded',
    sealedAt: createdAt,
    manifestHash: 'manifest-hash',
    laneCount: 1,
    completeCoverage: true,
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

  it('renders each run immutable archive without replacing old evidence with the newest source', async () => {
    const first = run('run-first', '2026-09-01T00:00:00Z', 100, ['first'])
    const second = run('run-second', '2026-09-08T00:00:00Z', 100, ['second'])
    first.sourcePackage = { versionId: 'source-v1', filename: 'original.zip', size: 1024, sha256: 'a'.repeat(64), target: '', uploadedBy: 'alice', uploadedAt: '2026-09-01T00:00:00Z' }
    second.sourcePackage = { versionId: 'source-v2', filename: 'updated.zip', size: 2048, sha256: 'b'.repeat(64), target: '', uploadedBy: 'bob', uploadedAt: '2026-09-08T00:00:00Z' }
    vi.mocked(api.scanRuns).mockResolvedValue([first, second])
    render(<ScanRunsTab engagementId="eng-001" />)
    expect(await screen.findByText('original.zip')).toBeVisible()
    expect(screen.getByText('updated.zip')).toBeVisible()
    expect(screen.getByLabelText(`Source SHA-256 ${'a'.repeat(64)}`)).toBeVisible()
    expect(screen.getByLabelText(`Source SHA-256 ${'b'.repeat(64)}`)).toBeVisible()
    expect(screen.getByText(/Uploaded by alice/)).toBeVisible()
    expect(screen.getByText(/Uploaded by bob/)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Scan run run-first' })).toHaveTextContent('original.zip')
    expect(screen.getByRole('button', { name: 'Scan run run-first' })).not.toHaveTextContent('updated.zip')
  })

  it('labels legacy missing source metadata neutrally and keeps non-upload target kinds', async () => {
    vi.mocked(api.scanRuns).mockResolvedValue([
      { ...run('legacy', '2026-09-01T00:00:00Z', 0, []), provenance: 'legacy' },
      { ...run('git-run', '2026-09-02T00:00:00Z', 100, []), targetKind: 'git', target: 'https://example.test/repo' },
      { ...run('image-run', '2026-09-03T00:00:00Z', 100, []), targetKind: 'image', target: 'example/image@sha256:abc' },
    ])
    render(<ScanRunsTab engagementId="eng-001" />)
    expect(await screen.findByText('Source metadata unavailable')).toBeVisible()
    expect(screen.getByText('git target · https://example.test/repo')).toBeVisible()
    expect(screen.getByText('image target · example/image@sha256:abc')).toBeVisible()
  })
})
