import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { CoverageWindow } from '../../lib/api'
import { CoverageWindows } from './CoverageWindows'

vi.mock('../../lib/api', () => ({
  api: { listCoverageWindows: vi.fn() },
}))

function windowFixture(over: Partial<CoverageWindow> = {}): CoverageWindow {
  return {
    assetId: 'ba-001',
    agentId: 'agent-001',
    hostId: 'host-web-01',
    since: '2026-09-01T00:00:00Z',
    until: '2026-09-02T00:00:00Z',
    inputDigest: 'sha256:9f1c0a44e7b2',
    revision: 'rev-0042',
    createdAt: '2026-09-02T00:00:00Z',
    states: [
      { class: 'network', hostId: 'host-web-01', agentId: 'agent-001', state: 'blind', reason: 'ebpf load failed', since: '2026-09-01T12:00:00Z' },
    ],
    sampledCount: 18420,
    truncatedCount: 12,
    droppedCount: 3,
    gapCount: 2,
    batchCount: 96,
    coverage: { process: 1, network: 0, file: 1, privilege: 1, reasons: ['network class blind'] },
    ...over,
  }
}

describe('CoverageWindows', () => {
  beforeEach(() => vi.resetAllMocks())

  it('renders sealed windows with their gap count and a blind class state', async () => {
    vi.mocked(api.listCoverageWindows).mockResolvedValue([windowFixture()])
    render(<CoverageWindows />)

    expect(await screen.findByText(/2 gaps/)).toBeInTheDocument()
    expect(screen.getByText('rev-0042')).toBeInTheDocument()
    expect(screen.getByText('blind')).toBeInTheDocument()
    expect(screen.getByText(/network class blind/)).toBeInTheDocument()
  })

  it('shows an empty state when no windows match', async () => {
    vi.mocked(api.listCoverageWindows).mockResolvedValue([])
    render(<CoverageWindows />)
    expect(await screen.findByText('No coverage windows')).toBeInTheDocument()
  })
})
