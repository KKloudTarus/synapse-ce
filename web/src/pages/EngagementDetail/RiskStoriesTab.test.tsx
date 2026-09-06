import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { RiskStory } from '../../lib/api'
import { RiskStoriesTab } from './RiskStoriesTab'

vi.mock('../../lib/api', () => ({
  api: { riskStories: vi.fn() },
}))

function story(id: string, name: string, score: number, findings: RiskStory['findings']): RiskStory {
  return {
    assetId: id,
    identity: { kind: 'host', key: name, name: `${name}.prod` },
    exposure: [],
    findings,
    paths: [],
    detections: [],
    score,
    qualifiers: [],
    generatedAt: '2026-02-20T00:00:00Z',
  }
}

describe('RiskStoriesTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('ranks assets by score and surfaces corroboration on findings', async () => {
    vi.mocked(api.riskStories).mockResolvedValue([
      story('db-01', 'db-01', 0, []),
      story('web-01', 'web-01', 1, [
        {
          findingId: 'f-1',
          title: 'lodash prototype pollution',
          severity: 'high',
          priority: 1,
          riskScore: 8.4,
          kev: false,
          reachability: 'reachable',
          reachable: true,
          onAttackPath: true,
          seenUnderAttack: false,
          corroboration: ['reachable', 'on_attack_path'],
          rankReason: 'raised by corroboration',
          lastObserved: '2026-02-13T00:00:00Z',
          stale: false,
        },
      ]),
    ])

    render(<RiskStoriesTab engagementId="eng-001" />)

    expect(await screen.findByText('web-01.prod')).toBeInTheDocument()
    expect(screen.getByText('db-01.prod')).toBeInTheDocument()
    expect(screen.getByText('lodash prototype pollution')).toBeInTheDocument()
    // Corroboration signals surface as badges.
    expect(screen.getByText('reachable')).toBeInTheDocument()
    expect(screen.getByText('on attack path')).toBeInTheDocument()
    // The asset with no findings says so rather than rendering an empty list.
    expect(screen.getByText('No findings correlated to this asset.')).toBeInTheDocument()
  })

  it('shows an empty state when no stories correlate', async () => {
    vi.mocked(api.riskStories).mockResolvedValue([])
    render(<RiskStoriesTab engagementId="eng-001" />)
    expect(await screen.findByText('No correlated risk stories yet')).toBeInTheDocument()
  })
})
