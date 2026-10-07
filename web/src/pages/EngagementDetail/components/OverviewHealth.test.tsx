import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { ScanJob, ScanResult } from '../../../lib/types'
import { ScanHealth } from './OverviewHealth'

const scan: ScanResult = {
  target: 'repo', scanMode: 'full', languages: [], components: [], dependencies: [], vulnerabilities: [], licenses: [], findings: [], toolVersions: {}, vulnDBSnapshot: '', debugEvents: [],
  completeness: { lockfiles: [], componentsTotal: 0, componentsResolved: 0, confident: true, warning: '' },
  licenseCoverage: { total: 0, detected: 0, unknown: 0, pct: 0 },
  manifest: { toolVersions: {}, vulnDBSnapshot: '', grypeDBVersion: '', correlationVersion: 0, sbomSha256: '', reproScore: 0, pinnedInputs: [], unpinnedInputs: [] },
  findingQuality: { rawFindings: 0, actionable: 0, background: 0, production: 0, development: 0, exampleTest: 0, thirdParty: 0, firstPartyHistorical: 0, versionCoveragePct: 0, pathCoveragePct: 0, confidence: '', byPriority: {} },
}

describe('ScanHealth', () => {
  it('distinguishes a finished worker from partial required-engine coverage', () => {
    const job: ScanJob = {
      id: 'job', engagementId: 'eng', target: 'repo', kind: 'repository', status: 'succeeded', stage: 'done', progress: 100, error: '', startedAt: null, finishedAt: null, debugEvents: [],
      engineCoverage: { status: 'partial', required: 3, completed: 2 },
    }
    render(<ScanHealth scan={{ ...scan, engineCoverage: { status: 'complete', required: 3, completed: 3 } }} job={job} />)
    expect(screen.getByText('Finished')).toBeInTheDocument()
    expect(screen.getByText('partial')).toBeInTheDocument()
    expect(screen.getByText('Dependencies')).toBeInTheDocument()
  })

  it('reports unknown coverage when historical metadata is absent', () => {
    render(<ScanHealth scan={scan} job={null} />)
    expect(screen.getByText('unknown')).toBeInTheDocument()
  })
})
