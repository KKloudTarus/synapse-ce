import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { VulnerabilityAction, VulnerabilityOccurrence } from '../../lib/types'
import { VulnPostureTab } from './VulnPostureTab'

vi.mock('../../lib/api', () => ({
  api: {
    engagementVulnerabilityActions: vi.fn(),
    engagementVulnerabilityOccurrences: vi.fn(),
    acknowledgeVulnerabilityAction: vi.fn(),
    resolveVulnerabilityAction: vi.fn(),
  },
}))

function action(id: string, status: string, title: string): VulnerabilityAction {
  return { id, engagementId: 'eng-001', occurrenceId: 'occ-1', findingId: 'f-1', type: 'remediate', status, title, reasonCodes: ['reachable'], createdAt: '', updatedAt: '' }
}

function occ(id: string, advisory: string, pkg: string): VulnerabilityOccurrence {
  return {
    id, engagementId: 'eng-001', advisoryId: advisory, advisoryRevision: 1, componentId: 'c1', componentFingerprint: `pkg:npm/${pkg}`, ecosystem: 'npm',
    packageName: pkg, componentVersion: '4.17.20', componentCpe: '', fixedVersion: '4.17.21', matchMethod: '', confidence: '', scope: '', reachability: 'reachable',
    state: 'open', firstDetectedAt: '', lastDetectedAt: '', lastEvaluatedAt: '', updatedAt: '',
  }
}

describe('VulnPostureTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows the action queue and resolves an action in place', async () => {
    vi.mocked(api.engagementVulnerabilityActions).mockResolvedValue([action('act-1', 'open', 'Upgrade lodash to 4.17.21')])
    vi.mocked(api.engagementVulnerabilityOccurrences).mockResolvedValue([occ('occ-1', 'CVE-2021-23337', 'lodash')])
    vi.mocked(api.resolveVulnerabilityAction).mockResolvedValue(action('act-1', 'resolved', 'Upgrade lodash to 4.17.21'))

    render(<VulnPostureTab engagementId="eng-001" />)

    expect(await screen.findByText('Upgrade lodash to 4.17.21')).toBeInTheDocument()
    expect(screen.getByText('CVE-2021-23337')).toBeInTheDocument()
    expect(screen.getByText('1 open')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    await waitFor(() => expect(api.resolveVulnerabilityAction).toHaveBeenCalledWith('eng-001', 'act-1'))
    // After resolving, the open counter drops and the Resolve button disappears for that row.
    expect(await screen.findByText('0 open')).toBeInTheDocument()
  })

  it('shows an empty state when nothing is reconciled', async () => {
    vi.mocked(api.engagementVulnerabilityActions).mockResolvedValue([])
    vi.mocked(api.engagementVulnerabilityOccurrences).mockResolvedValue([])
    render(<VulnPostureTab engagementId="eng-001" />)
    expect(await screen.findByText('No reconciled vulnerabilities yet')).toBeInTheDocument()
  })
})
