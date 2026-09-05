import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import type { Engagement } from '../../../lib/types'
import { EngagementTable } from './EngagementTable'

function engagement(overrides: Partial<Engagement> = {}): Engagement {
  return {
    id: 'eng-1234567890abcdef',
    name: 'Review NodeGoat',
    client: 'Review',
    status: 'draft',
    inScope: [{ kind: 'repo', value: 'https://github.com/OWASP/NodeGoat' }],
    outOfScope: [],
    authorizedFrom: null,
    authorizedTo: null,
    roe: { allowedToolClasses: [], blackouts: [] },
    liveReconEnabled: false,
    createdAt: new Date(Date.now() - 5 * 60_000).toISOString(),
    businessAssetId: '',
    ...overrides,
  }
}

function renderTable(engagements: Engagement[]) {
  render(
    <MemoryRouter>
      <EngagementTable
        engagements={engagements}
        assetNames={{}}
        sortField="lastScanDate"
        sortDirection="desc"
        onSort={vi.fn()}
        page={1}
        pageSize={20}
        totalItems={engagements.length}
        onPageChange={vi.fn()}
        onPageSizeChange={vi.fn()}
      />
    </MemoryRouter>,
  )
  return within(screen.getAllByRole('row')[1])
}

describe('EngagementTable honest columns', () => {
  it('does not claim zero findings when the list endpoint reports no count', () => {
    const row = renderTable([engagement()])

    expect(row.getByLabelText('Findings count not reported by the list endpoint')).toBeInTheDocument()
    expect(row.queryByText('0')).not.toBeInTheDocument()
  })

  it('shows the count when the endpoint does report one', () => {
    const row = renderTable([
      engagement({ findingsCount: { total: 446, critical: 3, high: 40, medium: 200, low: 203 } }),
    ])

    expect(row.getByText('446')).toBeInTheDocument()
    expect(row.queryByLabelText(/not reported by the list endpoint/)).not.toBeInTheDocument()
  })

  it('says not scanned instead of showing the creation time as a scan', () => {
    const row = renderTable([engagement()])

    expect(row.getByText('Not scanned')).toBeInTheDocument()
    expect(row.queryByText(/^Created/)).not.toBeInTheDocument()
  })

  it('reports the last scan with its state and time', () => {
    const row = renderTable([
      engagement({ lastScanDate: new Date(Date.now() - 2 * 3_600_000).toISOString(), lastScanStatus: 'succeeded', findingsCount: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } }),
    ])

    expect(row.getByText('Scanned')).toBeInTheDocument()
    expect(row.getByText('2h ago')).toBeInTheDocument()
    expect(row.getByText('0')).toBeInTheDocument()
    expect(row.queryByText(/^Created/)).not.toBeInTheDocument()
  })

  it('marks a failed last scan', () => {
    const row = renderTable([
      engagement({ lastScanDate: new Date(Date.now() - 86_400_000).toISOString(), lastScanStatus: 'failed' }),
    ])

    expect(row.getByText('Failed')).toBeInTheDocument()
    expect(row.getByText('1d ago')).toBeInTheDocument()
  })
})
