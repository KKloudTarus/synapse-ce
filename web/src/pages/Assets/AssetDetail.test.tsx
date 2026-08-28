import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { ReactNode } from 'react'
import { AssetCoverageView, AssetFindings, AssetOverview } from './AssetDetail'

function renderWithContext(element: ReactNode, context: any) {
  render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route element={<Outlet context={context} />}>
          <Route index element={element} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

describe('Asset detail projections', () => {
  it('labels external findings, suppression, provenance, and unknown reachability', () => {
    renderWithContext(<AssetFindings />, {
      findings: [{
        finding: { id: 'if-1', title: 'External result', severity: 'high' },
        external: true,
        canSelfPromote: false,
        suppressedByTool: true,
        provenance: { toolName: 'semgrep', toolVersion: '1.2.3', ruleId: 'rule.a', sourceDigest: 'sha256:abc' },
        reachability: { state: 'unknown', tier: 'tier-0', status: '', history: [] },
        engagementId: 'e1',
        engagementName: 'Login assessment',
      }],
    })
    expect(screen.getByText('External · semgrep')).toBeInTheDocument()
    expect(screen.getByText('Suppressed by tool')).toBeInTheDocument()
    expect(screen.getByText(/reachability unknown \(tier-0\)/)).toBeInTheDocument()
    expect(screen.getByText(/semgrep 1.2.3 · rule.a · sha256:abc/)).toBeInTheDocument()
  })

  it('renders partial coverage as a distinct non-passing state', () => {
    renderWithContext(<AssetCoverageView />, {
      coverage: {
        freshnessTargetDays: 90,
        counts: { partial: 1 },
        rows: [{ kind: 'technical_asset', componentId: 'workload-1', name: 'Workload 1', verdict: 'partial', engagementId: 'e1', lastAssessed: null, freshnessTargetDays: 90 }],
      },
    })
    expect(screen.getAllByText('partial')).toHaveLength(2)
    expect(screen.getByText(/never assessed/)).toBeInTheDocument()
  })

  it('renders AssetOverview stat strip, read-only profile, recent engagements, and collapsible editor', () => {
    const mockContext = {
      asset: {
        id: 'asset-1',
        name: 'Synapse Security Platform',
        key: 'synapse-platform',
        owner: 'security-engineering',
        type: 'application',
        criticality: 'high',
        lifecycle: 'active',
        version: 1,
        description: 'Core SCA/SAST platform',
        metadata: {},
      },
      posture: {
        rating: 'attention',
        explanation: 'Needs attention due to active findings',
        findingCounts: { critical: 1, high: 3, medium: 5, low: 0 },
        coverageCounts: {},
      },
      coverage: {
        counts: { covered: 2, stale: 1, not_assessed: 1 },
        rows: [
          { kind: 'technical_asset', componentId: 'w1', verdict: 'covered' },
          { kind: 'technical_asset', componentId: 'w2', verdict: 'covered' },
          { kind: 'technical_asset', componentId: 'w3', verdict: 'stale' },
          { kind: 'technical_asset', componentId: 'w4', verdict: 'not_assessed' },
        ],
      },
      history: [
        {
          engagementId: 'eng-1',
          name: 'Q3 Security Audit',
          status: 'active',
          findingCount: 45,
          retestCount: 2,
          scopeCount: 5,
          updatedAt: new Date(Date.now() - 3600000).toISOString(),
        },
      ],
      reload: () => {},
    }

    renderWithContext(<AssetOverview />, mockContext)

    // Zone 1: Stat strip
    expect(screen.getByText('Posture')).toBeInTheDocument()
    expect(screen.getByText('attention')).toBeInTheDocument()
    expect(screen.getByText('Coverage')).toBeInTheDocument()
    expect(screen.getByText('50%')).toBeInTheDocument()
    expect(screen.getByText('1 stale · 1 unassessed')).toBeInTheDocument()

    // Zone 2: Read-only profile
    expect(screen.getByText('Synapse Security Platform')).toBeInTheDocument()
    expect(screen.getByText('security-engineering')).toBeInTheDocument()
    expect(screen.getByText('Core SCA/SAST platform')).toBeInTheDocument()

    // Zone 3: Recent engagements
    expect(screen.getByText('Q3 Security Audit')).toBeInTheDocument()
    expect(screen.getByText('45 findings')).toBeInTheDocument()
    expect(screen.getByText('2 retests')).toBeInTheDocument()

    // Zone 4: Collapsible editor toggle
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Edit/i }))
    expect(screen.getByDisplayValue('Synapse Security Platform')).toBeInTheDocument()
  })

  it('supports severity filtering and pagination in AssetFindings', () => {
    const findings = Array.from({ length: 30 }, (_, index) => ({
      finding: {
        id: `f-${index}`,
        title: `Finding #${index + 1}`,
        severity: index === 0 ? 'critical' : index < 10 ? 'high' : 'medium',
      },
      external: false,
      canSelfPromote: false,
      suppressedByTool: false,
      reachability: { state: 'unreachable', tier: 'tier-1', status: '', history: [] },
      engagementId: 'eng-1',
      engagementName: 'Engagement 1',
    }))

    renderWithContext(<AssetFindings />, { findings })

    // Total count shows 30 findings, initial page shows 25
    expect(screen.getByText('30 findings')).toBeInTheDocument()
    expect(screen.getByText('Finding #1')).toBeInTheDocument()
    expect(screen.getByText('Finding #25')).toBeInTheDocument()
    expect(screen.queryByText('Finding #26')).not.toBeInTheDocument()
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument()

    // Next page
    fireEvent.click(screen.getByRole('button', { name: /Next/i }))
    expect(screen.getByText('Finding #26')).toBeInTheDocument()
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument()

    // Filter by Critical (1 finding)
    fireEvent.click(screen.getByRole('button', { name: 'Critical' }))
    expect(screen.getByText('1 finding')).toBeInTheDocument()
    expect(screen.getByText('Finding #1')).toBeInTheDocument()
    expect(screen.queryByText(/Page 1 of/i)).not.toBeInTheDocument()

    // Filter by Low (0 findings)
    fireEvent.click(screen.getByRole('button', { name: 'Low' }))
    expect(screen.getByText('0 findings')).toBeInTheDocument()
    expect(screen.getByText('No findings match this severity filter.')).toBeInTheDocument()
  })
})

