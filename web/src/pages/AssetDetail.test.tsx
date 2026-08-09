import { render, screen } from '@testing-library/react'
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { ReactNode } from 'react'
import { AssetCoverageView, AssetFindings } from './AssetDetail'

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
})
