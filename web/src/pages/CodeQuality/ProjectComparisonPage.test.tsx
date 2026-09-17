import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProjectComparisonPage } from './ProjectComparisonPage'
import type { ProjectRouteContext } from './CodeQualityProject'
import { availablePercentage, availableRating, buildAnalyzedOverview, buildFailedGate, buildPassedGate } from '../../test/projectOverviewFixtures'
import { api } from '../../lib/api'

vi.mock('../../lib/api', () => ({
  api: {
    projectBranches: vi.fn(),
    projectAnalyses: vi.fn(),
    projectOverview: vi.fn(),
  },
}))

const project = {
  key: 'proj',
  name: 'Proj',
  sourceBinding: { kind: 'git', value: 'git@example.com:acme/app.git', ref: 'main' },
  gateId: '',
} as unknown as ProjectRouteContext['project']

function renderAt(url: string) {
  const context = { projectKey: 'proj', project, branch: 'main' } as unknown as ProjectRouteContext
  const router = createMemoryRouter(
    [
      {
        path: '/c',
        element: <Outlet context={context} />,
        children: [{ index: true, element: <ProjectComparisonPage /> }],
      },
    ],
    { initialEntries: [url] },
  )
  return render(<RouterProvider router={router} />)
}

beforeEach(() => {
  vi.mocked(api.projectBranches).mockResolvedValue([
    { name: 'main', kind: 'long_lived' },
    { name: 'feature/x', kind: 'short_lived' },
  ])
  vi.mocked(api.projectAnalyses).mockResolvedValue({
    items: [
      { id: 'a1', createdAt: '2026-01-01T00:00:00Z', origin: 'ci', sourceRef: 'feature/pr-7', sourceCommit: 'abc', ci: { provider: 'github-actions', runUrl: '', runId: '7', branch: 'feature/pr-7', actor: 'octo', pullRequest: '7', targetBranch: 'main' } },
    ] as never,
    next: null,
  })
})

afterEach(() => vi.clearAllMocks())

describe('ProjectComparisonPage', () => {
  it('compares two branches side by side with metric directions', async () => {
    // base main: coverage 60%, security A. head feature/x: coverage 80% (improved), security C (regressed).
    vi.mocked(api.projectOverview).mockImplementation(async (_key: string, branch = '') => {
      if (branch === 'feature/x') {
        return buildAnalyzedOverview({
          gate: buildFailedGate(),
          lenses: {
            overall: { security: availableRating('C'), reliability: availableRating('A'), maintainability: availableRating('A'), securityHotspotsReviewed: availablePercentage(100), coverage: availablePercentage(80), duplications: availablePercentage(2) },
            newCode: buildAnalyzedOverview().lenses.newCode,
          },
        })
      }
      return buildAnalyzedOverview({
        gate: buildPassedGate(),
        lenses: {
          overall: { security: availableRating('A'), reliability: availableRating('A'), maintainability: availableRating('A'), securityHotspotsReviewed: availablePercentage(100), coverage: availablePercentage(60), duplications: availablePercentage(2) },
          newCode: buildAnalyzedOverview().lenses.newCode,
        },
      })
    })

    renderAt('/c?base=main&head=feature/x')

    await waitFor(() => expect(screen.getByText('Overall code metrics')).toBeInTheDocument())
    // Both gate banners rendered (passed for base, failed for head).
    expect(screen.getByText('Quality Gate Passed')).toBeInTheDocument()
    expect(screen.getByText('Quality Gate Failed')).toBeInTheDocument()
    // Coverage rose 60 -> 80 (higher is better) => Improved; Security A -> C => Regressed. Scope to the
    // metrics table since the failed-gate banner also names metrics.
    const table = screen.getByRole('table')
    const coverageRow = within(table).getByText('Coverage').closest('tr')!
    expect(coverageRow.textContent).toContain('Improved')
    const securityRow = within(table).getByText('Security').closest('tr')!
    expect(securityRow.textContent).toContain('Regressed')
  })

  it('lists a pull request derived from analyses as a selectable target', async () => {
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview({ gate: buildPassedGate() }))
    renderAt('/c?base=main&head=feature/x')
    await waitFor(() => expect(screen.getByText('Overall code metrics')).toBeInTheDocument())
    // The PR option appears in both the base and compare pickers.
    expect(screen.getAllByText('PR #7 → main').length).toBeGreaterThan(0)
  })

  it('asks for two different targets when base equals head', async () => {
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview({ gate: buildPassedGate() }))
    renderAt('/c?base=main&head=main')
    await waitFor(() => expect(screen.getByText('Pick two different targets')).toBeInTheDocument())
    expect(api.projectOverview).not.toHaveBeenCalled()
  })

  it('surfaces an error with a retry when an overview fails', async () => {
    vi.mocked(api.projectOverview).mockRejectedValue(new Error('boom'))
    renderAt('/c?base=main&head=feature/x')
    await waitFor(() => expect(screen.getByText('boom')).toBeInTheDocument())
    const retry = screen.getByRole('button', { name: 'Retry' })
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview({ gate: buildPassedGate() }))
    fireEvent.click(retry)
    await waitFor(() => expect(screen.getByText('Overall code metrics')).toBeInTheDocument())
  })
})
