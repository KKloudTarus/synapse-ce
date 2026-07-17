import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import { buildAnalyzedOverview, buildNotAnalyzedOverview } from '../test/projectOverviewFixtures'
import { CodeQualityProject } from './CodeQualityProject'
import { ProjectActivityPage } from './ProjectActivityPage'
import { ProjectAnalysisPage } from './ProjectAnalysisPage'
import { ProjectOverviewPage } from './ProjectOverviewPage'

vi.mock('../lib/api', () => ({
  api: {
    getProject: vi.fn(),
    projectAnalysisStatus: vi.fn(),
    projectOverview: vi.fn(),
    latestProjectAnalysis: vi.fn(),
    projectAnalyses: vi.fn(),
    listQualityGates: vi.fn(),
    assignProjectGate: vi.fn(),
    startProjectAnalysis: vi.fn(),
  },
}))

const project = {
  id: 'p1',
  name: 'Synapse',
  key: 'synapse',
  sourceBinding: { kind: 'git' as const, value: 'https://example.com/repo.git', ref: 'main' },
  defaultProfileByLang: {},
  gateId: '',
  createdAt: null,
  latestAnalysis: null,
  latestJob: null,
}

describe('Project Overview routes', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview())
    vi.mocked(api.latestProjectAnalysis).mockResolvedValue(null)
    vi.mocked(api.projectAnalyses).mockResolvedValue({ items: [], next: null })
    vi.mocked(api.listQualityGates).mockResolvedValue([])
  })

  it('loads Overview without fetching the full latest analysis or activity history', async () => {
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.getProject).toHaveBeenCalledWith('synapse')
    expect(api.projectAnalysisStatus).toHaveBeenCalledWith('synapse')
    expect(api.projectOverview).toHaveBeenCalledWith('synapse')
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
    expect(api.projectAnalyses).not.toHaveBeenCalled()
  })

  it('renders the not-analyzed state without fake metric cards', async () => {
    vi.mocked(api.projectOverview).mockResolvedValue(buildNotAnalyzedOverview())
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run first analysis' })).toBeInTheDocument()
    expect(screen.queryByText('Quality metrics')).not.toBeInTheDocument()
  })

  it('synchronizes the lens with the URL without refetching Overview', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse?foo=bar&lens=bad')
    await waitFor(() => expect(router.state.location.search).toBe('?foo=bar&lens=overall'))
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.projectOverview).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'New Code' }))
    expect(router.state.location.search).toBe('?foo=bar&lens=new-code')
    expect(screen.getAllByText('Changed-line metrics are not available for this analysis.').length).toBeGreaterThan(0)
    expect(api.projectOverview).toHaveBeenCalledTimes(1)
  })

  it('keeps the shell visible and retries only Overview on route-local errors', async () => {
    vi.mocked(api.projectOverview).mockRejectedValueOnce(new Error('overview offline')).mockResolvedValueOnce(buildAnalyzedOverview())
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByRole('heading', { name: 'Synapse' })).toBeInTheDocument()
    expect(await screen.findByText('overview offline')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry Overview' }))
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.projectOverview).toHaveBeenCalledTimes(2)
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
  })

  it('scopes Analysis and Activity requests to their routes', async () => {
    renderProjectRoute('/code-quality/projects/synapse/analysis')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
    expect(api.latestProjectAnalysis).toHaveBeenCalledWith('synapse')
    expect(api.projectOverview).not.toHaveBeenCalled()
    expect(api.projectAnalyses).not.toHaveBeenCalled()

    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.projectAnalyses).mockResolvedValue({ items: [], next: null })
    vi.mocked(api.listQualityGates).mockResolvedValue([])
    renderProjectRoute('/code-quality/projects/synapse/activity')
    expect(await screen.findByText('No analysis history yet')).toBeInTheDocument()
    expect(api.projectAnalyses).toHaveBeenCalledWith('synapse')
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
    expect(api.projectOverview).not.toHaveBeenCalled()
  })
})

function renderProjectRoute(initialPath: string) {
  const router = createMemoryRouter([
    {
      path: '/code-quality/projects/:key',
      element: <CodeQualityProject />,
      children: [
        { index: true, element: <ProjectOverviewPage /> },
        { path: 'analysis', element: <ProjectAnalysisPage /> },
        { path: 'activity', element: <ProjectActivityPage /> },
      ],
    },
  ], { initialEntries: [initialPath] })
  render(<RouterProvider router={router} />)
  return router
}
