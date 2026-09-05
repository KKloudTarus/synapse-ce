import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { api } from './lib/api'

vi.mock('./lib/api', () => ({
  api: {
    listEngagements: vi.fn(),
    // The sidebar probes the optional-subsystem catalog; null means "report nothing, show everything".
    listCapabilities: vi.fn().mockResolvedValue(null),
    listBusinessAssets: vi.fn(),
    fleetCoverageSummary: vi.fn(),
    dashboardSecurityOperations: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message)
    }
  },
}))

vi.mock('./auth/AuthContext', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: () => ({ phase: 'ready', logout: vi.fn() }),
  useOptionalAuth: () => ({ phase: 'ready', logout: vi.fn() }),
}))

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

describe('App shell', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.resetAllMocks()
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.listBusinessAssets).mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 })
    vi.mocked(api.fleetCoverageSummary).mockResolvedValue({
      agentsByState: {},
      rowsByVerdict: {},
      oldestPerCapability: {},
      assetsWithoutAgent: 0,
    })
    vi.mocked(api.dashboardSecurityOperations).mockResolvedValue({
      rangeDays: 30,
      generatedAt: '',
      assetPosture: {},
      assetsByCriticality: {},
      activeFindingsBySeverity: {},
      findingsOverTime: [],
      findingsWithoutTimestamp: 0,
      externalFindingsIncluded: true,
    })
  })

  it.each(['/findings', '/issues', '/hotspots', '/measures', '/components', '/dependencies', '/activity', '/history', '/coverage', '/analysis', '/code', '/config', '/nonsense-typo'])(
    'explains %s instead of silently redirecting to the dashboard',
    async (path) => {
      renderAt(path)
      expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument()
      expect(screen.getByText(path)).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /Back to dashboard/ })).toHaveAttribute('href', '/dashboard')
    },
  )

  it('keeps the app shell around the 404 page', async () => {
    renderAt('/findings')
    await screen.findByRole('heading', { name: 'Page not found' })
    expect(screen.getAllByRole('navigation').length).toBeGreaterThan(0)
  })

  it('offers a skip link that targets the main region', async () => {
    renderAt('/dashboard')
    const skip = await screen.findByRole('link', { name: 'Skip to main content' })
    expect(skip).toHaveAttribute('href', '#main-content')
    await waitFor(() => expect(document.getElementById('main-content')).not.toBeNull())
    expect(document.getElementById('main-content')?.tagName).toBe('MAIN')
  })
})
