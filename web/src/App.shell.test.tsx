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
    inboxUnread: vi.fn(),
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

const authNotice = vi.hoisted(() => ({
  error: null as string | null,
  currentUser: null as { id: string; name: string; role: string; credentialKind?: string; tenantId?: string } | null,
  logout: vi.fn(),
}))

vi.mock('./pages/Authentication', () => ({
  default: ({ enabled }: { enabled: boolean }) => <section><h2>Authentication recovery controls</h2><output>{String(enabled)}</output></section>,
}))

vi.mock('./auth/AuthContext', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: () => ({ phase: 'ready', error: authNotice.error, errorRequestId: null, currentUser: authNotice.currentUser, logout: authNotice.logout }),
  useOptionalAuth: () => ({ phase: 'ready', error: authNotice.error, currentUser: authNotice.currentUser, logout: authNotice.logout }),
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
    authNotice.error = null
    authNotice.currentUser = null
    authNotice.logout.mockReset()
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
    vi.mocked(api.inboxUnread).mockResolvedValue({ unread: 0 })
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

  it('shows a refused additional sign-in with a Profile action while keeping the dashboard usable', async () => {
    authNotice.error = 'The identity you selected is not approved for this action. Your existing sign-in is still active.'
    renderAt('/dashboard')
    expect(await screen.findByRole('heading', { name: 'Security Operations' })).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(authNotice.error)
    expect(screen.getByRole('link', { name: 'Review sign-in' })).toHaveAttribute('href', '/profile')
  })

  it('omits the authentication notice on an ordinary restored dashboard', async () => {
    renderAt('/dashboard')
    await screen.findByRole('heading', { name: 'Security Operations' })
    expect(screen.queryByRole('link', { name: 'Review sign-in' })).not.toBeInTheDocument()
  })

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

  it('isolates break-glass recovery access from the normal shell and dashboard requests', async () => {
    authNotice.currentUser = { id: 'recovery-1', name: 'Recovery operator', role: 'admin', credentialKind: 'break_glass', tenantId: 'tenant-recovery' }
    authNotice.error = 'Could not end the server session. Try signing out again.'
    renderAt('/dashboard')

    expect(await screen.findByRole('heading', { name: 'Recovery console' })).toBeInTheDocument()
    const alerts = screen.getAllByRole('alert')
    expect(alerts[0]).toHaveTextContent('Recovery access is active.')
    expect(alerts[1]).toHaveTextContent(authNotice.error)
    expect(screen.getByText('Recovery operator · tenant-recovery')).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'Authentication recovery controls' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    expect(api.dashboardSecurityOperations).not.toHaveBeenCalled()

    await screen.getByRole('button', { name: 'Sign out' }).click()
    expect(authNotice.logout).toHaveBeenCalledTimes(1)
  })
})
